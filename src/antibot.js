// SPDX-License-Identifier: BlueOak-1.0.0 OR Apache-2.0

import cryptoModule from 'crypto';

// Proof-of-work gate for browser-facing routes, called from nginx
// auth_request. Worker API routes are matched outside this module and never
// reach it.
//
// check() returns 204 when the request carries a valid challenge cookie and
// 401 when it does not. serve_challenge() returns the page that solves the
// challenge and stores the cookie.
//
// A client is identified by its IPv4 address or IPv6 /64, its User-Agent and
// its Accept-Language. The challenge is an HMAC-SHA256 over that identity and
// the current time slot. The client passes by finding a nonce whose SHA-256
// with the challenge begins with POW_BITS zero bits, and stores
// "<slot>.<nonce>" in the COOKIE_NAME cookie. A cookie is accepted for
// its own slot and the one after it, so it lasts between WINDOW_SIZE and twice
// WINDOW_SIZE.
//
// RESCREEN_RATE of document requests that already hold a valid cookie are
// challenged again. Subresource and background requests are never
// re-screened, because the challenge page is only a correct response to a
// top-level navigation.
//
// The module keeps no state. Rate limiting and blocking belong to limit_req.
//
// Requirements:
//
// - ANTIBOT_SECRET reaches the nginx workers and is at least 32 characters.
// - $remote_addr is the client address. Behind a CDN, set set_real_ip_from and
//   real_ip_header, otherwise every visitor shares one identity.
//
// Limits:
//
// - POW_BITS is clamped to POW_BITS_MAX and to nothing else. Configuration
//   problems are written to the error log on the first request, not at load.


// The solver assumes the challenge is exactly 64 bytes, which it is: an
// HMAC-SHA256 hex digest is exactly one SHA-256 block. That block is folded
// into a midstate once, so each candidate nonce costs one compression instead
// of two. If expected_challenge() stops returning 64 hex characters, rebuild
// the wasm. Nothing else in this file depends on that length.
//
// Two solvers implement the same algorithm. The wasm module is four-way SIMD.
// Engines that cannot validate a SIMD module, or that lack WebAssembly, use
// the pure-JS solver below, at somewhat under half the rate. Both are checked
// against a known-good SHA-256 by test/solver.test.mjs, which prints the rate
// for the machine it runs on.

// Stamped from package.json by build.sh. The value here marks a module
// that was never assembled.
const ANTIBOT_VERSION = "0.0.0-unbuilt";

const SECRET = process.env.ANTIBOT_SECRET || "";

const CONFIG_WARNINGS = [];

function fail_config(message) {
    CONFIG_WARNINGS.push("antibot " + ANTIBOT_VERSION + ": " + message);
    return true;
}

function report_config(r) {
    while (CONFIG_WARNINGS.length > 0) {
        r.error(CONFIG_WARNINGS.shift());
    }
}

// Each setting below is read from ANTIBOT_<NAME> where nginx exports it with
// the env directive, and falls back to the constant beside it otherwise. One
// built artifact then runs unmodified on any site: deploying changes the
// environment, not the file, so an upgrade is a replacement rather than a
// merge. An unset or empty variable is absent, not a value.
function env_raw(name) {
    const value = process.env["ANTIBOT_" + name];
    return value === undefined || value === "" ? null : value;
}

function env_number(name, fallback) {
    const raw = env_raw(name);
    if (raw === null) {
        return fallback;
    }
    const value = Number(raw);
    if (!isFinite(value)) {
        fail_config("ANTIBOT_" + name + "=" + raw + " is not a number, using " +
                    fallback);
        return fallback;
    }
    return value;
}

function env_string(name, fallback) {
    const raw = env_raw(name);
    return raw === null ? fallback : raw;
}

const COOKIE_NAME = "__Host-antibot-ac";

// Heading shown on the challenge page. Empty means no heading at all, which
// is the neutral default; set it to your site's name to brand the page.
// It is HTML-escaped before being inserted.
const SITE_NAME = "";


const WINDOW_SIZE = 6 * 60 * 60;

// A cookie is accepted for its own slot and the one after it, so it is
// useful for at most twice WINDOW_SIZE. Past that the browser would send
// bytes the module always refuses.
const COOKIE_TTL = 2 * WINDOW_SIZE;

// Difficulty in leading zero bits, at least 1. Each bit doubles the work.
// There is no value that disables verification: check() always recomputes
// the proof.
//
// Mean solve time with the SIMD solver on a desktop core:
//
//     bits | 1 worker | 2 workers | 4 workers
//       22 |    0.5s  |    0.2s   |    0.2s
//       24 |    1.9s  |    1.0s   |    0.6s
//       26 |    7.5s  |    3.9s   |    2.4s
//       28 |   30.0s  |   15.7s   |    9.8s
//       30 |     120s |      63s  |      39s
//
// One worker is the floor: a single-core client, or one where
// navigator.hardwareConcurrency is unavailable. The table is node on one
// desktop core; no browser and no phone has been measured, so a phone figure
// cannot be given here.
//
// The wait is geometrically distributed. 5% of visitors wait more than 3x
// the mean and 0.7% more than 5x. No visitor can be told how long to expect.
const POW_BITS = 22;

const POW_BITS_MAX = 32;

// Multiple of the expected work a client may spend before giving up.
// A correct client exhausts it with probability e^-POW_EFFORT_FACTOR.
const POW_EFFORT_FACTOR = 64;

// Fraction of requests holding a valid cookie that are challenged again.
// Applies to top-level navigations only.
const RESCREEN_RATE = 0.02;

// How many cookies sent under COOKIE_NAME are verified. A browser sends one:
// the __Host- prefix forces Path=/, so a host cannot hold two. Trying every
// one would let a request choose how many hashes the server performs.
const MAX_COOKIE_CANDIDATES = 4;

const POW_BITS_EFFECTIVE = (function () {
    let b = env_number("POW_BITS", POW_BITS);
    if (typeof b !== "number" || !isFinite(b) || Math.floor(b) !== b || b < 1) {
        fail_config("POW_BITS=" + b + " is not an integer of at least 1, using 16");
        b = 16;
    }
    if (b > POW_BITS_MAX) {
        fail_config("POW_BITS=" + b + " exceeds POW_BITS_MAX=" + POW_BITS_MAX +
                    ", clamped to " + POW_BITS_MAX);
        b = POW_BITS_MAX;
    }
    return b;
})();

// A slot shorter than a minute would expire while a client is still solving.
// The ceiling keeps a cookie from outliving a secret rotation by months.
const WINDOW_SIZE_EFFECTIVE = (function () {
    let v = env_number("WINDOW_SIZE", WINDOW_SIZE);
    if (typeof v !== "number" || !isFinite(v) || Math.floor(v) !== v ||
        v < 60 || v > 30 * 24 * 60 * 60) {
        fail_config("WINDOW_SIZE=" + v + " is not an integer between 60 and " +
                    (30 * 24 * 60 * 60) + " seconds, using " + WINDOW_SIZE);
        v = WINDOW_SIZE;
    }
    return v;
})();

// The __Host- prefix forces Path=/ and forbids Domain, which is what keeps a
// host from holding two cookies under this name. A name without it still
// works and gives up that guarantee, so it is reported and kept.
const COOKIE_NAME_EFFECTIVE = (function () {
    let v = env_string("COOKIE_NAME", COOKIE_NAME);
    if (!/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(v)) {
        fail_config("COOKIE_NAME=" + v + " is not a cookie name, using " +
                    COOKIE_NAME);
        v = COOKIE_NAME;
    } else if (v.indexOf("__Host-") !== 0) {
        fail_config("COOKIE_NAME=" + v + " has no __Host- prefix, so a host " +
                    "can hold more than one under this name");
    }
    return v;
})();

const SITE_NAME_EFFECTIVE = env_string("SITE_NAME", SITE_NAME);

// A rate of 1 challenges every navigation that holds a valid cookie, so a
// visitor solves, reloads and is challenged again without end. The range
// excludes it.
const RESCREEN_RATE_EFFECTIVE = (function () {
    let v = env_number("RESCREEN_RATE", RESCREEN_RATE);
    if (typeof v !== "number" || !isFinite(v) || v < 0 || v >= 1) {
        fail_config("RESCREEN_RATE=" + v + " is not a number in [0, 1), using 0.02");
        v = 0.02;
    }
    return v;
})();

// A cookie is accepted for its own slot and the one after it. A lifetime below
// that has the browser drop it while the module would still take it, which
// challenges the visitor again for no gain.
const COOKIE_TTL_EFFECTIVE = (function () {
    const floor = 2 * WINDOW_SIZE_EFFECTIVE;
    let v = env_number("COOKIE_TTL", COOKIE_TTL);
    if (typeof v !== "number" || !isFinite(v) || Math.floor(v) !== v || v < floor) {
        fail_config("COOKIE_TTL=" + v + " is below twice WINDOW_SIZE=" + floor +
                    ", using " + floor);
        v = floor;
    }
    return v;
})();

const POW_EXPECTED_WORK = Math.pow(2, POW_BITS_EFFECTIVE);

const POW_MAX_ITERATIONS = POW_EXPECTED_WORK * POW_EFFORT_FACTOR;

// njs creates a VM per request, so a counter held in a module variable is
// reset before anything reads it. Counting uses a shared dictionary, which
// outlives the request and is shared across workers:
//
//     js_shared_dict_zone zone=antibot:32k type=number;
//
// Without that zone the module gates exactly as it does with it, and status()
// says the zone is missing rather than reporting zeros.
const STATS_ZONE = "antibot";
const STATS_KEYS = ["challenges", "accepted", "rejected", "rescreened",
                    "misconfigured"];

function stats_dict() {
    try {
        if (typeof ngx === "undefined" || !ngx.shared) {
            return null;
        }
        return ngx.shared[STATS_ZONE] || null;
    } catch (err) {
        return null;
    }
}

// Counting never fails a request: a full or missing zone is not a reason to
// refuse a visitor.
function count(name) {
    const dict = stats_dict();
    if (dict === null) {
        return;
    }
    try {
        dict.incr(name, 1, 0);
    } catch (err) {
        // The zone is full or the wrong type. The gate does not depend on it.
    }
}

function secret_configured() {
    return SECRET.length >= 32;
}

function current_slot() {
    return Math.floor(Date.now() / 1000 / WINDOW_SIZE_EFFECTIVE);
}

function hmac_sha256_hex(key, message) {
    const hmac = cryptoModule.createHmac("sha256", key);
    hmac.update(message);
    return hmac.digest("hex");
}

function sha256_hex(message) {
    const hash = cryptoModule.createHash("sha256");
    hash.update(message);
    return hash.digest("hex");
}

// The eight groups of an IPv6 address, or null when it does not parse.
// Groups are normalised, so 2001:0db8::1 and 2001:db8::1 agree.
function expand_ipv6(address) {
    const halves = address.split("::");
    if (halves.length > 2) {
        return null;
    }
    const head = halves[0] ? halves[0].split(":") : [];
    const tail = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
    const fill = 8 - head.length - tail.length;
    if (halves.length === 1 ? head.length !== 8 : fill < 1) {
        return null;
    }
    const groups = head.slice();
    for (let i = 0; i < fill; i++) {
        groups.push("0");
    }
    const all = groups.concat(tail);
    for (let i = 0; i < all.length; i++) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(all[i])) {
            return null;
        }
        all[i] = parseInt(all[i], 16).toString(16);
    }
    return all;
}

// The address reduced to what identifies a client: an IPv4 address as given,
// an IPv6 address as its /64, and an IPv4-mapped address as the IPv4 it
// carries. An address that does not parse is kept whole.
//
// Two different addresses must never produce the same key. Folding an
// unparsed address to a constant would put every such client in one bucket,
// where one solved cookie serves all of them.
function address_key(address) {
    if (address.indexOf(":") === -1) {
        return address;
    }
    const mapped = /^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/i.exec(address);
    if (mapped) {
        let octets_valid = true;
        for (let i = 1; i <= 4; i++) {
            if (Number(mapped[i]) > 255) {
                octets_valid = false;
            }
        }
        if (octets_valid) {
            return mapped[1] + "." + mapped[2] + "." + mapped[3] + "." + mapped[4];
        }
    }
    if (address.indexOf("%") !== -1) {
        return address;
    }
    const groups = expand_ipv6(address);
    if (!groups) {
        return address;
    }
    return groups.slice(0, 4).join(":") + "::/64";
}

// Every identity component is attacker-controlled and the whole string is
// hashed on each request, so an oversized header would otherwise buy an
// attacker a proportionally larger HMAC. Real values are far below this.
const IDENTITY_FIELD_MAX = 256;

function clip(text) {
    return text.length > IDENTITY_FIELD_MAX
        ? text.substring(0, IDENTITY_FIELD_MAX)
        : text;
}

// A URI and an address reach the log as the client sent them, and nginx writes
// one line per call. Everything outside printable ASCII is encoded, so a
// percent-encoded newline stays inside the line it belongs to.
function log_field(text) {
    const s = clip(String(text));
    let out = "";
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c >= 0x20 && c < 0x7f && c !== 0x5c) {
            out += s[i];
        } else if (c < 0x100) {
            out += "\\x" + ("0" + c.toString(16)).slice(-2);
        } else {
            out += "\\u" + ("000" + c.toString(16)).slice(-4);
        }
    }
    return out;
}

function client_key(r) {
    // Clip before parsing, not after: address_key splits and matches over the
    // whole string, so bounding it afterwards would leave that work tracking
    // the length of a header an attacker controls when real_ip_header is set.
    // A valid address is far shorter than the bound, and an address that is
    // empty or unparseable keeps whatever it is as its own identity.
    const address = address_key(clip(r.remoteAddress || ""));
    const ua = clip(r.headersIn["User-Agent"] || "");
    const lang = clip(r.headersIn["Accept-Language"] || "");
    return address + "|" + ua + "|" + lang;
}

function expected_challenge(key, slot) {
    return hmac_sha256_hex(SECRET, key + ":" + slot);
}

function hex_has_leading_zero_bits(hex, bits) {
    const full_nibbles = bits >> 2;
    const remainder = bits & 3;
    for (let i = 0; i < full_nibbles; i++) {
        if (hex.charCodeAt(i) !== 48) {
            return false;
        }
    }
    if (remainder && (parseInt(hex[full_nibbles], 16) >> (4 - remainder)) !== 0) {
        return false;
    }
    return true;
}

function pow_valid(challenge, nonce) {
    return hex_has_leading_zero_bits(
        sha256_hex(challenge + ":" + nonce),
        POW_BITS_EFFECTIVE
    );
}

function escape_html(text) {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// Every value sent under this name. A request may carry more than one cookie
// with the same name, and taking only the first would let a junk duplicate
// mask a valid cookie.
// Scanned rather than split, and stopped at max: the header is
// attacker-controlled, and nginx allows 8 KB of it, which holds hundreds of
// cookies. Only the first max are ever verified, so only the first max are
// ever built.
function get_cookies(r, name, max) {
    const header = r.headersIn["Cookie"];
    const values = [];
    if (!header) {
        return values;
    }
    const prefix = name + "=";
    let pos = 0;
    while (pos < header.length && values.length < max) {
        while (pos < header.length && header.charCodeAt(pos) <= 32) {
            pos++;
        }
        let end = header.indexOf(";", pos);
        if (end === -1) {
            end = header.length;
        }
        if (header.startsWith(prefix, pos)) {
            values.push(header.substring(pos + prefix.length, end).trim());
        }
        pos = end + 1;
    }
    return values;
}

function parse_cookie_value(value) {
    if (!value) {
        return null;
    }
    const dot = value.indexOf(".");
    if (dot === -1) {
        return null;
    }
    const slot = value.substring(0, dot);
    const nonce = value.substring(dot + 1);
    if (!/^(0|[1-9][0-9]{0,11})$/.test(slot)) {
        return null;
    }
    // 15 digits at most: Number() is exact below 2^53, so the comparison
    // against the iteration cap below means what it says.
    if (!/^(0|[1-9][0-9]{0,14})$/.test(nonce)) {
        return null;
    }
    if (Number(nonce) > POW_MAX_ITERATIONS) {
        return null;
    }
    return { slot: Number(slot), nonce: nonce };
}

// A re-screen answers with the challenge page, which is only a correct
// response to a top-level navigation: handing it to a fetch, an image or a
// background request corrupts whatever asked. Sec-Fetch-Dest states what the
// client will do with the response. Clients that do not send it are treated
// as navigating.
function is_document_request(r) {
    const dest = r.headersIn["Sec-Fetch-Dest"];
    return !dest || dest === "document";
}

function check(r) {
    report_config(r);

    if (!secret_configured()) {
        r.error("antibot: ANTIBOT_SECRET is missing or too short");
        count("misconfigured");
        r.return(500, "");
        return;
    }

    const slot = current_slot();
    const values = get_cookies(r, COOKIE_NAME_EFFECTIVE, MAX_COOKIE_CANDIDATES);

    // The identity does not vary between candidates, and only two slots are
    // accepted, so each is derived at most once however many cookies arrive.
    let key = null;
    let challenge_current = null;
    let challenge_previous = null;

    for (let i = 0; i < values.length; i++) {
        const parsed = parse_cookie_value(values[i]);
        if (!parsed) {
            continue;
        }
        if (parsed.slot !== slot && parsed.slot !== slot - 1) {
            continue;
        }
        if (key === null) {
            key = client_key(r);
        }
        let challenge;
        if (parsed.slot === slot) {
            if (challenge_current === null) {
                challenge_current = expected_challenge(key, slot);
            }
            challenge = challenge_current;
        } else {
            if (challenge_previous === null) {
                challenge_previous = expected_challenge(key, slot - 1);
            }
            challenge = challenge_previous;
        }
        if (!pow_valid(challenge, parsed.nonce)) {
            continue;
        }
        if (is_document_request(r) && Math.random() < RESCREEN_RATE_EFFECTIVE) {
            count("rescreened");
            r.return(401, "");
            return;
        }
        count("accepted");
        r.return(204, "");
        return;
    }

    count("rejected");
    r.return(401, "");
}

// The SIMD solver, compiled from src/pow_solver.c.
//
// This constant is empty in the source tree. build.sh compiles the solver and
// writes the assembled module, with the base64 filled in, to dist/antibot.js.
// Deploy dist/antibot.js, never this file.
//
// The solver exports set_byte(i, v) to write one challenge byte, init() to
// fold the challenge block into the midstate, and solve(start, count, bits)
// returning the offset of the first solution in [start, start+count) or
// 0xFFFFFFFF.
//
// An empty payload is not fatal: WebAssembly.compile rejects it and every
// worker falls back to the pure-JS solver, so an unassembled module still
// gates correctly, only slower.
const POW_WASM_SIMD_B64 = "";

// Pure-JS SHA-256 solver. Used when the engine cannot validate the SIMD
// module, or has no WebAssembly at all.
//
// Implements the same algorithm as src/pow_solver.c: the 64-byte challenge
// is folded into a midstate once, each candidate compresses only the second
// block, only h0 is materialised, and the decimal nonce is incremented in
// place.
//
// The compression function is generated at run time and passed to
// new Function. Generating it rather than writing it allows three things a
// fixed implementation cannot have:
//
// - all 64 rounds unrolled with the K constants as literals, so no round
//   performs a table load;
// - the message schedule in 16 local variables rather than a typed array, so
//   the hot loop touches no memory;
// - working variables rotated by name, so a round assigns two variables
//   instead of eight.
//
// The compressor is further specialised on the nonce's decimal width: for a
// given width w4..w15 of the second block are constant, so they become
// literals and only w0..w3 are read from the block. Widths change only at
// powers of ten, so the generated functions are cached.
//
// The generated source is about 19.8KB and is
// built inside the worker, so it never crosses the wire.
//
// A content-security-policy reaching this page must allow 'unsafe-eval' for
// this solver and 'wasm-unsafe-eval' for the SIMD one. docs/installation.md
// carries the whole header.
//
// Exposes the same solve(start, count, bits) contract as the wasm module:
// the offset of the first solution, or 0xFFFFFFFF.
// The three programs the page is made of live beside this file and are
// written in by build.sh, the way the wasm is: src/solver.js, src/worker.js
// and src/page.html. Each is checked by its own parser at build time, which a
// string literal in here never was.
const POW_JS_SOLVER = "";

const WORKER_TEMPLATE = "";

const WORKER_SOURCE =
    WORKER_TEMPLATE.replace("/*__ANTIBOT_SOLVER__*/", POW_JS_SOLVER);

// Escaped once: the page carries the worker as a JavaScript string.
const WORKER_SOURCE_ESCAPED = JSON.stringify(WORKER_SOURCE).slice(1, -1);

const PAGE_TEMPLATE = "";

// Split once and joined per request. Substituting into the template on every
// request would put the length of the page into the cost of serving it, and
// the page is mostly the solver.
const PAGE_PARTS = PAGE_TEMPLATE.split(/(__ANTIBOT_[A-Z0-9_]+__)/);

// Every token the template carries must have a value below. A token added to
// src/page.html and not here would otherwise render as "undefined" in a page
// that still parses, so the mismatch is reported once at load.
const PAGE_TOKENS = [
    "__ANTIBOT_HEADING__", "__ANTIBOT_CHALLENGE__", "__ANTIBOT_BITS__",
    "__ANTIBOT_SLOT__", "__ANTIBOT_CAP__", "__ANTIBOT_EXPECTED__",
    "__ANTIBOT_COOKIE_NAME__", "__ANTIBOT_COOKIE_TTL__",
    "__ANTIBOT_WASM_B64__", "__ANTIBOT_WORKER_SRC__"
];

(function () {
    for (let i = 1; i < PAGE_PARTS.length; i += 2) {
        if (PAGE_TOKENS.indexOf(PAGE_PARTS[i]) === -1) {
            fail_config("the challenge page carries " + PAGE_PARTS[i] +
                        ", which has no value");
        }
    }
})();

function build_challenge(r, slot) {
    const values = {
        __ANTIBOT_HEADING__: SITE_NAME_EFFECTIVE
            ? "<h1>" + escape_html(SITE_NAME_EFFECTIVE) + "</h1>\n"
            : "",
        __ANTIBOT_CHALLENGE__: expected_challenge(client_key(r), slot),
        __ANTIBOT_BITS__: POW_BITS_EFFECTIVE,
        __ANTIBOT_SLOT__: slot,
        __ANTIBOT_CAP__: POW_MAX_ITERATIONS,
        __ANTIBOT_EXPECTED__: POW_EXPECTED_WORK,
        __ANTIBOT_COOKIE_NAME__: COOKIE_NAME_EFFECTIVE,
        __ANTIBOT_COOKIE_TTL__: COOKIE_TTL_EFFECTIVE,
        __ANTIBOT_WASM_B64__: POW_WASM_SIMD_B64,
        __ANTIBOT_WORKER_SRC__: WORKER_SOURCE_ESCAPED
    };

    // Odd entries are the tokens the split captured. A token with no value
    // is left as itself rather than rendered as "undefined", so it is visible
    // in the page instead of being a plausible-looking wrong one.
    let out = "";
    for (let i = 0; i < PAGE_PARTS.length; i++) {
        if (i % 2 === 0) {
            out += PAGE_PARTS[i];
        } else {
            const value = values[PAGE_PARTS[i]];
            out += value === undefined ? PAGE_PARTS[i] : value;
        }
    }
    return out;
}

function serve_challenge(r) {
    report_config(r);

    if (!secret_configured()) {
        r.error("antibot: ANTIBOT_SECRET is missing or too short");
        count("misconfigured");
        r.return(500, "Antibot misconfigured\n");
        return;
    }

    const slot = current_slot();
    const html = build_challenge(r, slot);

    // info, not warning: a challenge is the module's ordinary answer, and one
    // arrives for every request that has no cookie yet.
    r.log("antibot: challenge served to " + log_field(r.remoteAddress) +
          " uri=" + log_field(r.uri));

    r.headersOut["Content-Type"] = "text/html; charset=utf-8";
    r.headersOut["Cache-Control"] = "no-store, no-cache, must-revalidate";
    r.headersOut["X-Robots-Tag"] = "noindex, nofollow";
    r.headersOut["X-Content-Type-Options"] = "nosniff";
    count("challenges");
    r.return(200, html);
}

// The counters, as text. Restrict the location that serves it: the numbers
// say how much of the traffic is being challenged, which is not a visitor's
// business.
function status(r) {
    report_config(r);
    r.headersOut["Content-Type"] = "text/plain; charset=utf-8";
    r.headersOut["Cache-Control"] = "no-store";

    const dict = stats_dict();
    let body = "version " + ANTIBOT_VERSION + "\n" +
               "bits " + POW_BITS_EFFECTIVE + "\n";
    if (dict === null) {
        r.return(200, body + "zone missing\n");
        return;
    }
    body += "zone " + STATS_ZONE + "\n";
    for (let i = 0; i < STATS_KEYS.length; i++) {
        let value = 0;
        try {
            value = dict.get(STATS_KEYS[i]) || 0;
        } catch (err) {
            value = 0;
        }
        body += STATS_KEYS[i] + " " + value + "\n";
    }
    r.return(200, body);
}

export default { check, serve_challenge, status };
