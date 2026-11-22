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
// A client is identified by its address, its User-Agent and its
// Accept-Language; address_key() says how an address is reduced. The
// challenge is an HMAC-SHA256 over that identity and the current time slot.
// The client passes by finding a nonce whose SHA-256 with the challenge
// begins with POW_BITS zero bits, and stores "<slot>.<nonce>" in the
// COOKIE_NAME cookie. A cookie is accepted for its own slot and the one after
// it, so it lasts between WINDOW_SIZE and twice WINDOW_SIZE.
//
// report() takes the solver path and the wait the page sends after it solves,
// and counts them.
//
// The module keeps no state a request can reach. Rate limiting and blocking
// belong to limit_req.
//
// Requirements:
//
// - ANTIBOT_SECRET reaches the nginx workers and is at least 32 characters.
// - $remote_addr is the client address. Behind a CDN, set set_real_ip_from and
//   real_ip_header, otherwise every visitor shares one identity.
//
// Configuration problems are written to the error log on the first request,
// not at load.


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

// njs runs this file again for every request, so CONFIG_WARNINGS is full
// again on the next request and draining it here does not carry. The shared
// dictionary outlives the request and a reload, and holds a digest of the
// warnings last written: a request whose warnings have that digest skips
// them, and a reload that brings different ones writes those once. Without
// the zone every request writes them, because there is nowhere to record
// that one did.
const CONFIG_WARNED_KEY = "config_warned";

// 48 bits of the SHA-256 of the warnings, a whole number a number zone holds
// exactly.
function warnings_digest() {
    return parseInt(cryptoModule.createHash("sha256")
        .update(CONFIG_WARNINGS.join("\n")).digest("hex").slice(0, 12), 16);
}

function report_config(r) {
    if (CONFIG_WARNINGS.length === 0) {
        return;
    }
    const dict = stats_dict();
    if (dict !== null) {
        try {
            const digest = warnings_digest();
            if (dict.get(CONFIG_WARNED_KEY) === digest) {
                return;
            }
            dict.set(CONFIG_WARNED_KEY, digest);
        } catch (err) {
            // The zone is unusable. A misconfiguration is worth repeating.
        }
    }
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

// True when v is a string of min to max characters, none of them matched by
// outside, a class written negated such as /[^0-9]/. njs compiles a RegExp
// with PCRE2, where $ also matches before a final newline, so /^[0-9]+$/
// takes "22\n" under nginx and refuses it under node, where the suites run.
// Every value this module embeds, logs or compares is checked this way. The
// one anchored pattern left, in address_key(), runs only on text this has
// checked.
function made_of(v, outside, min, max) {
    return typeof v === "string" && v.length >= min && v.length <= max &&
        !outside.test(v);
}

// A string of decimal digits with no leading zero, as a nonce, a slot and a
// reported wait are written.
function is_decimal(v, max) {
    return made_of(v, /[^0-9]/, 1, max) &&
        (v.length === 1 || v.charAt(0) !== "0");
}

// A numeric setting from the environment, written in decimal digits. Number()
// would also read whitespace as 0, hexadecimal, exponents and fractions, none
// of which is a value an operator means, so anything else is NaN and fails
// every range below.
function env_integer(name) {
    const raw = env_raw(name);
    if (raw === null) {
        return null;
    }
    return ["ANTIBOT_" + name + "=" + raw,
            made_of(raw, /[^0-9]/, 1, 15) ? Number(raw) : NaN];
}

function is_integer(v, min, max) {
    return typeof v === "number" && Math.floor(v) === v && v >= min && v <= max;
}

// A setting is the first valid value among the environment, the constant in
// this file and BUILTIN, in that order. Each candidate is [label, value], or
// null where the environment holds none. broken(value) names the rule a value
// breaks, or returns null for a valid one. Every candidate passed over is
// reported with that rule and the value used instead, so a typo in either
// place is never silent. BUILTIN values are valid, so a value is always found.
function first_valid(candidates, broken) {
    const rejected = [];
    for (let i = 0; i < candidates.length; i++) {
        if (candidates[i] === null) {
            continue;
        }
        const why = broken(candidates[i][1]);
        if (why === null) {
            for (let j = 0; j < rejected.length; j++) {
                fail_config(rejected[j] + ", using " + candidates[i][1]);
            }
            return candidates[i][1];
        }
        rejected.push(candidates[i][0] + " " + why);
    }
    return null;
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

// Cookie lifetime in the browser, in seconds. null means twice WINDOW_SIZE: a
// cookie is accepted for its own slot and the one after it, so it is useful
// for at most that long, and past it the browser would send bytes the module
// always refuses.
const COOKIE_TTL = null;

// Difficulty in leading zero bits, at least 1. Each bit doubles the work.
// There is no value that disables verification: check() always recomputes
// the proof. docs/configuration.md#difficulty gives the measured solve times.
const POW_BITS = 22;

const POW_BITS_MAX = 32;

// Multiple of the expected work a client may spend before giving up.
// A correct client exhausts it with probability e^-POW_EFFORT_FACTOR.
const POW_EFFORT_FACTOR = 64;

// Level the per-challenge and per-report log lines are written at: "info",
// "warn", "error" or "off". A challenge is the module's ordinary answer, so it
// is written at info, which nginx keeps out of an error log below that level.
// A deployment that wants the lines without turning the whole error log up to
// info raises this; "off" writes nothing.
const CHALLENGE_LOG_LEVEL = "info";

const CHALLENGE_LOG_LEVELS = ["off", "info", "warn", "error"];

// Where the page sends the solver path and its wait after it solves. nginx
// serves it from a location gated by check() that calls report().
const REPORT_PATH = "/__antibot_report";

// How many cookies sent under COOKIE_NAME are verified. A browser sends one:
// the __Host- prefix forces Path=/, so a host cannot hold two. Trying every
// one would let a request choose how many hashes the server performs.
const MAX_COOKIE_CANDIDATES = 4;

// What a setting falls back to when neither the environment nor the constant
// above holds a valid value. Not for editing: change the constants above.
const BUILTIN = {
    COOKIE_NAME: "__Host-antibot-ac",
    WINDOW_SIZE: 6 * 60 * 60,
    POW_BITS: 22,
    CHALLENGE_LOG_LEVEL: "info",
    REPORT_PATH: "/__antibot_report"
};

const POW_BITS_EFFECTIVE = (function () {
    let b = first_valid(
        [env_integer("POW_BITS"), ["POW_BITS=" + POW_BITS, POW_BITS],
         ["", BUILTIN.POW_BITS]],
        function (v) {
            return is_integer(v, 1, Infinity) ? null : "is not an integer of at least 1";
        });
    if (b > POW_BITS_MAX) {
        fail_config("POW_BITS=" + b + " exceeds POW_BITS_MAX=" + POW_BITS_MAX +
                    ", clamped to " + POW_BITS_MAX);
        b = POW_BITS_MAX;
    }
    return b;
})();

// A slot shorter than a minute would expire while a client is still solving.
// The ceiling keeps a cookie from outliving a secret rotation by months.
const WINDOW_SIZE_MAX = 30 * 24 * 60 * 60;

const WINDOW_SIZE_EFFECTIVE = first_valid(
    [env_integer("WINDOW_SIZE"), ["WINDOW_SIZE=" + WINDOW_SIZE, WINDOW_SIZE],
     ["", BUILTIN.WINDOW_SIZE]],
    function (v) {
        return is_integer(v, 60, WINDOW_SIZE_MAX)
            ? null : "is not an integer between 60 and " + WINDOW_SIZE_MAX + " seconds";
    });

// The __Host- prefix forces Path=/ and forbids Domain, which is what keeps a
// host from holding two cookies under this name. A name without it still
// works and gives up that guarantee, so it is reported and kept.
const COOKIE_NAME_EFFECTIVE = (function () {
    const raw = env_raw("COOKIE_NAME");
    const v = first_valid(
        [raw === null ? null : ["ANTIBOT_COOKIE_NAME=" + raw, raw],
         ["COOKIE_NAME=" + COOKIE_NAME, COOKIE_NAME], ["", BUILTIN.COOKIE_NAME]],
        function (name) {
            return made_of(name, /[^A-Za-z0-9!#$%&'*+\-.^_`|~]/, 1, Infinity)
                ? null : "is not a cookie name";
        });
    if (v.indexOf("__Host-") !== 0) {
        fail_config("COOKIE_NAME=" + v + " has no __Host- prefix, so a host " +
                    "can hold more than one under this name");
    }
    return v;
})();

const SITE_NAME_EFFECTIVE = env_string("SITE_NAME", SITE_NAME);

// A lifetime below twice the window has the browser drop the cookie while the
// module would still take it, which challenges the visitor again for no gain.
// A Max-Age that is not a run of digits is ignored by the browser, so a value
// must be a whole number of seconds.
const COOKIE_TTL_EFFECTIVE = (function () {
    const floor = 2 * WINDOW_SIZE_EFFECTIVE;
    return first_valid(
        [env_integer("COOKIE_TTL"),
         COOKIE_TTL === null ? null : ["COOKIE_TTL=" + COOKIE_TTL, COOKIE_TTL],
         ["", floor]],
        function (v) {
            if (!is_integer(v, 0, 999999999999999)) {
                return "is not a whole number of seconds";
            }
            return v < floor ? "is below twice WINDOW_SIZE=" + floor : null;
        });
})();

const CHALLENGE_LOG_LEVEL_EFFECTIVE = (function () {
    const raw = env_raw("CHALLENGE_LOG_LEVEL");
    return first_valid(
        [raw === null ? null : ["ANTIBOT_CHALLENGE_LOG_LEVEL=" + raw, raw],
         ["CHALLENGE_LOG_LEVEL=" + CHALLENGE_LOG_LEVEL, CHALLENGE_LOG_LEVEL],
         ["", BUILTIN.CHALLENGE_LOG_LEVEL]],
        function (v) {
            return CHALLENGE_LOG_LEVELS.indexOf(v) !== -1
                ? null : "is not one of " + CHALLENGE_LOG_LEVELS.join(", ");
        });
})();

// The page inserts the path into a URL it requests from the same origin, so
// it is an absolute path of URL-safe characters and nothing else. A second
// leading / would make it a URL on another host.
const REPORT_PATH_EFFECTIVE = (function () {
    const raw = env_raw("REPORT_PATH");
    return first_valid(
        [raw === null ? null : ["ANTIBOT_REPORT_PATH=" + raw, raw],
         ["REPORT_PATH=" + REPORT_PATH, REPORT_PATH], ["", BUILTIN.REPORT_PATH]],
        function (v) {
            return made_of(v, /[^A-Za-z0-9._~\/-]/, 1, Infinity) &&
                v.charAt(0) === "/" && v.charAt(1) !== "/"
                ? null : "is not an absolute path of letters, digits and ._~/-, " +
                         "beginning with one /";
        });
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
const STATS_KEYS = ["challenges", "accepted", "rejected", "misconfigured",
                    "solved_wasm", "solved_js", "solved_slow"];

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
        if (!made_of(all[i], /[^0-9a-fA-F]/, 1, 4)) {
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
// Three IPv6 ranges hold one IPv4 client per address rather than one host per
// /64, so the /64 would put many clients in one identity:
//
// - 64:ff9b::/96, the well-known prefix of IPv4/IPv6 translation (RFC 6052),
//   carries the client's IPv4 address in its last 32 bits and is reduced to
//   it, as an IPv4-mapped address is;
// - 64:ff9b:1::/48, the local-use translation prefix (RFC 8215), embeds the
//   IPv4 address at a position the operator's prefix length decides, so it is
//   kept whole;
// - 2001::/32, Teredo (RFC 4380), carries its server's IPv4 address in bits 32
//   to 63, so every client of one server shares a /64, and it is kept whole.
//
// Two different addresses must never produce the same key. Folding an
// unparsed address to a constant would put every such client in one bucket,
// where one solved cookie serves all of them.
function address_key(address) {
    if (address.indexOf(":") === -1) {
        return address;
    }
    // Only hex digits, colons and dots reach the patterns below, so none of
    // them can match before a final newline. A zone id is kept whole here.
    if (!made_of(address, /[^0-9A-Fa-f:.]/, 1, Infinity)) {
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
    const groups = expand_ipv6(address);
    if (!groups) {
        return address;
    }
    if (groups[0] === "64" && groups[1] === "ff9b") {
        if (groups[2] === "0" && groups[3] === "0" && groups[4] === "0" &&
            groups[5] === "0") {
            const high = parseInt(groups[6], 16);
            const low = parseInt(groups[7], 16);
            return (high >> 8) + "." + (high & 255) + "." + (low >> 8) + "." + (low & 255);
        }
        if (groups[2] === "1") {
            return groups.join(":");
        }
    }
    if (groups[0] === "2001" && groups[1] === "0") {
        return groups.join(":");
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

// The challenge line goes to the level CHALLENGE_LOG_LEVEL_EFFECTIVE names.
// njs maps r.log to info, r.warn to warn and r.error to error, and nginx
// writes a line only at or above the level error_log is set to.
function log_challenge(r, message) {
    if (CHALLENGE_LOG_LEVEL_EFFECTIVE === "off") {
        return;
    }
    if (CHALLENGE_LOG_LEVEL_EFFECTIVE === "warn") {
        r.warn(message);
    } else if (CHALLENGE_LOG_LEVEL_EFFECTIVE === "error") {
        r.error(message);
    } else {
        r.log(message);
    }
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
    if (!is_decimal(slot, 12)) {
        return null;
    }
    // 15 digits at most: Number() is exact below 2^53, so the comparison
    // against the iteration cap below means what it says.
    if (!is_decimal(nonce, 15)) {
        return null;
    }
    // The page's workers scan the nonces below the cap, so one at or above it
    // is a nonce no page produced.
    if (Number(nonce) >= POW_MAX_ITERATIONS) {
        return null;
    }
    return { slot: Number(slot), nonce: nonce };
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

// The template split on its __ANTIBOT_*__ tokens, text and tokens
// alternating, and joined with values per request. Substituting into the
// assembled page would put its length, mostly the solver, into the cost of
// serving it. The split scans with indexOf: njs runs this file for every
// request, and under njs 0.8.2 String.prototype.split with a regular
// expression took about 10 ms of each one on the reference machine.
const PAGE_PARTS = (function () {
    const parts = [];
    let text = 0;
    let from = 0;
    for (;;) {
        const open = PAGE_TEMPLATE.indexOf("__ANTIBOT_", from);
        if (open === -1) {
            break;
        }
        const close = PAGE_TEMPLATE.indexOf("__", open + 10);
        if (close === -1) {
            break;
        }
        if (made_of(PAGE_TEMPLATE.slice(open + 10, close), /[^A-Z0-9_]/, 1, Infinity)) {
            parts.push(PAGE_TEMPLATE.slice(text, open), PAGE_TEMPLATE.slice(open, close + 2));
            text = close + 2;
            from = text;
        } else {
            from = open + 1;
        }
    }
    parts.push(PAGE_TEMPLATE.slice(text));
    return parts;
})();

// Every token the template carries must have a value below. A token added to
// src/page.html and not here would otherwise render as "undefined" in a page
// that still parses, so the mismatch is reported once at load.
const PAGE_TOKENS = [
    "__ANTIBOT_HEADING__", "__ANTIBOT_CHALLENGE__", "__ANTIBOT_BITS__",
    "__ANTIBOT_SLOT__", "__ANTIBOT_CAP__", "__ANTIBOT_EXPECTED__",
    "__ANTIBOT_COOKIE_NAME__", "__ANTIBOT_COOKIE_TTL__",
    "__ANTIBOT_WASM_B64__", "__ANTIBOT_WORKER_SRC__", "__ANTIBOT_REPORT_PATH__"
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
        __ANTIBOT_WORKER_SRC__: WORKER_SOURCE_ESCAPED,
        __ANTIBOT_REPORT_PATH__: REPORT_PATH_EFFECTIVE
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

    // One line arrives for every request that has no cookie yet, so the level
    // is a setting: info by default, raised where the line has to show in an
    // error log that is not turned up to info.
    // $request_uri is what the client asked for. After error_page, r.uri is
    // the internal location the request was redirected to.
    log_challenge(r, "antibot: challenge served to " + log_field(r.remoteAddress) +
                  " uri=" + log_field(r.variables.request_uri));

    r.headersOut["Content-Type"] = "text/html; charset=utf-8";
    r.headersOut["Cache-Control"] = "no-store, no-cache, must-revalidate";
    r.headersOut["X-Robots-Tag"] = "noindex, nofollow";
    r.headersOut["X-Content-Type-Options"] = "nosniff";
    count("challenges");
    r.return(200, html);
}

// A solve counts as slow when the visitor waited longer than this many
// seconds from navigation to the nonce.
const SLOW_SOLVE_SECONDS = 10;

// The page sends the solver that won, "wasm" or "js", and the milliseconds
// from navigation to the nonce, once it has written the cookie. REPORT_PATH is
// served from a location gated by check(), so only a client holding a valid
// cookie reaches this. A holder can send it again, so the counts are what
// visitors report.
function report(r) {
    report_config(r);
    const solver = r.args.solver;
    const ms = r.args.ms;
    if ((solver !== "wasm" && solver !== "js") || !is_decimal(ms, 10)) {
        r.return(400, "");
        return;
    }
    count("solved_" + solver);
    if (Number(ms) > SLOW_SOLVE_SECONDS * 1000) {
        count("solved_slow");
    }
    log_challenge(r, "antibot: solved by " + log_field(r.remoteAddress) +
                  " solver=" + solver + " ms=" + log_field(ms));
    r.return(204, "");
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
               "bits " + POW_BITS_EFFECTIVE + "\n" +
               "window " + WINDOW_SIZE_EFFECTIVE + "\n";
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

export default { check, serve_challenge, report, status };
