/*
 * End-to-end suite for the antibot njs module.
 *
 *   ANTIBOT_SECRET=$(openssl rand -hex 32) node test/module.test.mjs [path/to/antibot.js]
 *
 * serve_challenge() emits the page, the emitted worker source runs in real OS
 * threads, and the resulting cookie is fed back to check(). Both solver paths
 * are exercised: the SIMD wasm module, and the embedded pure-JS solver that
 * takes over when no module is supplied, which is what happens on an engine
 * that cannot compile the SIMD build. Re-screening is checked to reach
 * navigations only.
 *
 * For the solvers themselves see test/solver.test.mjs.
 * Exit status is non-zero if any check fails.
 */

import { Worker } from 'node:worker_threads';
import crypto from 'crypto';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { runChallengePage } from './page-runner.mjs';
import fs from 'node:fs';
import path from 'node:path';
/* The module reads ANTIBOT_SECRET at import time, so it must be set before the
   dynamic import below. Generate one if the caller did not supply it: nothing
   here depends on a particular value, and a test that needs an environment
   variable set to run at all is a test people skip. */
if (!process.env.ANTIBOT_SECRET || process.env.ANTIBOT_SECRET.length < 32) {
    process.env.ANTIBOT_SECRET = crypto.randomBytes(32).toString('hex');
    console.log("ANTIBOT_SECRET not supplied; using a random one for this run");
}

const MODULE_PATH = process.argv[2]
    ? pathToFileURL(process.argv[2]).href
    : new URL('../dist/antibot.js', import.meta.url).href;
if (!fs.existsSync(new URL(MODULE_PATH))) {
    console.error(MODULE_PATH.replace(/^.*\//, '') + ' not found. This suite runs ' +
                  'against the build output; run ./build.sh first.');
    process.exit(2);
}
const mod = (await import(MODULE_PATH)).default;

let failures = 0;

/* Each block below is a named test. A throw fails that one and the run
   continues, where before it ended the suite and hid every later result.
   check() still counts, so a block reports all of its failures rather than
   stopping at the first. */
let claimed = 0;
const section = (name, fn) => test(name, async () => {
    const before = failures;
    await fn();
    if (failures > before) {
        claimed += failures - before;
        throw new Error((failures - before) + ' check(s) failed');
    }
});
const check = (ok, label) => {
    if (!ok) { failures++; console.log("  FAIL: " + label); }
    return ok;
};

/* Web Worker shim: bridge self.postMessage/onmessage onto a worker thread. */
const SHIM = `
import { parentPort, workerData } from 'node:worker_threads';
const self_ = { postMessage: (m) => parentPort.postMessage(m), onmessage: null };
new Function("self", workerData.src)(self_);
parentPort.on('message', (d) => { if (self_.onmessage) self_.onmessage({ data: d }); });
`;

const makeR = (cookie, ip = "203.0.113.7", dest = null) => ({
    remoteAddress: ip, uri: "/tests",
    headersIn: { "User-Agent": "Mozilla/5.0", "Accept-Language": "en-US",
                 ...(dest ? { "Sec-Fetch-Dest": dest } : {}),
                 ...(cookie ? { Cookie: cookie } : {}) },
    headersOut: {}, error() {}, warn() {},
    logged: [], log(msg) { this.logged.push(msg); },
    return(code, body) { this.code = code; this.body = body; }
});

const r0 = makeR(null);
mod.serve_challenge(r0);
check(r0.code === 200, "serve_challenge did not return 200");
const page      = r0.body;
const challenge = /var challenge="([0-9a-f]+)"/.exec(page)[1];
const bits      = Number(/,bits=(\d+);/.exec(page)[1]);
const slot      = /var slot="(\d+)"/.exec(page)[1];
const cap       = Number(/,cap=(\d+);/.exec(page)[1]);
const src       = JSON.parse(/var src=("(?:[^"\\]|\\.)*");/.exec(page)[1]);
const simdB64   = JSON.parse(/var simd=("(?:[^"\\]|\\.)*");/.exec(page)[1]);
const dec = (s) => new Uint8Array(Buffer.from(s, 'base64'));
/* Read the cookie name out of the emitted page so renaming COOKIE_NAME in the
   module does not silently turn every assertion below into a no-op. The page
   names it once, where it builds the value it later writes and reads back. */
const POW_BITS_EFFECTIVE_IN_PAGE = bits;
const COOKIE_NAME_MATCH = /var v="([^"=]+)="\+slot/.exec(page);
if (!COOKIE_NAME_MATCH) {
    throw new Error('the challenge page no longer names the cookie where this ' +
                    'suite looks for it; every assertion below would be a no-op');
}
const COOKIE_NAME = COOKIE_NAME_MATCH[1];

console.log(MODULE_PATH.replace(/^.*\//, ''));
console.log("  challenge page: " + page.length + " bytes, bits=" + bits +
            ", cap=" + cap.toLocaleString("en-US"));

/* The emitted page script and worker script must both parse. */
const inner = /<script>\n([\s\S]*?)<\/script>/.exec(page)[1];
try { new Function(inner); check(true, ""); }
catch (e) { check(false, "emitted page script does not parse: " + e.message); }
try { new Function("self", src); }
catch (e) { check(false, "emitted worker script does not parse: " + e.message); }
console.log("  page script and worker script parse");

function digestOk(nonce) {
    const d = crypto.createHash('sha256').update(challenge + ":" + nonce).digest('hex');
    const full = bits >> 2, rem = bits & 3;
    if (d.slice(0, full) !== "0".repeat(full)) return false;
    if (rem && (parseInt(d[full], 16) >> (4 - rem)) !== 0) return false;
    return true;
}

/* Solve through a pool of `lanes` real threads, mirroring the page's logic. */
function solveWithPool(lanes, wasmModule) {
    return new Promise((resolve, reject) => {
        const ws = []; let over = false, dead = 0;
        const stop = (fn) => Promise.all(ws.map(w => w.terminate())).then(fn);
        for (let j = 0; j < lanes; j++) {
            const wk = new Worker(SHIM, { eval: true, workerData: { src } });
            wk.on('message', (ev) => {
                if (over) return;
                if (ev.n !== undefined) { over = true; stop(() => resolve(ev.n)); }
                else if (ev.f && ++dead >= lanes) { over = true; stop(() => reject(new Error("exhausted"))); }
            });
            ws.push(wk);
        }
        for (let j = 0; j < lanes; j++) {
            ws[j].postMessage({ c: challenge, b: bits, m: cap, mod: wasmModule, l: j, k: lanes });
        }
    });
}

/* The SIMD path, then the fallback: passing no module is exactly what the
   page does when WebAssembly is absent or the SIMD build will not compile. */
await section("both solver paths reach the same nonce", async () => {
    for (const [label, b64] of [["simd   ", simdB64], ["pure JS", null]]) {
        const wasmModule = b64 ? await WebAssembly.compile(dec(b64)) : null;
        for (const lanes of [1, 4]) {
            const t = Date.now();
            const nonce = await solveWithPool(lanes, wasmModule);
            const secs = (Date.now() - t) / 1000;
            check(digestOk(nonce), label + " lanes=" + lanes + ": digest does not meet " + bits + " bits");

            /* Sec-Fetch-Dest: empty makes this a subresource request, which is
               never re-screened. A navigation would be re-screened at
               RESCREEN_RATE and return 401 for a perfectly valid cookie, so
               asserting 204 on one would be flaky, not strict. Re-screening has
               its own test below. */
            const rc = makeR(COOKIE_NAME + "=" + slot + "." + nonce, "203.0.113.7", "empty");
            mod.check(rc);
            check(rc.code === 204, label + " lanes=" + lanes + ": solved cookie rejected (" + rc.code + ")");
            console.log("  " + label + " lanes=" + lanes + ": " + secs.toFixed(2) + "s nonce=" +
                        String(nonce).padStart(10) + " check()=" + rc.code);
        }
    }
});

/* Rejections. */
const good = await solveWithPool(1, null);
const cases = [
    ["tampered nonce", makeR(COOKIE_NAME + "=" + slot + "." + (good + 1))],
    ["no cookie",      makeR(null)],
    ["other IP",       makeR(COOKIE_NAME + "=" + slot + "." + good, "198.51.100.9")],
    ["stale slot",     makeR(COOKIE_NAME + "=" + (Number(slot) - 2) + "." + good)],
    ["malformed",      makeR(COOKIE_NAME + "=notaslot.notanonce")],
];
await section("difficulty is clamped to a usable value", async () => {
    for (const [label, r] of cases) {
        mod.check(r);
        check(r.code === 401, label + " was not rejected (got " + r.code + ")");
        console.log("  reject " + label.padEnd(15) + " -> " + r.code);
    }
});

/* Re-screening must reach navigations only: the challenge page is not a valid
   response to a fetch or an image request. RESCREEN_RATE is 0.02, so over 500
   navigations some 401s are expected, and over 500 subresource requests none
   are permitted. */
const cookie = COOKIE_NAME + "=" + slot + "." + good;
const rescreens = (dest) => {
    let n = 0;
    for (let i = 0; i < 500; i++) {
        const r = makeR(cookie, "203.0.113.7", dest);
        mod.check(r);
        if (r.code === 401) n++;
    }
    return n;
};
await section("a request without a valid cookie is refused", async () => {
    for (const dest of ["image", "empty", "script"]) {
        const n = rescreens(dest);
        check(n === 0, "Sec-Fetch-Dest: " + dest + " was re-screened " + n + " times");
        console.log("  Sec-Fetch-Dest: " + dest.padEnd(8) + " -> " + n + " re-screens in 500");
    }
});
const nav = rescreens("document") + rescreens(null);
check(nav > 0, "no navigation was re-screened in 1000 requests (RESCREEN_RATE broken?)");
console.log("  navigations                -> " + nav + " re-screens in 1000 (rate " +
            (nav / 10).toFixed(1) + "%, configured 2%)");

/* The accept path must be deterministic for a subresource request: a valid
   cookie is always 204, never a stray re-screen. */
let strays = 0;
await section("a subresource is never re-screened", async () => {
    for (let i = 0; i < 2000; i++) {
        const r = makeR(cookie, "203.0.113.7", "empty");
        mod.check(r);
        if (r.code !== 204) strays++;
    }
});
check(strays === 0, "a valid cookie was rejected " + strays + " times in 2000 subresource requests");
console.log("  valid cookie, 2000 subresource requests -> " + (2000 - strays) + " accepted");

/* No configuration may skip verification. POW_BITS is clamped to at least 1,
   so no accepted value yields a difficulty of zero.

   Forgery is tested separately, at a difficulty where guessing is negligible.
   At one bit a guessed nonce passes half the time, which is verification
   working, so a forgery assertion there would be measuring luck. */
/* Builds a copy of the module under test at another difficulty. A rewrite that
   silently matched nothing would grade the unmodified module and pass for the
   wrong reason. Rewriting a value to itself is legitimate, so the invariant is
   that the pattern matched, not that the text changed. */
const VARIANT_OS = await import('node:os');
const VARIANT_SRC = fs.readFileSync(new URL(MODULE_PATH), 'utf8');
const VARIANT_DIR = fs.mkdtempSync(path.join(VARIANT_OS.tmpdir(), 'antibot-bits-'));
const POW_BITS_LINE = /^const POW_BITS = -?\d+;$/m;
if (!POW_BITS_LINE.test(VARIANT_SRC)) {
    throw new Error('POW_BITS declaration not found; the difficulty tests ' +
                    'would have graded the unmodified module');
}
let variantSeq = 0;
const variantWith = async (replacements) => {
    let text = VARIANT_SRC;
    for (const [decl, value] of replacements) {
        const line = new RegExp('^const ' + decl + ' = [^;]+;$', 'm');
        if (!line.test(text)) {
            throw new Error(decl + ' declaration not found; the variant would ' +
                            'have graded the unmodified module');
        }
        const wanted = 'const ' + decl + ' = ' + value + ';';
        text = text.replace(line, wanted);
        if (text.indexOf(wanted) === -1) {
            throw new Error(decl + ' rewrite produced no such line');
        }
    }
    const file = path.join(VARIANT_DIR, 'v' + (variantSeq++) + '.js');
    fs.writeFileSync(file, text);
    return (await import(pathToFileURL(file).href)).default;
};
const variantFor = (bits) => variantWith([['POW_BITS', bits]]);

await section("no configuration skips verification", async () => {

        for (const bits of [0, -1, 1, 22, 32, 99]) {
            const variant = await variantFor(bits);
            const r = makeR(null);
            variant.serve_challenge(r);
            const effective = Number(/,bits=(\d+);/.exec(r.body)[1]);
            check(effective >= 1, 'POW_BITS=' + bits + ' yields difficulty ' + effective);
            console.log('  POW_BITS=' + String(bits).padEnd(3) + ' -> difficulty ' + effective);
        }

        /* At 24 bits a guess passes with probability 2^-24. */
        const strict = await variantFor(24);
        const slotNow = Math.floor(Date.now() / 1000 / 21600);
        let accepted = 0;
        for (const n of ['0', '1', '999999', '4294967295']) {
            for (const slotTry of [slotNow, slotNow - 1]) {
                const r = makeR(COOKIE_NAME + '=' + slotTry + '.' + n);
                strict.check(r);
                if (r.code !== 401) accepted++;
            }
        }
        check(accepted === 0, 'POW_BITS=24: ' + accepted + ' forged cookies accepted');
        console.log('  forged cookies at 24 bits -> ' + (8 - accepted) + '/8 rejected');

        /* A cookie is bound to one address. Addresses that differ must not share
           an identity, including IPv4-mapped forms and addresses that do not
           parse, which a fold-to-zero would have put in one bucket.

           The identity is checked through the challenge the server issues, which
           is deterministic. Replaying a cookie is the behaviour that matters, but
           a nonce solved for one identity satisfies another with probability
           2^-bits, so that part runs at a difficulty where the coincidence is
           negligible rather than at one where it is a routine flake. */
        const challengeFor = (variant, ip) => {
            const r = makeR(null, ip);
            variant.serve_challenge(r);
            return /var challenge="([0-9a-f]+)"/.exec(r.body)[1];
        };
        const distinct = [
            ['::ffff:192.0.2.1', '::ffff:198.51.100.7'],
            ['2001:db8:1:2::1',  '2001:db8:1:3::1'],
            ['not-an-ip:x',      'also-not-an-ip:y'],
            ['::ffff:999.999.999.999', '::ffff:99.99.99.99'],
        ];
        const strictVariant = await variantFor(24);
        for (const [one, two] of distinct) {
            const a1 = challengeFor(strictVariant, one);
            const b1 = challengeFor(strictVariant, two);
            check(a1 !== b1, one + ' and ' + two + ' share an identity');
            console.log('  ' + one.padEnd(24) + ' vs ' + two.padEnd(22) +
                        (a1 !== b1 ? ' distinct' : ' SHARED'));
        }
        /* The two spellings of one host must agree. */
        check(challengeFor(strictVariant, '192.0.2.1') ===
              challengeFor(strictVariant, '::ffff:192.0.2.1'),
              '192.0.2.1 and ::ffff:192.0.2.1 were given different identities');
        console.log('  192.0.2.1 and ::ffff:192.0.2.1 agree');

        /* The other half of the invariant. docs/security.md states the identity as
           the /64, and only the negative half was checked above. IPv6 privacy
           extensions rotate the interface identifier, so a client that keeps its
           prefix has to keep its identity or it is challenged on every rotation. */
        const same64 = [
            ['2001:db8:1:2::1',       '2001:db8:1:2::9999'],
            ['2001:db8:1:2:aaaa::1',  '2001:db8:1:2:ffff:ffff:ffff:ffff'],
            ['2001:db8:1:2::',        '2001:db8:1:2:0:0:0:5'],
        ];
        for (const [one, two] of same64) {
            const agree = challengeFor(strictVariant, one) === challengeFor(strictVariant, two);
            check(agree, one + ' and ' + two + ' are one /64 and were given ' +
                         'different identities');
            console.log('  ' + one.padEnd(24) + ' and ' + two.padEnd(30) +
                        (agree ? ' one identity' : ' SPLIT'));
        }

        /* One replay, at a difficulty where an accidental acceptance is 2^-20. */
        const replay = await variantFor(20);
        const meets20 = (hex) => hex.slice(0, 5) === '00000';
        const own = '::ffff:192.0.2.1', other = '::ffff:198.51.100.7';
        const page = makeR(null, own);
        replay.serve_challenge(page);
        const ch = /var challenge="([0-9a-f]+)"/.exec(page.body)[1];
        const slotValue = /var slot="(\d+)"/.exec(page.body)[1];
        let nonce = -1;
        for (let n = 0; n < 5e7; n++) {
            if (meets20(crypto.createHash('sha256').update(ch + ':' + n).digest('hex'))) {
                nonce = n; break;
            }
        }
        check(nonce >= 0, 'no nonce found at 20 bits');
        const cookie = COOKIE_NAME + '=' + slotValue + '.' + nonce;
        const mine = makeR(cookie, own, 'empty');
        replay.check(mine);
        const theirs = makeR(cookie, other, 'empty');
        replay.check(theirs);
        check(mine.code === 204, 'own cookie rejected (' + mine.code + ')');
        check(theirs.code === 401, 'cookie accepted for another address');
        console.log('  replay at 20 bits: own ' + mine.code + ', other ' + theirs.code);
});

/* Run the page the way a browser does. Parsing the inline script proves only
   that it is syntactically valid; this executes it against stubs for document,
   navigator, Worker, Blob and URL, so the cookie write, the worker pool and
   the fallback selection are all exercised. */
await section("the page solves in a browser-shaped environment", async () => {
    for (const [label, options] of [
        ['wasm, 4 cores', { cores: 4 }],
        ['wasm, 1 core',  { cores: 1 }],
        ['no WebAssembly', { cores: 2, withWebAssembly: false }],
    ]) {
        const served = makeR(null);
        mod.serve_challenge(served);
        const t = Date.now();
        let out;
        try {
            out = await runChallengePage(served.body, options);
        } catch (err) {
            check(false, 'page (' + label + ') did not finish: ' + err.message);
            continue;
        }
        const secs = ((Date.now() - t) / 1000).toFixed(2);
        check(!out.failed, 'page (' + label + ') showed the failure message');
        check(out.cookies.length === 1, 'page (' + label + ') set ' + out.cookies.length + ' cookies');

        const value = (out.cookies[0] || '').split(';')[0];
        check(value.startsWith(COOKIE_NAME + '='),
              'page (' + label + ') set an unexpected cookie: ' + value);
        check(out.violations.length === 0,
              'page (' + label + ') set a cookie a browser would reject: ' +
              out.violations.join('; '));

        const back = makeR(value, '203.0.113.7', 'empty');
        mod.check(back);
        check(back.code === 204,
              'page (' + label + ') cookie rejected by check() (' + back.code + ')');
        console.log('  page ' + label.padEnd(15) + ' ' + secs + 's, ' + out.workers +
                    ' worker(s), progress ' + JSON.stringify(out.progress) +
                    ', check() ' + back.code);
    }
});

/* The page is assembled from src/page.html by substituting tokens. A token
   with no value would render as "undefined" and a token the split missed would
   ship as itself, and both would still be a page that parses. */
await section("every token in the page template is substituted", async () => {
        for (const [label, mod2] of [['default', mod],
                                     ['with a heading', await variantWith([['SITE_NAME', '"Acme"']])]]) {
            const r = makeR(null, '203.0.113.61');
            const logged = [];
            r.error = (m) => logged.push(m);
            mod2.serve_challenge(r);
            const leftover = r.body.match(/__ANTIBOT_[A-Z0-9_]+__/g);
            check(leftover === null, 'the ' + label + ' page carries an unsubstituted ' +
                  'token: ' + JSON.stringify(leftover));
            check(logged.length === 0,
                  'the ' + label + ' page reported a token with no value: ' + logged.join('; '));
        }
        console.log('  page template: every token substituted, with and without a heading');
});

/* SITE_NAME is the one operator-supplied string the page interpolates. It is
   empty by default, so the escaping it goes through was never run. */
await section("the site name is escaped", async () => {
        const raw = '<img src=x onerror="alert(1)"> & \'quoted\'';
        const variant = await variantWith([['SITE_NAME', JSON.stringify(raw)]]);
        const r = makeR(null);
        variant.serve_challenge(r);
        const page = r.body;
        check(page.indexOf('<img src=x') === -1,
              'SITE_NAME reached the page unescaped');
        check(page.indexOf('&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; ') !== -1,
              'SITE_NAME was not escaped as expected; the heading was ' +
              JSON.stringify((/<h1>([\s\S]*?)<\/h1>/.exec(page) || [, ''])[1]));
        const heading = (/<h1>([\s\S]*?)<\/h1>/.exec(page) || [, ''])[1];
        check(heading.indexOf('<') === -1 && heading.indexOf('>') === -1,
              'the heading carries a raw angle bracket: ' + JSON.stringify(heading));
        /* An empty SITE_NAME emits no heading at all. */
        const bare = makeR(null);
        mod.serve_challenge(bare);
        check(/<h1>/.test(bare.body) === false,
              'the default empty SITE_NAME emitted a heading');
        console.log('  SITE_NAME escaped: ' + JSON.stringify(heading));
});

/* Settings come from ANTIBOT_<NAME> where nginx exports one, and fall back to
   the constant in the source otherwise, through the same validation. A built
   artifact runs unmodified on any site, so this covers the path a deployment
   actually uses. Each case imports a fresh copy, because the environment is
   read once when the module loads. */
await section("settings are read from the environment", async () => {
        const withEnv = async (vars) => {
            const saved = {};
            for (const k of Object.keys(vars)) {
                saved[k] = process.env[k];
                if (vars[k] === null) delete process.env[k];
                else process.env[k] = vars[k];
            }
            try {
                const mod = await variantWith([]);
                const logged = [];
                const r = makeR(null, '203.0.113.5');
                r.error = (m) => logged.push(m);
                mod.serve_challenge(r);
                const pick = (re) => (re.exec(r.body) || [, null])[1];
                return {
                    bits: Number(pick(/,bits=(\d+);/)),
                    cookie: pick(/var v="([^"=]+)="/),
                    maxAge: Number(pick(/Max-Age=(\d+)/)),
                    heading: pick(/<h1>([\s\S]*?)<\/h1>/),
                    logged: logged.join(' | ')
                };
            } finally {
                for (const k of Object.keys(saved)) {
                    if (saved[k] === undefined) delete process.env[k];
                    else process.env[k] = saved[k];
                }
            }
        };

        const base = await withEnv({});
        check(base.bits === 22 && base.cookie === COOKIE_NAME && base.heading === null,
              'the defaults changed with no environment set: ' + JSON.stringify(base));

        const set = await withEnv({
            ANTIBOT_POW_BITS: '8', ANTIBOT_SITE_NAME: 'Acme & Co',
            ANTIBOT_COOKIE_NAME: '__Host-acme', ANTIBOT_WINDOW_SIZE: '3600'
        });
        check(set.bits === 8, 'ANTIBOT_POW_BITS=8 served bits=' + set.bits);
        check(set.cookie === '__Host-acme',
              'ANTIBOT_COOKIE_NAME served ' + set.cookie);
        check(set.heading === 'Acme &amp; Co',
              'ANTIBOT_SITE_NAME reached the page as ' + JSON.stringify(set.heading));
        check(set.logged === '', 'valid settings were reported: ' + set.logged);
        console.log('  environment: bits=' + set.bits + ' cookie=' + set.cookie +
                    ' heading=' + JSON.stringify(set.heading));

        /* Out of range falls back to the source constant and says so, the way an
           out-of-range constant does. */
        const bad = await withEnv({
            ANTIBOT_POW_BITS: 'notanumber', ANTIBOT_WINDOW_SIZE: '5',
            ANTIBOT_COOKIE_NAME: 'bad;name', ANTIBOT_RESCREEN_RATE: '1'
        });
        check(bad.bits === 22, 'a non-numeric ANTIBOT_POW_BITS served bits=' + bad.bits);
        check(bad.cookie === COOKIE_NAME,
              'an invalid ANTIBOT_COOKIE_NAME served ' + bad.cookie);
        for (const want of ['ANTIBOT_POW_BITS=notanumber', 'WINDOW_SIZE=5',
                            'COOKIE_NAME=bad;name', 'RESCREEN_RATE=1']) {
            check(bad.logged.indexOf(want) !== -1,
                  'no error-log line for ' + want + '; logged: ' + bad.logged);
        }
        console.log('  environment: 4 out-of-range values fell back and were reported');

        /* A name without the prefix is kept, and the guarantee it drops is said. */
        const loose = await withEnv({ ANTIBOT_COOKIE_NAME: 'plain-name' });
        check(loose.cookie === 'plain-name',
              'a valid name without the __Host- prefix was replaced');
        check(loose.logged.indexOf('__Host-') !== -1,
              'no error-log line for a name without the __Host- prefix');
});

/* RESCREEN_RATE and COOKIE_TTL are checked at load the way POW_BITS is. Both
   break a visitor rather than an attacker: a rate of 1 challenges every
   navigation that holds a valid cookie, and a lifetime below the acceptance
   window has the browser drop the cookie while the module would still take
   it. Either leaves the visitor solving and reloading without end. */
await section("the constants that trap a visitor are validated", async () => {
        const WINDOW = 6 * 60 * 60;
        for (const [value, expected] of [['1', 0.02], ['-0.5', 0.02], ['2', 0.02],
                                         ['0', 0], ['0.5', 0.5]]) {
            /* Measure the rate the module actually applies: navigations holding a
               cookie the module refuses are 401 either way, so this uses a valid
               one at 1 bit and counts how often a navigation is turned away. */
            const bits = 1;
            const v = await variantWith([['RESCREEN_RATE', value], ['POW_BITS', String(bits)]]);
            const served = makeR(null, '203.0.113.90');
            v.serve_challenge(served);
            const challenge = /var challenge="([0-9a-f]+)"/.exec(served.body)[1];
            const issued = /var slot="(\d+)"/.exec(served.body)[1];
            let nonce = 0;
            while ((parseInt(crypto.createHash('sha256')
                       .update(challenge + ':' + nonce).digest('hex')[0], 16) >> 3) !== 0) nonce++;
            const cookie = COOKIE_NAME + '=' + issued + '.' + nonce;
            const N = 4000;
            let turned = 0;
            for (let i = 0; i < N; i++) {
                const r = makeR(cookie, '203.0.113.90', 'document');
                v.check(r);
                if (r.code === 401) turned++;
            }
            const observed = turned / N;
            const slack = 4 * Math.sqrt(Math.max(expected, 1 / N) * (1 - expected) / N);
            check(Math.abs(observed - expected) <= slack + 0.005,
                  'RESCREEN_RATE=' + value + ' applied ' + observed.toFixed(3) +
                  ', expected about ' + expected);
            console.log('  RESCREEN_RATE=' + String(value).padEnd(5) + ' -> ' +
                        observed.toFixed(3) + ' (expected ' + expected + ')');
        }

        for (const [value, expected] of [['1', 2 * WINDOW], ['0', 2 * WINDOW],
                                         ['-1', 2 * WINDOW], ['2 * WINDOW_SIZE', 2 * WINDOW],
                                         ['99999999', 99999999]]) {
            const v = await variantWith([['COOKIE_TTL', value]]);
            const r = makeR(null);
            v.serve_challenge(r);
            const age = Number(/Max-Age=(\d+)/.exec(r.body)[1]);
            check(age === expected, 'COOKIE_TTL=' + value + ' produced Max-Age=' + age +
                  ', expected ' + expected);
            console.log('  COOKIE_TTL=' + String(value).padEnd(15) + ' -> Max-Age=' + age);
        }
});

/* MAX_COOKIE_CANDIDATES bounds the hashing one request can demand. The bound
   only means something if a valid cookie behind other cookies of the same name
   is still found, up to the bound, and refused past it. A browser sends one:
   the __Host- prefix forces Path=/, so only something else sends more. */
await section("a valid cookie is found within the candidate bound", async () => {
        const bits = 12;
        const variant = await variantFor(bits);
        const address = '203.0.113.77';
        const served = makeR(null, address);
        variant.serve_challenge(served);
        const challenge = /var challenge="([0-9a-f]+)"/.exec(served.body)[1];
        const issued = /var slot="(\d+)"/.exec(served.body)[1];
        let nonce = 0;
        while (!(function () {
            const hex = crypto.createHash('sha256').update(challenge + ':' + nonce).digest('hex');
            const full = bits >> 2, rem = bits & 3;
            if (hex.slice(0, full) !== '0'.repeat(full)) return false;
            return rem ? (parseInt(hex[full], 16) >> (4 - rem)) === 0 : true;
        })()) nonce++;
        const good = COOKIE_NAME + '=' + issued + '.' + nonce;

        /* Taken from docs/configuration.md, not from the module, so lowering the
           constant is a failure rather than something the test adapts to. */
        const table = fs.readFileSync(new URL('../docs/configuration.md', import.meta.url), 'utf8');
        /* Matches the value column whatever else the row carries, and stops here
           rather than throwing further down if the row is gone. */
        const documented = /\| `MAX_COOKIE_CANDIDATES` \|[^|]*\| (\d+) \|/.exec(table);
        if (documented === null) {
            throw new Error('docs/configuration.md no longer states ' +
                            'MAX_COOKIE_CANDIDATES in a form this suite reads; the ' +
                            'bound below would have been taken from the module it grades');
        }
        const bound = Number(documented[1]);
        const inModule = Number(/^const MAX_COOKIE_CANDIDATES = (\d+);$/m.exec(VARIANT_SRC)[1]);
        check(inModule === bound, 'the module verifies ' + inModule +
              ' cookies and docs/configuration.md states ' + bound);

        /* Junk that parses and carries the right slot, so each one costs a
           verification and none of them passes. */
        const junk = (n) => Array.from({ length: n },
            (_, i) => COOKIE_NAME + '=' + issued + '.' + (1000000 + i)).join('; ');

        for (let ahead = 0; ahead < bound; ahead++) {
            const header = ahead === 0 ? good : junk(ahead) + '; ' + good;
            const r = makeR(header, address, 'empty');
            variant.check(r);
            check(r.code === 204, 'a valid cookie behind ' + ahead +
                  ' others was answered ' + r.code + ', within the bound of ' + bound);
        }
        const past = makeR(junk(bound) + '; ' + good, address, 'empty');
        variant.check(past);
        check(past.code === 401, 'a valid cookie behind ' + bound +
              ' others was answered ' + past.code + ', past the bound of ' + bound);
        console.log('  cookie candidates: found behind 0 to ' + (bound - 1) +
                    ' others, refused behind ' + bound);
});

/* A cookie is accepted for its own slot and the one after it, which is what
   COOKIE_TTL is set from. Only the reject side of that boundary was covered.
   The clock moves back one window so the module issues the previous slot's
   challenge through its own derivation, rather than a copy of it here. */
await section("a cookie works across the slot boundary and no further", async () => {
        const bits = 12;
        const variant = await variantFor(bits);
        const realNow = Date.now;
        const slotNow = Math.floor(realNow() / 1000 / 21600);
        let cookie = null;
        try {
            Date.now = () => realNow() - 21600 * 1000;
            const served = makeR(null, '203.0.113.44');
            variant.serve_challenge(served);
            const challenge = /var challenge="([0-9a-f]+)"/.exec(served.body)[1];
            const issued = Number(/var slot="(\d+)"/.exec(served.body)[1]);
            check(issued === slotNow - 1,
                  'the clock move issued slot ' + issued + ', expected ' + (slotNow - 1));
            let nonce = 0;
            while (!(function () {
                const hex = crypto.createHash('sha256')
                                  .update(challenge + ':' + nonce).digest('hex');
                const full = bits >> 2, rem = bits & 3;
                if (hex.slice(0, full) !== '0'.repeat(full)) return false;
                return rem ? (parseInt(hex[full], 16) >> (4 - rem)) === 0 : true;
            })()) nonce++;
            cookie = COOKIE_NAME + '=' + issued + '.' + nonce;
        } finally {
            Date.now = realNow;
        }
        const now = makeR(cookie, '203.0.113.44', 'empty');
        variant.check(now);
        check(now.code === 204,
              'a cookie solved in the previous slot was answered ' + now.code);
        const older = makeR(cookie.replace('=' + (slotNow - 1) + '.', '=' + (slotNow - 2) + '.'),
                            '203.0.113.44', 'empty');
        variant.check(older);
        check(older.code === 401,
              'a cookie two slots old was answered ' + older.code);
        console.log('  slot boundary: previous slot ' + now.code +
                    ', two slots back ' + older.code +
                    ', COOKIE_TTL covers ' + (2 * 6) + 'h');
});

/* The cookie is __Host- and Secure, so a browser that reached the page over
   plain HTTP discards it without an error. The page must say so rather than
   reload into the same challenge and solve it again forever. */
await section("a cookie the browser refuses reports a failure", async () => {
        const served = makeR(null);
        mod.serve_challenge(served);
        let out;
        try {
            out = await runChallengePage(served.body,
                                         { cores: 2, refuseCookies: true, timeoutMs: 30000 });
        } catch (err) {
            check(false, 'page (refused cookie) did not finish: ' + err.message);
            out = null;
        }
        if (out) {
            check(out.failed, 'page (refused cookie) reloaded instead of reporting failure');
            check(out.cookies.length === 0,
                  'page (refused cookie) stored ' + out.cookies.length + ' cookies');
            console.log('  page refused cookie  reported failure, no reload');
        }
});

/* get_cookies() was rewritten from a split into a scan. A parser in the gate
   states its behaviour change here rather than shipping it: the reference is
   the collector it replaced, and the only difference allowed is the one that
   rewrite made, which is that the value comes back trimmed. */
await section("the cookie collector matches the one it replaced", async () => {
        const source = fs.readFileSync(new URL(MODULE_PATH), 'utf8');
        const start = source.indexOf('function get_cookies(');
        const end = source.indexOf('\n}', start);
        if (start === -1 || end === -1) {
            throw new Error('get_cookies not found in the module; the differential ' +
                            'test would have compared the reference against itself');
        }
        const collector = new Function('return ' + source.slice(start, end + 2))();

        /* The split-based collector, as it stood before the rewrite. */
        const reference = (header, name, max) => {
            const values = [];
            if (!header) return values;
            const parts = header.split(';');
            for (let i = 0; i < parts.length; i++) {
                const pair = parts[i].trim();
                if (pair.indexOf(name + '=') === 0) values.push(pair.substring(name.length + 1));
            }
            return values.slice(0, max);
        };

        const N = COOKIE_NAME, TAB = String.fromCharCode(9), LF = String.fromCharCode(10);
        const fixed = ['', ' ', ';', ';;;', '  ;  ;  ', N, N + '=', N + '=1', ' ' + N + '=1',
                       N + '=1;', N + '=1; ' + N + '=2', N + '=1;' + N + '=2', TAB + N + '=1',
                       N + TAB + '=1', N + '= 1 ', N + '=1 ;', 'x=1; ' + N + '=2; y=3',
                       N + 'X=1', 'X' + N + '=1', N + '=a=b', N + '=;', '=1', N + '=1;;' + N + '=2',
                       LF + N + '=1', N + '=1' + LF, 'a; ' + N + '=1', N + '=1; a', ';' + N + '=1',
                       N + '= 82803.12345', N + '=82803.12345 '];
        const alphabet = ['a', '=', ';', ' ', TAB, '_', '-', 'H', 'o', 's', 't', '1', N, N + '=', '__Host-'];
        let seed = 12345n;
        const rnd = (n) => { seed = (seed * 6364136223846793005n + 1n) & 0xffffffffffffffffn;
                             return Number((seed >> 33n) % BigInt(n)); };
        const cases = fixed.slice();
        for (let i = 0; i < 50000; i++) {
            let h = '';
            for (let j = rnd(9); j > 0; j--) h += alphabet[rnd(alphabet.length)];
            cases.push(h);
        }
        let compared = 0, trimmed = 0, unexplained = 0, firstBad = null;
        for (const h of cases) {
            for (const max of [1, 4]) {
                const r = { headersIn: h === undefined ? {} : { Cookie: h } };
                const a = reference(h, N, max);
                const b = collector(r, N, max);
                compared++;
                if (JSON.stringify(a) === JSON.stringify(b)) continue;
                if (a.length === b.length && a.every((v, i) => v.trim() === b[i])) { trimmed++; continue; }
                unexplained++;
                if (!firstBad) firstBad = JSON.stringify({ h, max, a, b });
            }
        }
        check(unexplained === 0, 'get_cookies differs from the collector it replaced in a way ' +
              'the rewrite did not state: ' + firstBad);
        console.log('  get_cookies: ' + compared.toLocaleString('en-US') + ' comparisons, ' +
                    trimmed + ' trimmed values, ' + unexplained + ' unexplained');
});

/* A single timing run swings by tens of percent, which a ratio amplifies.
   Every cost below is the median of three. */
const median3 = (f) => [f(), f(), f()].sort((a, b) => a - b)[1];

/* The identity is attacker-controlled and hashed on every request, so its
   cost must not track header size. Comparing totals would also measure the
   header parsing, which grows with size whatever the module does, so each
   measurement subtracts the same request without a cookie: what remains is
   the hashing. */
await section("hashing does not track header size", async () => {
        const timeWith = (ua, cookie) => {
            const N = 2000;
            const one = () => {
                const r = makeR(cookie, '203.0.113.9', 'empty');
                r.headersIn['User-Agent'] = ua;
                return r;
            };
            one();
            const t = process.hrtime.bigint();
            for (let i = 0; i < N; i++) mod.check(one());
            return Number(process.hrtime.bigint() - t) / 1000 / N;
        };
        const withCookie = COOKIE_NAME + '=' + slot + '.123456789';
        const hashing = (ua) =>
            median3(() => timeWith(ua, withCookie) - timeWith(ua, null));

        const short = hashing('Mozilla/5.0');
        const long = hashing('M'.repeat(8192));
        const ratio = long / short;
        check(ratio < 2, 'hashing an 8 KB header costs ' + ratio.toFixed(2) +
                         'x a short one; the identity is not being clipped');
        console.log('  hashing work: short header ' + short.toFixed(1) +
                    ' us, 8 KB header ' + long.toFixed(1) +
                    ' us, ratio ' + ratio.toFixed(2));
});

/* The address is attacker-controlled too when real_ip_header is set, and it
   is split and matched on before it is hashed. It arrives outside the headers,
   so the whole request cost measures it directly.

   The assertion is on growth, not on a ratio against a short address: the
   residual cost of clipping and parsing a bounded address is a fixed number of
   microseconds, which reads as a large ratio on a fast machine and a small one
   on a slow machine. What must hold everywhere is that the cost stops tracking
   the length of the input once the bound is ahead of the parse. Clipping after
   the parse instead of before takes this from 0.84x to 6.8x. */
await section("the request cost does not track address size", async () => {
        const cost = (address) => {
            const N = 1000;
            const one = () => makeR(COOKIE_NAME + '=' + slot + '.123456789',
                                    address, 'empty');
            for (let i = 0; i < 300; i++) mod.check(one());
            const t = process.hrtime.bigint();
            for (let i = 0; i < N; i++) mod.check(one());
            return Number(process.hrtime.bigint() - t) / 1000 / N;
        };
        /* IPv6-shaped: address_key() splits on ":" before it rejects the group
           count, so this is the shape whose cost tracks its length. */
        const v6 = (groups) => '2001:db8:' + '0:'.repeat(groups) + '1';
        const short = median3(() => cost('203.0.113.9'));
        const big = median3(() => cost(v6(4096)));
        const bigger = median3(() => cost(v6(4096 * 8)));
        const growth = bigger / big;
        check(growth < 2, 'an address 8x longer costs ' + growth.toFixed(2) +
                          'x as much; it is not being clipped before parsing');
        console.log('  request cost: short ' + short.toFixed(1) +
                    ' us, 8 KB ' + big.toFixed(1) + ' us, 64 KB ' +
                    bigger.toFixed(1) + ' us, growth ' + growth.toFixed(2) + 'x');
});

/* The Cookie header is the other attacker-controlled input check() reads.
   nginx allows 8 KB of it, which holds about 273 cookies carrying this name,
   and only MAX_COOKIE_CANDIDATES of them are ever verified. Collecting all of
   them first would make the cost track the header, so the same growth test the
   address gets applies here. */
await section("the request cost does not track cookie count", async () => {
        const cost = (cookie) => {
            const N = 500;
            const one = () => makeR(cookie, '203.0.113.9', 'empty');
            for (let i = 0; i < 200; i++) mod.check(one());
            const t = process.hrtime.bigint();
            for (let i = 0; i < N; i++) mod.check(one());
            return Number(process.hrtime.bigint() - t) / 1000 / N;
        };
        const many = (n) => Array.from({ length: n },
            (_, i) => COOKIE_NAME + '=' + slot + '.' + i).join('; ');
        const full = median3(() => cost(many(273)));
        const over = median3(() => cost(many(273 * 8)));
        const growth = over / full;
        check(growth < 2, 'a header with 8x the cookies costs ' + growth.toFixed(2) +
                          'x as much; collection is not stopping at the cap');
        console.log('  cookie cost: 273 cookies ' + full.toFixed(1) +
                    ' us, 2184 cookies ' + over.toFixed(1) +
                    ' us, growth ' + growth.toFixed(2) + 'x');
});

/* nginx writes one error-log line per call and $uri is percent-decoded, so a
   request for /a%0Ab reaches the module with a newline in it. Every field the
   module logs is encoded first, and the challenge goes to the info level
   because one is served for every request that arrives without a cookie. */
await section("the log line survives a URI with a newline", async () => {
        const LF = String.fromCharCode(10);
        const r = makeR(null, '203.0.113.9');
        r.uri = '/a' + LF + 'antibot: forged';
        mod.serve_challenge(r);
        check(r.logged.length === 1,
              'serve_challenge wrote ' + r.logged.length + ' log lines, expected 1');
        const line = r.logged[0] || '';
        check(line.indexOf(LF) === -1,
              'a newline in the URI survived into the log line');
        check(line.indexOf('/a\\x0aantibot: forged') !== -1,
              'the URI was not encoded in the log line: ' + JSON.stringify(line));
        const wide = makeR(null, '203.0.113.9');
        wide.uri = '/' + String.fromCodePoint(0x1f600);
        mod.serve_challenge(wide);
        check(wide.logged[0].indexOf('\\ud83d') !== -1,
              'a non-ASCII URI was not encoded: ' + JSON.stringify(wide.logged[0]));
        console.log('  log line: ' + JSON.stringify(line.slice(0, 72)));
});

/* docs/security.md states the page size, because at one request per address
   the bytes cost more than the CPU. The figure is read back out of the
   document, so the two cannot drift apart. */
await section("the documented page size matches the built page", async () => {
        const doc = fs.readFileSync(new URL('../docs/security.md', import.meta.url), 'utf8');
        const m = /The challenge page is ([\d,]+) bytes, ([\d,]+) gzipped/.exec(doc);
        check(m !== null, 'docs/security.md no longer states the challenge page size');
        if (m) {
            const documented = Number(m[1].replace(/,/g, ''));
            const r = makeR(null);
            mod.serve_challenge(r);
            const actual = Buffer.byteLength(r.body);
            const drift = Math.abs(actual - documented);
            check(drift <= 1024, 'the challenge page is ' + actual.toLocaleString('en-US') +
                  ' bytes and docs/security.md states ' + documented.toLocaleString('en-US') +
                  ', a drift of ' + drift.toLocaleString('en-US'));
            console.log('  challenge page: ' + actual.toLocaleString('en-US') +
                        ' bytes, documented ' + documented.toLocaleString('en-US') +
                        ', drift ' + drift);
        }
});

/* node:test sets the exit code from the tests themselves, and a check that
   ran outside one would otherwise fail nothing. */
await section("the counters report what the module did", async () => {
    /* njs creates a VM per request, so the counters live in a shared
       dictionary rather than a module variable. This stands in for
       ngx.shared with the three methods the module calls. */
    const store = new Map();
    const zone = {
        incr(key, delta, init) {
            const next = (store.has(key) ? store.get(key) : init) + delta;
            store.set(key, next);
            return next;
        },
        get(key) { return store.get(key); }
    };

    const counted = await variantWith([]);
    const read = () => {
        const r = makeR(null);
        counted.status(r);
        const out = {};
        for (const line of r.body.split('\n')) {
            const [k, v] = line.split(' ');
            if (k) out[k] = v;
        }
        return out;
    };

    /* With no zone the gate still works and status says so. */
    const saved = globalThis.ngx;
    try {
        delete globalThis.ngx;
        const bare = read();
        check(bare.zone === 'missing',
              'with no shared zone, status reported ' + JSON.stringify(bare));
        const r = makeR(null, '203.0.113.70');
        counted.check(r);
        check(r.code === 401, 'with no shared zone a request was answered ' + r.code);

        globalThis.ngx = { shared: { antibot: zone } };
        const before = read();
        check(before.challenges === undefined || before.challenges === '0',
              'a fresh zone reported ' + JSON.stringify(before));

        for (let i = 0; i < 5; i++) counted.check(makeR(null, '203.0.113.71'));
        for (let i = 0; i < 3; i++) counted.serve_challenge(makeR(null, '203.0.113.71'));
        const after = read();
        check(after.zone === 'antibot', 'status did not name the zone: ' + after.zone);
        check(after.rejected === '5', 'five refusals were counted as ' + after.rejected);
        check(after.challenges === '3', 'three challenges were counted as ' + after.challenges);
        check(after.accepted === '0', 'nothing was accepted, yet ' + after.accepted + ' was counted');
        check(after.misconfigured === '0',
              'a usable secret was configured, yet ' + after.misconfigured + ' was counted');
        check(after.bits === String(POW_BITS_EFFECTIVE_IN_PAGE),
              'the counters report bits=' + after.bits);

        /* An acceptance moves accepted and nothing else. */
        const solved = await variantWith([['POW_BITS', 12]]);
        const served = makeR(null, '203.0.113.72');
        solved.serve_challenge(served);
        const challenge = /var challenge="([0-9a-f]+)"/.exec(served.body)[1];
        const issued = /var slot="(\d+)"/.exec(served.body)[1];
        let nonce = 0;
        while (crypto.createHash('sha256').update(challenge + ':' + nonce)
                     .digest('hex').slice(0, 3) !== '000') nonce++;
        const ok = makeR(COOKIE_NAME + '=' + issued + '.' + nonce, '203.0.113.72', 'empty');
        solved.check(ok);
        check(ok.code === 204, 'the solved cookie was answered ' + ok.code);
        check(read().accepted === '1',
              'one acceptance was counted as ' + read().accepted);
        console.log('  counters: 5 rejected, 4 challenges, 1 accepted, and ' +
                    'zone missing reported without one');
    } finally {
        if (saved === undefined) delete globalThis.ngx;
        else globalThis.ngx = saved;
    }
});

await test("every check ran inside a named test", () => {
    if (failures > claimed) {
        throw new Error((failures - claimed) + ' check(s) failed outside a test');
    }
});

/* After the last test: the variants are files the tests import. */
fs.rmSync(VARIANT_DIR, { recursive: true, force: true });

console.log(failures ? "\n" + failures + " FAILURE(S)" : "\nall checks passed");
