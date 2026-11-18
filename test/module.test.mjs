/*
 * End-to-end suite for the antibot njs module.
 *
 *   ANTIBOT_SECRET=$(openssl rand -hex 32) node test/module.test.mjs [path/to/antibot.js]
 *
 * serve_challenge() emits the page, the emitted worker source runs in real OS
 * threads, and the resulting cookie is fed back to check(). Both solver paths
 * are exercised: the SIMD wasm module, and the embedded pure-JS solver that
 * takes over when no module is supplied, which is what happens on an engine
 * that cannot compile the SIMD build.
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

const makeR = (cookie, ip = "203.0.113.7") => ({
    remoteAddress: ip, uri: "/__antibot_challenge",
    variables: { request_uri: "/tests" }, args: {},
    headersIn: { "User-Agent": "Mozilla/5.0", "Accept-Language": "en-US",
                 ...(cookie ? { Cookie: cookie } : {}) },
    headersOut: {}, error() {}, warn() {},
    logged: [], log(msg) { this.logged.push(msg); },
    return(code, body) { this.code = code; this.body = body; }
});

const r0 = makeR(null);
mod.serve_challenge(r0);
check(r0.code === 200, "serve_challenge did not return 200");
const page = r0.body;

/* Reads one value out of a challenge page: the one built at load through
   fromPage, or one a variant served, through fromBody. A pattern that stops
   matching means the page changed shape, and saying so beats a TypeError from
   indexing null, which is what the rest of the run would otherwise report. */
const fromBody = (body, what, re) => {
    const m = re.exec(body);
    if (m === null) {
        throw new Error('the challenge page no longer carries ' + what +
                        ' where this suite reads it (' + re + '), so every ' +
                        'assertion below would grade the wrong thing');
    }
    return m[1];
};
const fromPage = (what, re) => fromBody(page, what, re);
const challenge = fromPage('the challenge', /var challenge="([0-9a-f]+)"/);
const bits      = Number(fromPage('the difficulty', /,bits=(\d+);/));
const slot      = fromPage('the slot', /var slot="(\d+)"/);
const cap       = Number(fromPage('the iteration cap', /,cap=(\d+);/));
const src       = JSON.parse(fromPage('the worker source', /var src=("(?:[^"\\]|\\.)*");/));
const simdB64   = JSON.parse(fromPage('the wasm payload', /var simd=("(?:[^"\\]|\\.)*");/));
const dec = (s) => new Uint8Array(Buffer.from(s, 'base64'));
/* Read the cookie name out of the emitted page so renaming COOKIE_NAME in the
   module does not silently turn every assertion below into a no-op. The page
   names it once, where it builds the value it later writes and reads back. */
const POW_BITS_EFFECTIVE_IN_PAGE = bits;
const COOKIE_NAME = fromPage('the cookie name', /var v="([^"=]+)="\+slot/);

console.log(MODULE_PATH.replace(/^.*\//, ''));
console.log("  challenge page: " + page.length + " bytes, bits=" + bits +
            ", cap=" + cap.toLocaleString("en-US"));

/* The emitted page script and worker script must both parse. */
const inner = fromPage('an inline script', /<script>\n([\s\S]*?)<\/script>/);
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

            const rc = makeR(COOKIE_NAME + "=" + slot + "." + nonce, "203.0.113.7");
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
await section("a request without a valid cookie is refused", async () => {
    for (const [label, r] of cases) {
        mod.check(r);
        check(r.code === 401, label + " was not rejected (got " + r.code + ")");
        console.log("  reject " + label.padEnd(15) + " -> " + r.code);
    }
});

/* The accept path is deterministic: a valid cookie is answered 204 on every
   request, whatever the request is for. */
const cookie = COOKIE_NAME + "=" + slot + "." + good;
await section("a valid cookie is accepted on every request", async () => {
    let strays = 0;
    for (let i = 0; i < 2000; i++) {
        const r = makeR(cookie);
        mod.check(r);
        if (r.code !== 204) strays++;
    }
    check(strays === 0, "a valid cookie was refused " + strays + " times in 2000 requests");
    console.log("  valid cookie, 2000 requests -> " + (2000 - strays) + " accepted");
});

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
const POW_BITS_LINE = /^const POW_BITS = [^;]+;$/m;
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

        /* An invalid constant falls back to the built-in 22, and one past
           POW_BITS_MAX is clamped to it, so no value yields a difficulty the
           page cannot solve or one that verifies nothing. */
        for (const [bits, want] of [[0, 22], [-1, 22], ['22.5', 22], [1, 1], [22, 22],
                                    [32, 32], [33, 32], [99, 32]]) {
            const variant = await variantFor(bits);
            const r = makeR(null);
            variant.serve_challenge(r);
            const effective = Number(/,bits=(\d+);/.exec(r.body)[1]);
            check(effective === want, 'POW_BITS=' + bits + ' yields difficulty ' +
                  effective + ', expected ' + want);
            console.log('  POW_BITS=' + String(bits).padEnd(4) + ' -> difficulty ' + effective);
        }

        /* At 24 bits a guess passes with probability 2^-24. The cap at 24 bits
           is 2^24 x 64 = 2^30, so the largest nonce tried sits just under it
           and reaches pow_valid() rather than stopping at the parser. */
        const strict = await variantFor(24);
        const slotNow = Math.floor(Date.now() / 1000 / 21600);
        let accepted = 0;
        for (const n of ['0', '1', '999999', String(Math.pow(2, 30) - 1)]) {
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
            /* One IPv4 client per address: translation and Teredo. */
            ['64:ff9b::c000:201',    '64:ff9b::c633:6407'],
            ['64:ff9b:1::c000:201',  '64:ff9b:1::c633:6407'],
            ['2001:0:4136:e378:8000:63bf:3fff:fdd2',
             '2001:0:4136:e378:8000:63bf:f3ff:fdd1'],
        ];
        const strictVariant = await variantFor(24);
        for (const [one, two] of distinct) {
            const a1 = challengeFor(strictVariant, one);
            const b1 = challengeFor(strictVariant, two);
            check(a1 !== b1, one + ' and ' + two + ' share an identity');
            console.log('  ' + one.padEnd(24) + ' vs ' + two.padEnd(22) +
                        (a1 !== b1 ? ' distinct' : ' SHARED'));
        }
        /* The spellings of one IPv4 client must agree. */
        for (const spelling of ['::ffff:192.0.2.1', '64:ff9b::c000:201',
                                '64:FF9B:0:0:0:0:C000:0201']) {
            check(challengeFor(strictVariant, '192.0.2.1') ===
                  challengeFor(strictVariant, spelling),
                  '192.0.2.1 and ' + spelling + ' were given different identities');
        }
        console.log('  192.0.2.1, ::ffff:192.0.2.1 and 64:ff9b::c000:201 agree');

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
        const mine = makeR(cookie, own);
        replay.check(mine);
        const theirs = makeR(cookie, other);
        replay.check(theirs);
        check(mine.code === 204, 'own cookie rejected (' + mine.code + ')');
        check(theirs.code === 401, 'cookie accepted for another address');
        console.log('  replay at 20 bits: own ' + mine.code + ', other ' + theirs.code);
});

/* The difficulty the page ships is advisory: check() verifies with
   POW_BITS_EFFECTIVE, and a cookie carries a slot and a nonce with no field
   for a difficulty, so a tampered page, a patched worker or a hand-written
   client cannot choose the bar it is judged against. Solving below the
   server's difficulty is refused. Solving above it is accepted, because a
   digest with more leading zero bits has the ones asked for. */
await section("the difficulty the page ships does not decide acceptance", async () => {
    const SERVER_BITS = 16;
    /* variantFor rewrites the constant, which env_number overrides. Without
       this, running the suite with ANTIBOT_POW_BITS set fails the check below
       rather than grading the difficulty. */
    const savedBits = process.env.ANTIBOT_POW_BITS;
    delete process.env.ANTIBOT_POW_BITS;
    const server = await variantFor(SERVER_BITS);
    if (savedBits === undefined) delete process.env.ANTIBOT_POW_BITS;
    else process.env.ANTIBOT_POW_BITS = savedBits;

    const issued = makeR(null);
    server.serve_challenge(issued);
    const target = fromBody(issued.body, 'the challenge', /var challenge="([0-9a-f]+)"/);
    const issuedSlot = fromBody(issued.body, 'the slot', /var slot="(\d+)"/);
    const shipped = Number(fromBody(issued.body, 'the difficulty', /,bits=(\d+);/));
    check(shipped === SERVER_BITS,
          'the variant ships ' + shipped + ' bits, not ' + SERVER_BITS);

    const meets = (nonce, want) => {
        const d = crypto.createHash('sha256').update(target + ':' + nonce).digest();
        return (d.readUInt32BE(0) >>> (32 - want)) === 0;
    };
    /* `refuse` is what makes the cases below SERVER_BITS test what they claim.
       The first nonce meeting `want` also meets SERVER_BITS once in
       2^(SERVER_BITS - want) challenges, and that nonce would be accepted for
       the right reason, reporting a pass that proves nothing. */
    const solve = (want, refuse) => {
        for (let n = 0; n < 5e7; n++) {
            if (meets(n, want) && !(refuse && meets(n, SERVER_BITS))) return n;
        }
        return -1;
    };

    /* The cases above SERVER_BITS stop at SERVER_BITS + 2. The variant's
       POW_MAX_ITERATIONS is 64 times its own expected work, so a solve at
       SERVER_BITS + 2 runs past it with probability e^-16; further up, the cap
       and not the difficulty would be what refused the cookie. */
    const CASES = [10, 12, 14, SERVER_BITS, SERVER_BITS + 1, SERVER_BITS + 2];
    let ran = 0;
    for (const want of CASES) {
        const below = want < SERVER_BITS;
        const nonce = solve(want, below);
        if (!check(nonce >= 0, 'no nonce found at ' + want + ' bits')) { continue; }
        const r = makeR(COOKIE_NAME + '=' + issuedSlot + '.' + nonce,
                        '203.0.113.7');
        server.check(r);
        const wanted = below ? 401 : 204;
        check(r.code === wanted,
              'client at ' + want + ' bits, server at ' + SERVER_BITS + ' bits: ' +
              r.code + ', expected ' + wanted);
        ran++;
        console.log('  client ' + String(want).padStart(2) + ' bits, server ' +
                    SERVER_BITS + ' bits -> ' + r.code +
                    (below ? '  refused' : '  accepted'));
    }
    /* A run that solved nothing would report six passes and no coverage. */
    check(ran === CASES.length,
          'only ' + ran + ' of ' + CASES.length + ' difficulty cases ran');
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

        const back = makeR(value, '203.0.113.7');
        mod.check(back);
        check(back.code === 204,
              'page (' + label + ') cookie rejected by check() (' + back.code + ')');

        /* After the cookie, the page sends the solver that won and its rate
           to the report location, which report() accepts. */
        check(out.beacons.length === 1,
              'page (' + label + ') sent ' + out.beacons.length + ' reports');
        const sent = new URL(out.beacons[0] || '/', 'https://site.example');
        const solver = options.withWebAssembly === false ? 'js' : 'wasm';
        check(sent.pathname === '/__antibot_report',
              'page (' + label + ') reported to ' + sent.pathname);
        check(sent.searchParams.get('solver') === solver,
              'page (' + label + ') reported solver=' + sent.searchParams.get('solver') +
              ', expected ' + solver);
        check(/^[1-9][0-9]*$/.test(sent.searchParams.get('rate') || ''),
              'page (' + label + ') reported rate=' + sent.searchParams.get('rate'));
        const rep = makeR(value, '203.0.113.7');
        rep.args = Object.fromEntries(sent.searchParams);
        mod.report(rep);
        check(rep.code === 204, 'page (' + label + ') report was answered ' + rep.code);
        console.log('  page ' + label.padEnd(15) + ' ' + secs + 's, ' + out.workers +
                    ' worker(s), progress ' + JSON.stringify(out.progress) +
                    ', check() ' + back.code + ', reported ' + sent.search);
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
            ANTIBOT_COOKIE_NAME: 'bad;name'
        });
        check(bad.bits === 22, 'a non-numeric ANTIBOT_POW_BITS served bits=' + bad.bits);
        check(bad.cookie === COOKIE_NAME,
              'an invalid ANTIBOT_COOKIE_NAME served ' + bad.cookie);
        for (const want of ['ANTIBOT_POW_BITS=notanumber', 'ANTIBOT_WINDOW_SIZE=5',
                            'ANTIBOT_COOKIE_NAME=bad;name']) {
            check(bad.logged.indexOf(want) !== -1,
                  'no error-log line for ' + want + '; logged: ' + bad.logged);
        }
        console.log('  environment: 3 out-of-range values fell back and were reported');

        /* A number is decimal digits and nothing else. Number() reads
           whitespace as 0 and accepts hexadecimal, an exponent and a fraction,
           and each of those once set the difficulty to 16, or to 24 unreported. */
        let parsed = 0;
        for (const value of ['0', '-24', '22.5', ' ', '\t', '0x18', '1e1', '+8', '8 ']) {
            const got = await withEnv({ ANTIBOT_POW_BITS: value });
            check(got.bits === 22, 'ANTIBOT_POW_BITS=' + JSON.stringify(value) +
                  ' served bits=' + got.bits + ', expected the default 22');
            check(got.logged.indexOf('ANTIBOT_POW_BITS=' + value + ' is not') !== -1,
                  'ANTIBOT_POW_BITS=' + JSON.stringify(value) + ' was not reported: ' +
                  got.logged);
            parsed++;
        }
        check(parsed === 9, 'only ' + parsed + ' of 9 malformed difficulties ran');
        console.log('  environment: 9 malformed difficulties fell back to 22 and were reported');

        /* A lifetime is reported for the rule it breaks. */
        const frac = await withEnv({ ANTIBOT_COOKIE_TTL: '50000.5' });
        check(frac.maxAge === 43200, 'ANTIBOT_COOKIE_TTL=50000.5 served Max-Age=' + frac.maxAge);
        check(frac.logged.indexOf('ANTIBOT_COOKIE_TTL=50000.5 is not a whole number') !== -1,
              'a fractional lifetime was reported as ' + JSON.stringify(frac.logged));
        const huge = await withEnv({ ANTIBOT_COOKIE_TTL: '1e21' });
        check(huge.maxAge === 43200 && huge.logged.indexOf('ANTIBOT_COOKIE_TTL=1e21 is not') !== -1,
              'ANTIBOT_COOKIE_TTL=1e21 served Max-Age=' + huge.maxAge + ' and logged ' +
              JSON.stringify(huge.logged));
        const short = await withEnv({ ANTIBOT_COOKIE_TTL: '600' });
        check(short.logged.indexOf('ANTIBOT_COOKIE_TTL=600 is below twice WINDOW_SIZE=43200') !== -1,
              'a short lifetime was reported as ' + JSON.stringify(short.logged));

        /* The lifetime follows the window it is derived from, and a longer
           window alone is a valid configuration that reports nothing. */
        const day = await withEnv({ ANTIBOT_WINDOW_SIZE: '86400' });
        check(day.maxAge === 172800, 'ANTIBOT_WINDOW_SIZE=86400 served Max-Age=' + day.maxAge);
        check(day.logged === '', 'ANTIBOT_WINDOW_SIZE=86400 alone reported: ' + day.logged);
        console.log('  environment: lifetimes reported by rule; a 1-day window gives Max-Age=' +
                    day.maxAge + ' and no report');

        /* A name without the prefix is kept, and the guarantee it drops is said. */
        const loose = await withEnv({ ANTIBOT_COOKIE_NAME: 'plain-name' });
        check(loose.cookie === 'plain-name',
              'a valid name without the __Host- prefix was replaced');
        check(loose.logged.indexOf('__Host-') !== -1,
              'no error-log line for a name without the __Host- prefix');
});

/* One line is written per challenge, so which level it lands at decides
   whether a deployment can read it at all: nginx writes a line only at or
   above the level error_log is set to, and that defaults to error. Without
   this setting the level is reachable only by editing the built module. */
await section("the challenge log line is written at the configured level", async () => {
    const at = async (value) => {
        const saved = process.env.ANTIBOT_CHALLENGE_LOG_LEVEL;
        if (value === null) delete process.env.ANTIBOT_CHALLENGE_LOG_LEVEL;
        else process.env.ANTIBOT_CHALLENGE_LOG_LEVEL = value;
        try {
            const m = await variantWith([]);
            const seen = { log: [], warn: [], error: [] };
            const r = makeR(null, '203.0.113.6');
            r.log = (s) => seen.log.push(s);
            r.warn = (s) => seen.warn.push(s);
            r.error = (s) => seen.error.push(s);
            m.serve_challenge(r);
            check(r.code === 200, 'level ' + JSON.stringify(value) +
                  ' served ' + r.code + ', so the line was not the only thing that moved');
            return seen;
        } finally {
            if (saved === undefined) delete process.env.ANTIBOT_CHALLENGE_LOG_LEVEL;
            else process.env.ANTIBOT_CHALLENGE_LOG_LEVEL = saved;
        }
    };
    const lines = (seen, k) =>
        seen[k].filter((line) => line.indexOf('challenge served to') !== -1).length;

    let ran = 0;
    for (const [value, where] of [[null, 'log'], ['info', 'log'], ['warn', 'warn'],
                                  ['error', 'error'], ['off', null]]) {
        const seen = await at(value);
        for (const k of ['log', 'warn', 'error']) {
            const want = k === where ? 1 : 0;
            check(lines(seen, k) === want, 'level ' + JSON.stringify(value) + ': r.' +
                  k + ' carried ' + lines(seen, k) + ' challenge lines, expected ' + want);
        }
        ran++;
        console.log('  ANTIBOT_CHALLENGE_LOG_LEVEL=' + String(value).padEnd(5) +
                    ' -> ' + (where === null ? 'nothing written' : 'r.' + where));
    }

    /* An unknown level falls back to the constant and says so, the way every
       other setting outside its range does. */
    const bad = await at('verbose');
    check(lines(bad, 'log') === 1, 'an unknown level did not fall back to info');
    check(bad.error.some((line) => line.indexOf('CHALLENGE_LOG_LEVEL=verbose') !== -1),
          'no error-log line for an unknown level; wrote: ' + bad.error.join(' | '));
    ran++;
    console.log('  ANTIBOT_CHALLENGE_LOG_LEVEL=verbose -> r.log, and reported');

    /* A run where serve_challenge stopped writing the line would otherwise
       report every "expected 0" as a pass. */
    check(ran === 6, 'only ' + ran + ' of 6 level cases ran');
});

/* A constant in the source is validated the way an environment value is, and
   one that is invalid falls back to the built-in value rather than being
   kept. A window of 0 once put slot=Infinity in the page and locked every
   visitor out; a cookie lifetime below the acceptance window has the browser
   drop the cookie while the module would still take it. */
await section("a constant in the source is validated like the environment", async () => {
        const served = async (decls) => {
            const v = await variantWith(decls);
            const logged = [];
            const r = makeR(null, '203.0.113.91');
            r.error = (m) => logged.push(m);
            v.serve_challenge(r);
            const st = makeR(null);
            v.status(st);
            return {
                slot: /var slot="([^"]*)"/.exec(r.body)[1],
                cookie: /var v="([^"=]+)="/.exec(r.body)[1],
                maxAge: Number(/Max-Age=(\d+)/.exec(r.body)[1]),
                window: Number(/^window (\d+)$/m.exec(st.body)[1]),
                logged: logged.join(' | ')
            };
        };
        const zero = await served([['WINDOW_SIZE', '0']]);
        check(zero.window === 21600 && /^\d+$/.test(zero.slot),
              'WINDOW_SIZE = 0 gave window ' + zero.window + ' and slot ' + zero.slot);
        check(zero.logged.indexOf('WINDOW_SIZE=0 is not an integer') !== -1,
              'WINDOW_SIZE = 0 was not reported: ' + zero.logged);
        const name = await served([['COOKIE_NAME', '"bad;name"']]);
        check(name.cookie === '__Host-antibot-ac',
              'COOKIE_NAME = "bad;name" served ' + name.cookie);
        check(name.logged.indexOf('COOKIE_NAME=bad;name is not a cookie name') !== -1,
              'COOKIE_NAME = "bad;name" was not reported: ' + name.logged);
        console.log('  source: WINDOW_SIZE = 0 -> ' + zero.window + ', COOKIE_NAME = "bad;name" -> ' +
                    name.cookie + ', both reported');

        const WINDOW = 6 * 60 * 60;
        for (const [value, expected] of [['1', 2 * WINDOW], ['0', 2 * WINDOW],
                                         ['-1', 2 * WINDOW], ['50000.5', 2 * WINDOW],
                                         ['null', 2 * WINDOW], ['2 * WINDOW_SIZE', 2 * WINDOW],
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
            const r = makeR(header, address);
            variant.check(r);
            check(r.code === 204, 'a valid cookie behind ' + ahead +
                  ' others was answered ' + r.code + ', within the bound of ' + bound);
        }
        const past = makeR(junk(bound) + '; ' + good, address);
        variant.check(past);
        check(past.code === 401, 'a valid cookie behind ' + bound +
              ' others was answered ' + past.code + ', past the bound of ' + bound);
        console.log('  cookie candidates: found behind 0 to ' + (bound - 1) +
                    ' others, refused behind ' + bound);
});

/* The page's workers scan the nonces below POW_MAX_ITERATIONS, so the server
   refuses a nonce at the cap. At 4 bits the cap is 2^4 x 64 = 1024, and an
   identity whose challenge is met by both 1023 and 1024 tells the two sides
   apart: 1023 is accepted and 1024 is refused for being at the cap, not for
   its digest. */
await section("a nonce at the iteration cap is refused", async () => {
        const v = await variantFor(4);
        const meets4 = (ch, n) => crypto.createHash('sha256').update(ch + ':' + n)
                                        .digest()[0] >> 4 === 0;
        let found = null;
        for (let i = 0; i < 20000 && found === null; i++) {
            const address = '198.51.' + (i >> 8) + '.' + (i & 255);
            const r = makeR(null, address);
            v.serve_challenge(r);
            const ch = /var challenge="([0-9a-f]+)"/.exec(r.body)[1];
            const cap = Number(/,cap=(\d+);/.exec(r.body)[1]);
            if (meets4(ch, cap - 1) && meets4(ch, cap)) {
                found = { address, cap, issued: /var slot="(\d+)"/.exec(r.body)[1] };
            }
        }
        check(found !== null, 'no identity met 4 bits at both 1023 and 1024');
        if (found !== null) {
            check(found.cap === 1024, 'the cap at 4 bits is ' + found.cap);
            const at = (n) => {
                const r = makeR(COOKIE_NAME + '=' + found.issued + '.' + n, found.address);
                v.check(r);
                return r.code;
            };
            check(at(found.cap - 1) === 204, 'the nonce below the cap was answered ' +
                  at(found.cap - 1));
            check(at(found.cap) === 401, 'the nonce at the cap was answered ' + at(found.cap));
            console.log('  cap ' + found.cap + ': ' + (found.cap - 1) + ' -> ' +
                        at(found.cap - 1) + ', ' + found.cap + ' -> ' + at(found.cap));
        }
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
        const now = makeR(cookie, '203.0.113.44');
        variant.check(now);
        check(now.code === 204,
              'a cookie solved in the previous slot was answered ' + now.code);
        const older = makeR(cookie.replace('=' + (slotNow - 1) + '.', '=' + (slotNow - 2) + '.'),
                            '203.0.113.44');
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
   cost must not track header size, for either header it is built from.
   Comparing totals would also measure the header parsing, which grows with
   size whatever the module does, so each measurement subtracts the same
   request without a cookie: what remains is the hashing. The assertion is on
   growth from 8 KB to 64 KB, not on a ratio against a short header, for the
   reason the address test below gives. Without the clip, Accept-Language took
   this to 4.54x. */
await section("hashing does not track header size", async () => {
        const timeWith = (header, value, cookie) => {
            const N = 1000;
            const one = () => {
                const r = makeR(cookie, '203.0.113.9');
                r.headersIn[header] = value;
                return r;
            };
            for (let i = 0; i < 100; i++) mod.check(one());
            const t = process.hrtime.bigint();
            for (let i = 0; i < N; i++) mod.check(one());
            return Number(process.hrtime.bigint() - t) / 1000 / N;
        };
        const withCookie = COOKIE_NAME + '=' + slot + '.123456789';
        const hashing = (header, value) =>
            median3(() => timeWith(header, value, withCookie) - timeWith(header, value, null));

        let ran = 0;
        for (const header of ['User-Agent', 'Accept-Language']) {
            const big = hashing(header, 'M'.repeat(8192));
            const bigger = hashing(header, 'M'.repeat(65536));
            const growth = bigger / big;
            check(growth < 2, 'hashing a 64 KB ' + header + ' costs ' + growth.toFixed(2) +
                             'x an 8 KB one; the identity is not being clipped');
            ran++;
            console.log('  hashing work, ' + header.padEnd(15) + ': 8 KB ' + big.toFixed(1) +
                        ' us, 64 KB ' + bigger.toFixed(1) + ' us, growth ' + growth.toFixed(2) + 'x');
        }
        check(ran === 2, 'only ' + ran + ' of 2 identity headers were measured');
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
                                    address);
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
            const one = () => makeR(cookie, '203.0.113.9');
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

/* nginx writes one error-log line per call. The line carries $request_uri,
   what the client asked for, because after error_page r.uri is the internal
   location. Every field the module logs is encoded first, so a newline in one
   cannot start a line of its own. */
await section("the log line survives a URI with a newline", async () => {
        const LF = String.fromCharCode(10);
        const r = makeR(null, '203.0.113.9');
        r.variables.request_uri = '/a' + LF + 'antibot: forged';
        mod.serve_challenge(r);
        check(r.logged.length === 1,
              'serve_challenge wrote ' + r.logged.length + ' log lines, expected 1');
        const line = r.logged[0] || '';
        check(line.indexOf(LF) === -1,
              'a newline in the URI survived into the log line');
        check(line.indexOf('/a\\x0aantibot: forged') !== -1,
              'the URI was not encoded in the log line: ' + JSON.stringify(line));
        check(line.indexOf('__antibot_challenge') === -1,
              'the log line names the internal location: ' + JSON.stringify(line));
        const wide = makeR(null, '203.0.113.9');
        wide.variables.request_uri = '/' + String.fromCodePoint(0x1f600);
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
        const ok = makeR(COOKIE_NAME + '=' + issued + '.' + nonce, '203.0.113.72');
        solved.check(ok);
        check(ok.code === 204, 'the solved cookie was answered ' + ok.code);
        check(read().accepted === '1',
              'one acceptance was counted as ' + read().accepted);

        /* A report counts its solver, and counts a solve as slow when the
           reported rate puts the mean solve at this difficulty above ten
           seconds. 2^22 hashes at 419,431 per second is 10.0 s. */
        const send = (args) => {
            const r = makeR(null, '203.0.113.73');
            r.args = args;
            const seen = [];
            r.log = (m) => seen.push(m);
            counted.report(r);
            return { code: r.code, seen };
        };
        const fast = send({ solver: 'wasm', rate: '8400000' });
        check(fast.code === 204, 'a valid report was answered ' + fast.code);
        check(fast.seen.some((m) => m.indexOf('solver=wasm rate=8400000') !== -1),
              'a report was not logged: ' + JSON.stringify(fast.seen));
        send({ solver: 'js', rate: '132000' });
        send({ solver: 'wasm', rate: '419431' });
        send({ solver: 'wasm', rate: '419430' });
        let refused = 0;
        for (const args of [{}, { solver: 'wasm' }, { rate: '1' },
                            { solver: 'gpu', rate: '1' }, { solver: 'js', rate: '1.5' },
                            { solver: 'js', rate: '' }, { solver: 'js', rate: '1e9' },
                            { solver: ['js', 'js'], rate: '1' },
                            { solver: 'js', rate: '1234567890123' }]) {
            if (send(args).code === 400) refused++;
        }
        check(refused === 9, refused + ' of 9 malformed reports were refused');
        const tally = read();
        check(tally.solved_wasm === '3' && tally.solved_js === '1',
              'four reports were counted as wasm=' + tally.solved_wasm +
              ' js=' + tally.solved_js);
        check(tally.solved_slow === '2',
              'two slow solves were counted as ' + tally.solved_slow);
        check(tally.window === '21600', 'status reported window ' + tally.window);
        console.log('  counters: 5 rejected, 4 challenges, 1 accepted, 4 reports ' +
                    '(2 slow), 9 malformed refused, and zone missing reported without one');
    } finally {
        if (saved === undefined) delete globalThis.ngx;
        else globalThis.ngx = saved;
    }
});

await section("the embedded programs match the files they came from", async () => {
    /* build.sh writes three files into the module as JavaScript strings,
       escaping in awk. Decoding them back is what checks that escaping. */
    const built = fs.readFileSync(new URL(MODULE_PATH), 'utf8').split('\n');
    const embedded = (name) => {
        const prefix = 'const ' + name + ' = ';
        for (const line of built) {
            if (line.startsWith(prefix) && line.endsWith('";')) {
                return JSON.parse(line.slice(prefix.length, -1));
            }
        }
        return null;
    };
    const here = new URL('../', import.meta.url);
    for (const [name, file] of [['POW_JS_SOLVER', 'src/solver.js'],
                                ['WORKER_TEMPLATE', 'src/worker.js'],
                                ['PAGE_TEMPLATE', 'src/page.html']]) {
        const got = embedded(name);
        check(got !== null, name + ' is not a single string in the built module');
        if (got === null) continue;
        const want = fs.readFileSync(new URL(file, here), 'utf8');
        check(got === want, name + ' differs from ' + file + ': embedded ' +
              got.length + ' characters, the file has ' + want.length);
    }
    console.log('  embedding: solver, worker and page match their files');
});

await section("a cookie is refused by a host configured differently", async () => {
    /* Settings come from the environment, so two hosts behind one name can
       differ by one line. A cookie is only accepted by a host that agrees on
       what makes it valid, and the visitor is challenged again by one that
       does not. */
    const saved = {};
    const set = (env) => {
        for (const k of ['ANTIBOT_SECRET', 'ANTIBOT_POW_BITS', 'ANTIBOT_WINDOW_SIZE',
                         'ANTIBOT_COOKIE_NAME']) {
            if (!(k in saved)) saved[k] = process.env[k];
            if (env[k] === undefined) delete process.env[k];
            else process.env[k] = env[k];
        }
    };
    const meets = (challenge, nonce, bits) => {
        const hex = crypto.createHash('sha256').update(challenge + ':' + nonce).digest('hex');
        const full = bits >> 2, rem = bits & 3;
        if (hex.slice(0, full) !== '0'.repeat(full)) return false;
        return rem ? (parseInt(hex[full], 16) >> (4 - rem)) === 0 : true;
    };
    const ADDRESS = '203.0.113.81';
    const BASE = {
        ANTIBOT_SECRET: 'a'.repeat(64),
        ANTIBOT_POW_BITS: '10',
        ANTIBOT_WINDOW_SIZE: '21600',
        ANTIBOT_COOKIE_NAME: '__Host-antibot-ac'
    };
    try {
        set(BASE);
        const home = await variantWith([]);
        const served = makeR(null, ADDRESS);
        home.serve_challenge(served);
        const challenge = /var challenge="([0-9a-f]+)"/.exec(served.body)[1];
        const slot = /var slot="(\d+)"/.exec(served.body)[1];
        const name = /var v="([^"=]+)="/.exec(served.body)[1];
        /* Meets 10 bits and not 24, so the stricter host refuses it for the
           reason under test rather than by luck. */
        let nonce = 0;
        while (!(meets(challenge, nonce, 10) && !meets(challenge, nonce, 24))) nonce++;
        const cookie = name + '=' + slot + '.' + nonce;

        const own = makeR(cookie, ADDRESS);
        home.check(own);
        check(own.code === 204, 'the host that issued the challenge answered ' + own.code);

        for (const [setting, value] of [['ANTIBOT_SECRET', 'b'.repeat(64)],
                                        ['ANTIBOT_POW_BITS', '24'],
                                        ['ANTIBOT_WINDOW_SIZE', '3600'],
                                        ['ANTIBOT_COOKIE_NAME', '__Host-other']]) {
            set({ ...BASE, [setting]: value });
            const other = await variantWith([]);
            const r = makeR(cookie, ADDRESS);
            other.check(r);
            check(r.code === 401, 'a host differing only in ' + setting +
                  ' answered ' + r.code + ', so the mismatch went unnoticed');
        }
        console.log('  host settings: a cookie is refused when any of the four differs');
    } finally {
        for (const k of Object.keys(saved)) {
            if (saved[k] === undefined) delete process.env[k];
            else process.env[k] = saved[k];
        }
    }
});

await section("a configuration warning is written once, not per request", async () => {
    /* njs clones a VM per request from the configuration scope, so a module
       variable is back to its loaded state every time. variantWith gives a
       fresh module, which is the same thing: several of them with one shared
       dictionary between them is what a worker actually does. */
    const store = new Map();
    const zone = {
        get(key) { return store.get(key); },
        set(key, value) { store.set(key, value); },
        incr(key, delta, init) {
            const next = (store.has(key) ? store.get(key) : init) + delta;
            store.set(key, next);
            return next;
        }
    };
    const saved = globalThis.ngx;
    const savedBits = process.env.ANTIBOT_POW_BITS;
    try {
        process.env.ANTIBOT_POW_BITS = '999';

        const lines = async () => {
            const mod2 = await variantWith([]);
            const logged = [];
            const r = makeR(null, '203.0.113.80');
            r.error = (m) => logged.push(m);
            mod2.check(r);
            return logged;
        };

        globalThis.ngx = { shared: { antibot: zone } };
        let total = 0, first = null;
        for (let i = 0; i < 4; i++) {
            const got = await lines();
            if (first === null && got.length) first = got[0];
            total += got.length;
        }
        check(total === 1, 'four requests wrote ' + total +
              ' configuration warnings, expected 1');
        check(first !== null && first.indexOf('POW_BITS=999') !== -1,
              'the warning did not name the setting: ' + JSON.stringify(first));

        /* Without the zone there is nowhere to record that one was written. */
        delete globalThis.ngx;
        let bare = 0;
        for (let i = 0; i < 3; i++) bare += (await lines()).length;
        check(bare === 3, 'without the zone, three requests wrote ' + bare +
              ' warnings, expected one each');

        /* A configuration with nothing wrong writes nothing. */
        process.env.ANTIBOT_POW_BITS = '22';
        globalThis.ngx = { shared: { antibot: zone } };
        store.clear();
        let quiet = 0;
        for (let i = 0; i < 3; i++) quiet += (await lines()).length;
        check(quiet === 0, 'a valid configuration wrote ' + quiet + ' warnings');

        console.log('  config warnings: 1 in four requests with the zone, ' +
                    '3 in three without it, 0 when nothing is wrong');
    } finally {
        if (saved === undefined) delete globalThis.ngx; else globalThis.ngx = saved;
        if (savedBits === undefined) delete process.env.ANTIBOT_POW_BITS;
        else process.env.ANTIBOT_POW_BITS = savedBits;
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
