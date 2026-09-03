/*
 * Randomised robustness test for what the module parses.
 *
 *   node test/module-fuzz.mjs [module] [iterations] [seed]
 *
 * Everything the module reads from a request is attacker-controlled: the
 * cookie header, the User-Agent, the Accept-Language, Sec-Fetch-Dest and,
 * where real_ip_header is configured, the address. Only the solver was ever
 * fuzzed; this covers the parsers.
 *
 * Three properties hold for any input:
 *
 *   1. Neither entry point throws, and check() answers 204, 401 or 500.
 *   2. A 204 is only ever returned for a nonce whose digest really meets the
 *      difficulty. That is verified against the challenge the module itself
 *      issues for the same identity, so it cannot pass by coincidence.
 *   3. A module with no secret answers 500 and never 204.
 *
 * Property 2 needs a solved cookie to reach it. Guessing one at the shipped
 * difficulty takes 2^22 tries, so the pass that carries it runs against a
 * variant at ACCEPT_BITS, where the suite solves cookies itself and mutates
 * them. The run fails if that pass reports no acceptance, because a property
 * that never executes is not being tested.
 */

import crypto from 'crypto';
import { test } from 'node:test';
import fs from 'fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const usage = 'usage: node test/module-fuzz.mjs [module] [iterations] [seed]';
const MODULE_PATH = process.argv[2]
    ? pathToFileURL(process.argv[2]).href
    : new URL('../dist/antibot.js', import.meta.url).href;
if (!fs.existsSync(new URL(MODULE_PATH))) {
    console.error(MODULE_PATH.replace(/^.*\//, '') + ' not found. This suite runs ' +
                  'against a build; run ./build.sh first.\n' + usage);
    process.exit(2);
}

/* A count that is not a positive integer would otherwise run zero iterations
   and report success. */
const iterations = process.argv[3] === undefined ? 20000 : Number(process.argv[3]);
if (!Number.isInteger(iterations) || iterations < 1) {
    console.error('iterations must be a positive integer, got ' +
                  JSON.stringify(process.argv[3]) + '\n' + usage);
    process.exit(2);
}
const seed = process.argv[4] === undefined ? 1 : Number(process.argv[4]);
if (!Number.isInteger(seed)) {
    console.error('seed must be an integer, got ' + JSON.stringify(process.argv[4]) +
                  '\n' + usage);
    process.exit(2);
}

if (!process.env.ANTIBOT_SECRET || process.env.ANTIBOT_SECRET.length < 32) {
    process.env.ANTIBOT_SECRET = crypto.randomBytes(32).toString('hex');
}

const SRC = fs.readFileSync(new URL(MODULE_PATH), 'utf8');
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'antibot-fuzz-'));
const POW_BITS_LINE = /^const POW_BITS = -?\d+;$/m;
if (!POW_BITS_LINE.test(SRC)) {
    throw new Error('POW_BITS declaration not found; the accept pass would have ' +
                    'run at the shipped difficulty and never accepted anything');
}
/* Low enough to solve in milliseconds, high enough that a mutated nonce is
   rejected almost always: a guess passes 1 time in 2^14. */
const ACCEPT_BITS = 14;

let variants = 0;
const variantFor = async (bits) => {
    const wanted = 'const POW_BITS = ' + bits + ';';
    const text = SRC.replace(POW_BITS_LINE, wanted);
    if (text.indexOf(wanted) === -1) {
        throw new Error('POW_BITS rewrite produced no such line');
    }
    const file = path.join(DIR, 'bits' + bits + '.' + (variants++) + '.js');
    fs.writeFileSync(file, text);
    return (await import(pathToFileURL(file).href)).default;
};

let state = BigInt(seed);
const rand = (n) => {
    state = (state * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn;
    return Number((state >> 33n) % BigInt(n));
};
const pick = (a) => a[rand(a.length)];
const repeat = (s, n) => s.repeat(n);

const NAME = '__Host-antibot-ac';
const slot = Math.floor(Date.now() / 1000 / 21600);

/* Shapes worth hitting deliberately, mixed in with the random ones. */
const corpus = [
    '', NAME, NAME + '=', NAME + '=.', NAME + '=' + repeat('.', 4000),
    NAME + '=' + slot + '.' + repeat('9', 4000),
    NAME + '=' + repeat('9', 4000) + '.1',
    NAME + '=1.' + String.fromCodePoint(0x1f600),
    NAME + '=' + slot + '.-1', NAME + '=-1.0', NAME + '=1e3.1',
    NAME + '=' + slot + '.0; ' + NAME + '=' + slot + '.1',
    'other=1; ' + NAME + '=' + slot + '.2',
    NAME + '=' + slot + '.' + Number.MAX_SAFE_INTEGER,
];
const addresses = ['', ' ', '1.2.3.4', '::1', '::ffff:1.2.3.4', 'unix:',
                   'unix:/var/run/x.sock', repeat(':', 2000),
                   repeat('a', 300) + ':' + repeat('b', 300), 'not-an-ip:x'];
const dests = [undefined, 'document', 'empty', 'image', repeat('x', 500)];

const bytes = (n) => {
    let out = '';
    for (let i = 0; i < n; i++) out += String.fromCharCode(rand(0x2000) + 1);
    return out;
};

let failures = 0;
const fail = (msg) => { failures++; console.log('  FAIL: ' + msg); };

const request = (cookie, address, dest, ua, lang) => {
    const headersIn = { 'User-Agent': ua, 'Accept-Language': lang };
    if (cookie !== undefined) headersIn.Cookie = cookie;
    if (dest !== undefined) headersIn['Sec-Fetch-Dest'] = dest;
    return {
        remoteAddress: address, uri: '/', headersIn, headersOut: {},
        error() {}, warn() {}, log() {},
        return(code, body) { this.code = code; this.body = body; }
    };
};

/* The challenge the module issues for this identity, `back` slots ago. The
   clock is moved rather than the derivation reimplemented here, so what the
   check compares against is the module's own answer. */
const challengeCache = new Map();
const challengeOf = (mod, address, dest, ua, lang, back) => {
    const key = back + '\u0000' + address + '\u0000' + ua + '\u0000' + lang;
    if (challengeCache.has(key)) return challengeCache.get(key);
    const realNow = Date.now;
    let out = null;
    try {
        if (back) Date.now = () => realNow() - back * 21600 * 1000;
        const r = request(undefined, address, dest, ua, lang);
        mod.serve_challenge(r);
        if (r.code !== 500) {
            out = {
                challenge: /var challenge="([0-9a-f]+)"/.exec(r.body)[1],
                bits: Number(/,bits=(\d+);/.exec(r.body)[1]),
                slot: Number(/var slot="(\d+)"/.exec(r.body)[1])
            };
        }
    } finally {
        Date.now = realNow;
    }
    challengeCache.set(key, out);
    return out;
};

const meets = (challenge, nonce, bits) => {
    const hex = crypto.createHash('sha256').update(challenge + ':' + nonce).digest('hex');
    const full = bits >> 2, rem = bits & 3;
    if (hex.slice(0, full) !== '0'.repeat(full)) return false;
    return rem ? (parseInt(hex[full], 16) >> (4 - rem)) === 0 : true;
};

/* Identities with a genuinely solved cookie, for the accept pass. */
const solvedFor = (mod, identities) => {
    const out = [];
    for (const id of identities) {
        const c = challengeOf(mod, id.address, 'empty', id.ua, id.lang);
        let nonce = 0;
        while (!meets(c.challenge, String(nonce), c.bits)) nonce++;
        out.push({ ...id, cookie: NAME + '=' + slot + '.' + nonce });
    }
    return out;
};

const mutate = (s) => {
    const i = rand(s.length);
    return s.slice(0, i) + String.fromCharCode(s.charCodeAt(i) ^ (1 + rand(15))) +
           s.slice(i + 1);
};

function fuzz(mod, label, count, solved) {
    const counts = { 204: 0, 401: 0, 500: 0, other: 0 };
    let verified = 0, mutantsRejected = 0;

    for (let i = 0; i < count; i++) {
        /* One iteration in four draws a solved identity, so the accept path is
           reached by construction rather than by chance. */
        const useSolved = solved.length > 0 && rand(4) === 0;
        const id = useSolved ? pick(solved) : null;
        let cookie, mutated = false;
        if (id) {
            if (rand(3) === 0) { cookie = mutate(id.cookie); mutated = true; }
            else cookie = id.cookie;
        } else {
            cookie = rand(3) === 0 ? pick(corpus)
                   : rand(2) === 0 ? NAME + '=' + rand(1e6) + '.' + rand(1e9)
                   : bytes(rand(80));
        }
        const address = id ? id.address
                       : rand(4) === 0 ? bytes(rand(40)) : pick(addresses);
        const dest = id ? 'empty' : pick(dests);
        const ua = id ? id.ua : rand(6) === 0 ? bytes(rand(300)) : 'Mozilla/5.0';
        const lang = id ? id.lang : rand(8) === 0 ? bytes(rand(60)) : 'en-US';

        const r = request(cookie, address, dest, ua, lang);
        try {
            mod.check(r);
        } catch (err) {
            fail(label + ': check threw on cookie=' +
                 JSON.stringify(String(cookie).slice(0, 60)) + ' address=' +
                 JSON.stringify(String(address).slice(0, 40)) + ': ' + err.message);
            continue;
        }
        if (r.code === 204 || r.code === 401 || r.code === 500) {
            counts[r.code]++;
        } else {
            counts.other++;
            fail(label + ': check answered ' + r.code);
            continue;
        }
        if (mutated && r.code !== 204) mutantsRejected++;

        if (r.code === 204) {
            /* A cookie is accepted for its own slot and the one before it, so
               a 204 is justified when some candidate under the name meets the
               difficulty against the challenge for the slot it carries. The
               header can hold several, and a mutation can move one onto the
               previous slot, so every candidate is tried rather than the last
               dot in the string. */
            const header = String(cookie);
            const candidates = [];
            for (const part of header.split(';')) {
                const pair = part.trim();
                if (pair.indexOf(NAME + '=') !== 0) continue;
                const value = pair.substring(NAME.length + 1);
                const dot = value.indexOf('.');
                if (dot === -1) continue;
                candidates.push({ slot: value.substring(0, dot),
                                  nonce: value.substring(dot + 1) });
            }
            let justified = false, serves = true;
            for (const cand of candidates) {
                for (const back of [0, 1]) {
                    const c = challengeOf(mod, address, dest, ua, lang, back);
                    if (c === null) { serves = false; continue; }
                    if (String(c.slot) !== cand.slot) continue;
                    if (meets(c.challenge, cand.nonce, c.bits)) justified = true;
                }
            }
            if (!serves) {
                fail(label + ': 204 from a module that serves no challenge');
            } else if (!justified) {
                fail(label + ': 204 for a cookie no candidate justifies: ' +
                     JSON.stringify(header.slice(0, 80)) + ' mutated=' + mutated);
            } else {
                verified++;
            }
        }

        if (rand(50) === 0) {
            const page = request(undefined, address, dest, ua, lang);
            try {
                mod.serve_challenge(page);
            } catch (err) {
                fail(label + ': serve_challenge threw for address=' +
                     JSON.stringify(String(address).slice(0, 40)) + ': ' + err.message);
                continue;
            }
            if (page.code !== 200 && page.code !== 500) {
                fail(label + ': serve_challenge answered ' + page.code);
            }
            if (page.code === 200 && !/var challenge="[0-9a-f]{64}"/.test(page.body)) {
                fail(label + ': serve_challenge produced a page with no challenge');
            }
        }
    }

    console.log('  ' + label.padEnd(22) + count.toLocaleString('en-US') + ' requests: ' +
                counts[401] + ' rejected, ' + counts[204] + ' accepted (' + verified +
                ' verified), ' + counts[500] + ' misconfigured, ' + counts.other + ' other');
    return { counts, verified, mutantsRejected };
}

/* Pass 1: the shipped artifact, at its own difficulty. */
const shipped = (await import(MODULE_PATH)).default;
const robustness = fuzz(shipped, 'shipped', iterations, []);

/* Pass 2: a variant low enough to solve, so property 2 executes. */
const low = await variantFor(ACCEPT_BITS);
const identities = solvedFor(low, [
    { address: '203.0.113.9', ua: 'Mozilla/5.0', lang: 'en-US' },
    { address: '2001:db8:1:2::1', ua: 'Mozilla/5.0 (X11)', lang: 'fr' },
    { address: '::ffff:198.51.100.7', ua: repeat('U', 300), lang: 'en-GB' },
    { address: 'not-an-ip:x', ua: 'curl/8', lang: '' },
]);
const accept = fuzz(low, 'accept ' + ACCEPT_BITS + ' bits',
                    Math.max(2000, Math.floor(iterations / 10)), identities);

/* Pass 3: no secret. SECRET is read once at load, so this needs its own copy. */
const savedSecret = process.env.ANTIBOT_SECRET;
delete process.env.ANTIBOT_SECRET;
const unconfigured = await variantFor(22);
process.env.ANTIBOT_SECRET = savedSecret;
const misconfigured = fuzz(unconfigured, 'no secret', 2000, []);

/* A property that never executes is not being tested. Each is a named test so
   one failing says which, and the rest still report. */
await test('the shipped pass rejects what it is given', () => {
    if (robustness.counts[401] === 0) fail('the shipped pass rejected nothing');
});
await test('the accept pass reaches an acceptance and verifies it', () => {
    if (accept.verified === 0) {
        fail('the accept pass verified no acceptance; the property did not execute');
    }
});
await test('the accept pass rejects a mutated cookie', () => {
    if (accept.mutantsRejected === 0) fail('the accept pass rejected no mutated cookie');
});
await test('a module with no secret answers 500 and never 204', () => {
    if (misconfigured.counts[500] !== 2000 || misconfigured.counts[204] !== 0) {
        fail('a module with no secret answered ' + misconfigured.counts[204] +
             ' times with 204 and ' + misconfigured.counts[500] + ' times with 500');
    }
});
await test('no request threw or answered outside 204, 401 and 500', () => {
    if (failures > 0) throw new Error(failures + ' failure(s) during the passes');
});

fs.rmSync(DIR, { recursive: true, force: true });
console.log(failures ? '\n' + failures + ' FAILURE(S)' : '\nall checks passed');
