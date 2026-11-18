/*
 * Server cost per request under node: the harness behind the cost table in
 * docs/security.md.
 *
 *   taskset -c 2 node test/bench/cost.mjs [module]
 *
 * A request runs the way nginx runs it: auth_request calls check(), and a 401
 * goes through error_page to serve_challenge(), which builds the page. Each
 * case is timed as check() alone and as the whole request. Cases are
 * interleaved: seven runs of 5,000 requests each, after 1,000 warm-up
 * requests per case, and a cost is the median of the seven runs. The page
 * size is the one serve_challenge() returns, raw and gzipped.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import zlib from 'node:zlib';
import { pathToFileURL } from 'node:url';

const MODULE = process.argv[2] || 'dist/antibot.js';
if (!fs.existsSync(MODULE)) {
    console.error(MODULE + ' not found; run ./build.sh first');
    process.exit(2);
}
if (!process.env.ANTIBOT_SECRET || process.env.ANTIBOT_SECRET.length < 32) {
    process.env.ANTIBOT_SECRET = crypto.randomBytes(32).toString('hex');
}
delete process.env.ANTIBOT_POW_BITS;
const mod = (await import(pathToFileURL(MODULE).href)).default;

const request = (cookie) => ({
    remoteAddress: '203.0.113.7', uri: '/__antibot_challenge',
    variables: { request_uri: '/' }, args: {},
    headersIn: cookie === undefined
        ? { 'User-Agent': 'Mozilla/5.0', 'Accept-Language': 'en-US' }
        : { 'User-Agent': 'Mozilla/5.0', 'Accept-Language': 'en-US', Cookie: cookie },
    headersOut: {}, log() {}, warn() {}, error() {},
    return(code, body) { this.code = code; this.body = body; }
});

const first = request();
mod.serve_challenge(first);
const page = first.body;
const challenge = /var challenge="([0-9a-f]+)"/.exec(page)[1];
const slot = Number(/var slot="(\d+)"/.exec(page)[1]);
const bits = Number(/,bits=(\d+);/.exec(page)[1]);
const NAME = /var v="([^"=]+)="/.exec(page)[1] + '=';

let nonce = 0;
const meets = (n) => {
    const d = crypto.createHash('sha256').update(challenge + ':' + n).digest();
    return (d.readUInt32BE(0) >>> (32 - bits)) === 0;
};
while (!meets(nonce)) nonce++;
const junk = (s, i) => NAME + s + '.' + (123456789 + i);

const CASES = [
    ['no cookie', undefined],
    ['valid cookie', NAME + slot + '.' + nonce],
    ['1 junk cookie, current slot', junk(slot, 0)],
    ['4 junk cookies, two slots',
     [junk(slot, 0), junk(slot, 1), junk(slot - 1, 2), junk(slot - 1, 3)].join('; ')],
    ['256 junk cookies', Array.from({ length: 256 }, (_, i) => junk(slot, i)).join('; ')],
];

const whole = (cookie) => {
    const r = request(cookie);
    mod.check(r);
    if (r.code === 401) {
        mod.serve_challenge(request(cookie));
    }
    return r.code;
};
const alone = (cookie) => {
    const r = request(cookie);
    mod.check(r);
    return r.code;
};

const N = 5000;
const RUNS = 7;
const time = (fn, cookie) => {
    const t = process.hrtime.bigint();
    for (let i = 0; i < N; i++) fn(cookie);
    return Number(process.hrtime.bigint() - t) / 1000 / N;
};
const results = CASES.map(([label, cookie]) => {
    for (let i = 0; i < 1000; i++) { alone(cookie); whole(cookie); }
    return { label, cookie, code: alone(cookie), alone: [], whole: [] };
});
for (let run = 0; run < RUNS; run++) {
    for (const c of results) {
        c.alone.push(time(alone, c.cookie));
        c.whole.push(time(whole, c.cookie));
    }
}
const median = (a) => a.slice().sort((x, y) => x - y)[RUNS >> 1];

console.log('node ' + process.version + ', ' + bits + ' bits, median of ' + RUNS +
            ' runs of ' + N.toLocaleString('en-US') + ' requests');
console.log('case'.padEnd(30) + 'check()  ' + 'check() and page on 401');
for (const c of results) {
    console.log(c.label.padEnd(30) + (median(c.alone).toFixed(2) + ' us').padEnd(9) +
                median(c.whole).toFixed(2) + ' us  (check() answers ' + c.code + ')');
}
console.log('challenge page ' + Buffer.byteLength(page).toLocaleString('en-US') + ' bytes, ' +
            zlib.gzipSync(page).length.toLocaleString('en-US') + ' gzipped');
