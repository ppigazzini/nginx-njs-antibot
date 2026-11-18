/*
 * The challenge page in a real browser, end to end.
 *
 *   node test/browser/page.mjs <chromium> [module] [--bits N] [flags...]
 *
 * Serves the page a built module emits, at N bits (default 16), from
 * http://127.0.0.1, which a browser treats as a secure origin, so the
 * __Host- cookie is stored. Requests reach the module the way nginx sends
 * them: / through check(), and serve_challenge() when it answers 401; the
 * report location through check() and then report(). The page is served
 * under the Content-Security-Policy examples/nginx.conf.example gives its
 * location, so the browser enforces the documented policy. Flags go to
 * Chromium, for example --js-flags=--jitless, which leaves the page no
 * WebAssembly.
 *
 * Prints what the page reported and what the gate answered, and exits
 * non-zero unless, within two minutes, the page solved, its cookie was
 * accepted, and its report was taken and named the solver the browser offers:
 * wasm where WebAssembly exists, js where it does not.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { launch } from './cdp.mjs';

const args = process.argv.slice(2);
const binary = args.shift();
if (!binary) {
    console.error('usage: node test/browser/page.mjs <chromium> [module] [--bits N] [flags...]');
    process.exit(2);
}
const MODULE = args[0] && !args[0].startsWith('--') ? args.shift() : 'dist/antibot.js';
let bits = '16';
const at = args.indexOf('--bits');
if (at !== -1) {
    bits = args[at + 1];
    args.splice(at, 2);
}
process.env.ANTIBOT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.ANTIBOT_POW_BITS = bits;
const mod = (await import(pathToFileURL(MODULE).href)).default;

const example = fs.readFileSync(new URL('../../examples/nginx.conf.example', import.meta.url),
                                'utf8');
const policy = /add_header Content-Security-Policy "([^"]+)"/.exec(example);
if (policy === null) {
    console.error('examples/nginx.conf.example carries no Content-Security-Policy');
    process.exit(2);
}

/* The request object njs hands the module, built from a node request. */
const njsRequest = (req) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const out = {
        remoteAddress: req.socket.remoteAddress,
        uri: url.pathname,
        variables: { request_uri: req.url },
        args: Object.fromEntries(url.searchParams),
        headersIn: {
            'User-Agent': req.headers['user-agent'],
            'Accept-Language': req.headers['accept-language'],
            Cookie: req.headers.cookie
        },
        headersOut: {},
        log() {}, warn() {}, error(m) { console.error(m); },
        return(code, body) { this.code = code; this.body = body; }
    };
    return out;
};

const seen = { challenges: 0, accepted: 0, reports: [] };
const server = http.createServer((req, res) => {
    const gate = njsRequest(req);
    mod.check(gate);
    if (gate.code !== 204) {
        if (req.url.startsWith('/__antibot_report')) {
            res.writeHead(gate.code).end();
            return;
        }
        const page = njsRequest(req);
        mod.serve_challenge(page);
        seen.challenges++;
        res.writeHead(page.code, { ...page.headersOut,
                                   'Content-Security-Policy': policy[1] }).end(page.body);
        return;
    }
    if (req.url.startsWith('/__antibot_report')) {
        const r = njsRequest(req);
        mod.report(r);
        seen.reports.push({ args: r.args, code: r.code });
        res.writeHead(r.code).end();
        return;
    }
    seen.accepted++;
    res.writeHead(200, { 'content-type': 'text/html' })
       .end('<!doctype html><title>backend</title><p id="backend">backend</p>');
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

const browser = await launch(binary, args);
const started = Date.now();
let ok = false;
try {
    const page = await browser.page('http://127.0.0.1:' + server.address().port + '/');
    while (Date.now() - started < 120000 && !(seen.reports.length && seen.accepted)) {
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    const ua = await page.evaluate('navigator.userAgent');
    const wasm = await page.evaluate('typeof WebAssembly');
    const secs = ((Date.now() - started) / 1000).toFixed(1);
    console.log(ua + (args.length ? ', flags ' + args.join(' ') : '') +
                ', WebAssembly ' + wasm + ', ' + bits + ' bits');
    console.log('challenges served ' + seen.challenges + ', solved cookie accepted ' +
                seen.accepted + ' time(s), after ' + secs + ' s');
    for (const r of seen.reports) {
        console.log('report ' + JSON.stringify(r.args) + ' -> ' + r.code);
    }
    ok = seen.accepted > 0 && seen.reports.length === 1 && seen.reports[0].code === 204 &&
         seen.reports[0].args.solver === (wasm === 'object' ? 'wasm' : 'js');
} finally {
    await browser.close();
    server.close();
}
process.exit(ok ? 0 : 1);
