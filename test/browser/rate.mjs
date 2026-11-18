/*
 * Solver throughput in a browser worker: the harness behind the browser rates
 * in docs/.
 *
 *   taskset -c 2 node test/browser/rate.mjs <chromium> [module] [flags...]
 *
 * The module defaults to dist/antibot.js; the wasm beside it and the JS
 * solver it embeds are measured. Flags go to Chromium, for example
 * --js-flags=--jitless.
 *
 * Each solver runs the way the page runs it: the wasm is compiled on the main
 * thread and the WebAssembly.Module posted to a Worker built from a Blob,
 * which instantiates it; the JS solver is built inside the Worker from its
 * source. Warm-up calls of 16,384 nonces run for at least two seconds and at
 * least eight calls; the rate they reach sizes the measured calls to about
 * half a second each, from 16,384 to 2,097,152 nonces, so an interpreted
 * solver is measured in seconds rather than hours. Then three rounds per
 * solver of five calls at 32 bits, which never finds a solution. Rounds
 * alternate between the solvers. A rate is the median of the 15 calls. Pin
 * the process with taskset; the browser inherits it.
 */

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { launch } from './cdp.mjs';

const [binary, moduleArg, ...flags] = process.argv.slice(2);
if (!binary) {
    console.error('usage: node test/browser/rate.mjs <chromium> [module] [flags...]');
    process.exit(2);
}
const MODULE = moduleArg && !moduleArg.startsWith('--') ? moduleArg : 'dist/antibot.js';
if (moduleArg && moduleArg.startsWith('--')) flags.unshift(moduleArg);
const WASM = path.join(path.dirname(MODULE), 'pow_solver.wasm');

const src = fs.readFileSync(MODULE, 'utf8');
const from = src.indexOf('const POW_JS_SOLVER =');
const to = src.indexOf('const WORKER_TEMPLATE =');
const solver = new Function('return (' + src.slice(from, to)
    .replace(/^const POW_JS_SOLVER =/, '').trim().replace(/;$/, '') + ')')();
if (from < 0 || to < 0 || !solver) {
    console.error(MODULE + ' carries no assembled POW_JS_SOLVER');
    process.exit(2);
}

const PAGE = `<!doctype html><meta charset="utf-8"><title>rate</title><script>
var WORKER = "self.onmessage=function(e){var c=e.data.c,x,i,k=0,t,n=0,B=16384,C,r=[];" +
  "if(e.data.mod){x=new WebAssembly.Instance(e.data.mod,{}).exports;" +
  "for(i=0;i<64;i++){x.set_byte(i,c.charCodeAt(i));}x.init();}" +
  "else{x=new Function(e.data.js+';return jsSolver;')()(c);}" +
  "t=performance.now();while(k<8||performance.now()-t<2000){x.solve(n,B,32);n+=B;k++;}" +
  "C=Math.max(B,Math.min(2097152,Math.floor(k*B/(performance.now()-t)*500/B)*B));" +
  "for(k=0;k<5;k++){t=performance.now();x.solve(n,C,32);n+=C;" +
  "r.push(C/(performance.now()-t)/1e3);}self.postMessage(r);};";
window.run = async function (kind, js) {
  var mod = kind === 'wasm'
    ? await WebAssembly.compile(await (await fetch('/pow_solver.wasm')).arrayBuffer())
    : null;
  var w = new Worker(URL.createObjectURL(new Blob([WORKER], {type: 'text/javascript'})));
  return await new Promise(function (resolve) {
    w.onmessage = function (e) { w.terminate(); resolve(e.data); };
    w.postMessage({mod: mod, js: js, c: 'a'.repeat(32) + '0123456789abcdef0123456789abcdef'});
  });
};
</script>`;

const server = http.createServer((req, res) => {
    if (req.url === '/pow_solver.wasm') {
        res.writeHead(200, { 'content-type': 'application/wasm' }).end(fs.readFileSync(WASM));
    } else {
        res.writeHead(200, { 'content-type': 'text/html' }).end(PAGE);
    }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

const browser = await launch(binary, flags);
try {
    const page = await browser.page('http://127.0.0.1:' + server.address().port + '/');
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const ua = await page.evaluate('navigator.userAgent');
    /* --jitless leaves WebAssembly undefined, so there the JS solver is all
       a page can run. */
    const kinds = (await page.evaluate('typeof WebAssembly')) === 'object'
        ? ['wasm', 'js'] : ['js'];
    const rates = { wasm: [], js: [] };
    for (let round = 0; round < 3; round++) {
        for (const kind of kinds) {
            rates[kind].push(...await page.evaluate(
                'run(' + JSON.stringify(kind) + ', ' + JSON.stringify(solver) + ')'));
        }
    }
    console.log(ua + (flags.length ? ', flags ' + flags.join(' ') : ''));
    for (const kind of kinds) {
        const sorted = rates[kind].sort((a, b) => a - b);
        console.log(kind.padEnd(5) + ' median ' + sorted[sorted.length >> 1].toFixed(3) +
                    'M hashes/sec  min ' + sorted[0].toFixed(3) + '  max ' +
                    sorted[sorted.length - 1].toFixed(3) + '  n ' + sorted.length);
    }
} finally {
    browser.close();
    server.close();
}
