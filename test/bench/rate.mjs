/*
 * Solver throughput under node: the harness behind every rate in docs/.
 *
 *   taskset -c 2 node test/bench/rate.mjs                     # dist/ build
 *   taskset -c 2 node test/bench/rate.mjs a=x.wasm b=y.wasm   # compare builds
 *
 * Each argument is [label=]file. A .wasm file is measured as the SIMD
 * solver; a .js file is a built module, and the pure-JS solver it embeds is
 * measured. With no argument, dist/pow_solver.wasm and dist/antibot.js are.
 *
 * Every solver gets five warm-up calls, then 15 rounds of one call of
 * 2,000,000 nonces at 32 bits, which never finds a solution, so each call
 * scans the whole batch. Rounds are interleaved solver by solver, so drift in
 * the machine lands on all of them alike. A rate is the median of the 15.
 * Pin the process to one logical core with taskset, so a rate is one core's.
 */

import fs from 'node:fs';

const BATCH = 2e6;
const WARMUP = 5;
const ROUNDS = 15;
const CHALLENGE = 'a'.repeat(32) + '0123456789abcdef0123456789abcdef';

function wasmSolver(file) {
    const x = new WebAssembly.Instance(
        new WebAssembly.Module(fs.readFileSync(file)), {}).exports;
    for (let i = 0; i < 64; i++) {
        x.set_byte(i, CHALLENGE.charCodeAt(i));
    }
    x.init();
    return (start, count) => x.solve(start, count, 32);
}

/* The solver the page ships, lifted out of the built module. */
function jsSolver(file) {
    const src = fs.readFileSync(file, 'utf8');
    const from = src.indexOf('const POW_JS_SOLVER =');
    const to = src.indexOf('const WORKER_TEMPLATE =');
    if (from < 0 || to < 0) {
        throw new Error(file + ' carries no POW_JS_SOLVER');
    }
    const expr = src.slice(from, to).replace(/^const POW_JS_SOLVER =/, '')
        .trim().replace(/;$/, '');
    const code = new Function('return (' + expr + ')')();
    if (!code) {
        throw new Error(file + ' is not assembled: POW_JS_SOLVER is empty');
    }
    const s = new Function(code + '; return jsSolver;')()(CHALLENGE);
    return (start, count) => s.solve(start, count, 32);
}

const args = process.argv.slice(2);
const specs = args.length ? args : ['wasm=dist/pow_solver.wasm', 'js=dist/antibot.js'];
const solvers = specs.map((spec) => {
    const eq = spec.indexOf('=');
    const label = eq > 0 ? spec.slice(0, eq) : spec;
    const file = eq > 0 ? spec.slice(eq + 1) : spec;
    const solve = file.endsWith('.wasm') ? wasmSolver(file) : jsSolver(file);
    return { label, solve, base: 0, rates: [] };
});

for (const s of solvers) {
    for (let w = 0; w < WARMUP; w++) {
        s.solve(s.base, BATCH);
        s.base += BATCH;
    }
}
for (let r = 0; r < ROUNDS; r++) {
    for (const s of solvers) {
        const t = process.hrtime.bigint();
        s.solve(s.base, BATCH);
        s.base += BATCH;
        s.rates.push(BATCH / (Number(process.hrtime.bigint() - t) / 1e9) / 1e6);
    }
}

console.log('node ' + process.version + ', ' + BATCH.toLocaleString('en-US') +
            ' nonces per call, median of ' + ROUNDS + ' calls');
for (const s of solvers) {
    const sorted = s.rates.slice().sort((a, b) => a - b);
    console.log(s.label.padEnd(16) + ' median ' + sorted[ROUNDS >> 1].toFixed(2) +
                'M hashes/sec  min ' + sorted[0].toFixed(2) +
                '  max ' + sorted[ROUNDS - 1].toFixed(2));
}
