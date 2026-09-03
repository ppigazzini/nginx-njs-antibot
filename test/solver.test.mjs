/*
 * Verification and benchmark suite for both proof-of-work solvers.
 *
 *   node test/solver.test.mjs   # after ./build.sh
 *
 * Two implementations of one algorithm are shipped and both are checked here:
 *
 *   - the SIMD wasm built from src/pow_solver.c into dist/
 *   - the pure-JS solver in dist/antibot.js, which serves
 *     engines that cannot compile a SIMD module
 *
 * Checks, in order:
 *   1. digest vectors    -- full digests against node's SHA-256 (wasm only;
 *                           the JS solver exposes no digest entry point)
 *   2. agreement         -- solve() returns the same index as brute force
 *   3. carry boundaries  -- the same, across the powers of ten where the
 *                           nonce's decimal width grows and the block is
 *                           rebuilt
 *   4. real solves       -- every returned nonce re-verified independently
 *   5. throughput
 *
 * Exit status is non-zero if any check fails.
 */

import fs from 'fs';
import path from 'node:path';
import crypto from 'crypto';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

/* The module under test, and the wasm beside it, so this suite grades the
   build it is given rather than always dist/. */
const MODULE = process.argv[2]
    ? pathToFileURL(process.argv[2])
    : new URL('../dist/antibot.js', import.meta.url);
const WASM = new URL('pow_solver.wasm', MODULE);
const MODULE_NAME = process.argv[2] || 'dist/antibot.js';
const WASM_NAME = path.join(path.dirname(MODULE_NAME), 'pow_solver.wasm');

for (const [file, label] of [[WASM, WASM_NAME], [MODULE, MODULE_NAME]]) {
    if (!fs.existsSync(file)) {
        console.error(label + ' not found. This suite runs against a build; ' +
                      'run ./build.sh first, or pass the module to grade as ' +
                      'the first argument.\n' +
                      'usage: node test/solver.test.mjs [module]');
        process.exit(2);
    }
}

let failures = 0;
let claimed = 0;

/* Each check below is a named test, so a throw fails that one and the rest
   still run. check() keeps counting, so a test reports all of its failures
   rather than stopping at the first. */
const section = (name, fn) => test(name, async () => {
    const before = failures;
    await fn();
    if (failures > before) {
        claimed += failures - before;
        throw new Error((failures - before) + ' check(s) failed');
    }
});
const fail = (msg) => { failures++; console.log("  FAIL: " + msg); };

const realDigest = (ch, n) => crypto.createHash('sha256').update(ch + ':' + n).digest('hex');
function meetsBits(hex, bits) {
    const full = bits >> 2, rem = bits & 3;
    if (hex.slice(0, full) !== '0'.repeat(full)) return false;
    if (rem && (parseInt(hex[full], 16) >> (4 - rem)) !== 0) return false;
    return true;
}
function bruteForce(ch, start, count, bits) {
    for (let n = start; n < start + count; n++) {
        if (meetsBits(realDigest(ch, n), bits)) return n - start;
    }
    return 0xFFFFFFFF;
}

/* --- the two solvers, behind one interface: load(challenge) -> {solve} --- */

function wasmSolver() {
    const x = new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(WASM)), {}).exports;
    return {
        load(ch) {
            for (let i = 0; i < 64; i++) x.set_byte(i, ch.charCodeAt(i));
            x.init();
            return { solve: (s, c, b) => x.solve(s, c, b) >>> 0 };
        },
        digest(nonce) {
            let hex = '';
            for (let i = 0; i < 8; i++) hex += (x.digest_word(nonce, i) >>> 0).toString(16).padStart(8, '0');
            return hex;
        }
    };
}

/* Lift POW_JS_SOLVER out of the njs module and evaluate it, so this tests the
   exact source the challenge page ships rather than a copy. */
function jsSolverFromModule() {
    const src = fs.readFileSync(MODULE, 'utf8');
    const from = src.indexOf('const POW_JS_SOLVER =');
    const to   = src.indexOf('const WORKER_TEMPLATE =');
    if (from < 0 || to < 0) { fail('could not locate POW_JS_SOLVER in ' + MODULE_NAME); return null; }
    const expr = src.slice(from, to).replace(/^const POW_JS_SOLVER =/, '').trim().replace(/;$/, '');
    const code = new Function('return (' + expr + ')')();
    const make = new Function(code + '; return jsSolver;')();
    let current = null;
    return {
        load(ch) {
            current = make(ch);
            return { solve: (st, c, b) => current.solve(st, c, b) };
        },
        digest: (nonce) => current.digest(nonce)
    };
}

/* --- checks --- */

function checkVectors(name, impl) {
    const nonces = [0, 1, 9, 10, 99, 100, 1000, 65535, 1048576, 12345678,
                    999999999, 4294967295, 4294967296, 274877906944, 999999999999];
    let bad = 0, total = 0;
    for (let t = 0; t < 50; t++) {
        const ch = crypto.randomBytes(32).toString('hex');
        impl.load(ch);
        for (const n of nonces) {
            total++;
            if (impl.digest(n) !== realDigest(ch, n)) bad++;
        }
    }
    if (bad) fail(name + ": " + bad + "/" + total + " digest vectors wrong");
    console.log("  " + name + " digest vectors: " + (total - bad) + "/" + total);
}

function checkAgreement(name, impl) {
    let bad = 0, total = 0;
    for (let t = 0; t < 40; t++) {
        const ch = crypto.randomBytes(32).toString('hex');
        const s = impl.load(ch);
        for (const bits of [8, 10]) {
            total++;
            const got = s.solve(0, 400, bits), want = bruteForce(ch, 0, 400, bits);
            if (got !== want) { bad++; fail(name + ": bits=" + bits + " got=" + got + " want=" + want); }
        }
    }
    console.log("  " + name + " agreement with brute force: " + (total - bad) + "/" + total);
}

function checkCarries(name, impl) {
    const ch = crypto.randomBytes(32).toString('hex');
    const s = impl.load(ch);
    const ranges = [[0,300],[1,300],[7,101],[95,20],[995,20],[9995,20],[99995,20],
                    [999995,20],[9999995,20],[99999995,20],[999999995,20],
                    [9999999995,20],[1000000-3,7],[4294967290,12]];
    let bad = 0, total = 0;
    for (const [start, count] of ranges) {
        for (const bits of [8, 11, 14]) {
            total++;
            const got = s.solve(start, count, bits), want = bruteForce(ch, start, count, bits);
            if (got !== want) {
                bad++;
                fail(name + ": start=" + start + " count=" + count + " bits=" + bits +
                     " got=" + got + " want=" + want);
            }
        }
    }
    console.log("  " + name + " carry boundaries: " + (total - bad) + "/" + total);
}

function checkRealSolves(name, impl) {
    let bad = 0;
    for (let t = 0; t < 10; t++) {
        const ch = crypto.randomBytes(32).toString('hex');
        const s = impl.load(ch);
        let n = 0, found = -1;
        while (found < 0 && n < 3e7) {
            const r = s.solve(n, 1e6, 18);
            if (r !== 0xFFFFFFFF) found = n + r; else n += 1e6;
        }
        if (found < 0 || !meetsBits(realDigest(ch, found), 18)) bad++;
    }
    if (bad) fail(name + ": " + bad + "/10 real solves invalid");
    console.log("  " + name + " real solves at 18 bits: " + (10 - bad) + "/10 verified");
}

function benchmark(name, impl) {
    const s = impl.load(crypto.randomBytes(32).toString('hex'));
    s.solve(0, 2e6, 32);
    const BATCH = 4e6, REPS = 5, rates = [];
    for (let r = 0; r < REPS; r++) {
        const t = process.hrtime.bigint();
        s.solve(r * BATCH, BATCH, 32);
        rates.push(BATCH / (Number(process.hrtime.bigint() - t) / 1e9));
    }
    rates.sort((a, b) => a - b);
    console.log("  " + name + " throughput: " + (rates[2] / 1e6).toFixed(2) + "M hashes/sec (median of " + REPS + ")");
    return rates[2];
}

/* The two solvers are checked against node's SHA-256 separately above. A
   misreading of the message layout shared by both would pass those, so they
   are also compared against each other, over the same challenges and the same
   ranges. */
function checkDifferential(a, b) {
    let bad = 0, total = 0;
    for (let t = 0; t < 30; t++) {
        const ch = crypto.randomBytes(32).toString('hex');
        const sa = a.impl.load(ch), sb = b.impl.load(ch);
        for (const n of [0, 7, 99, 1000, 99999, 4294967296, 999999999999]) {
            total++;
            if (a.impl.digest(n) !== b.impl.digest(n)) bad++;
        }
        for (const [start, count] of [[0, 400], [995, 20], [999995, 20], [4294967290, 12]]) {
            for (const bits of [8, 12]) {
                total++;
                if ((sa.solve(start, count, bits) >>> 0) !== (sb.solve(start, count, bits) >>> 0)) bad++;
            }
        }
    }
    if (bad) fail('the two solvers disagree in ' + bad + '/' + total + ' comparisons');
    console.log('  differential wasm vs JS: ' + (total - bad) + '/' + total + ' agree');
}

/*
 * The verifier and the solvers decide difficulty differently: the module
 * counts leading zero bits across a hex digest, the solvers test the first
 * output word. They must agree for every difficulty the module accepts.
 *
 * End-to-end runs cover a handful of difficulties, and cannot cover
 * POW_BITS_MAX at all, because solving at 32 bits is not something a test can
 * do. Comparing the predicates costs nothing and covers all of them.
 */
function checkPredicates() {
    const src = fs.readFileSync(MODULE, 'utf8');
    const from = src.indexOf('function hex_has_leading_zero_bits');
    const to = src.indexOf('function pow_valid');
    if (from < 0 || to < 0) {
        fail('could not locate hex_has_leading_zero_bits in ' + MODULE_NAME);
        return;
    }
    const verifier = new Function(src.slice(from, to) +
                                  '; return hex_has_leading_zero_bits;')();
    /* What the solvers test: the top `bits` of the first output word. */
    const solver = (hex, bits) =>
        ((parseInt(hex.slice(0, 8), 16) >>> 0) >>> (32 - bits)) === 0;

    const digests = [];
    for (let i = 0; i < 3000; i++) {
        digests.push(crypto.randomBytes(32).toString('hex'));
    }
    /* Boundaries: an all-zero word, the smallest non-zero, a full nibble, and
       the two sides of the top bit. */
    for (const head of ['00000000', '00000001', '0000000f', '00001000',
                        '7fffffff', '80000000', 'ffffffff']) {
        digests.push(head + '0'.repeat(56));
        digests.push(head + 'f'.repeat(56));
    }

    let bad = 0, total = 0;
    for (const hex of digests) {
        for (let bits = 1; bits <= 32; bits++) {
            total++;
            if (verifier(hex, bits) !== solver(hex, bits)) {
                if (bad === 0) {
                    fail('predicates disagree at bits=' + bits + ' for ' +
                         hex.slice(0, 8));
                }
                bad++;
            }
        }
    }
    console.log('  verifier vs solver predicate: ' + (total - bad) + '/' + total +
                ' agree, difficulties 1 to 32');
}

const impls = [
    ['wasm SIMD', wasmSolver(), WASM_NAME + ' (' + fs.statSync(WASM).size + ' bytes)'],
    ['pure JS  ', jsSolverFromModule(), 'POW_JS_SOLVER in ' + MODULE_NAME],
];

const rates = {};
for (const [name, impl, where] of impls) {
    /* Both loaders call fail() before returning null, and wasmSolver() throws
       on a module that will not instantiate, so a solver cannot drop out of
       this loop quietly. */
    console.log(where);
    await section(name.trim() + ": digest vectors", () => checkVectors(name, impl));
    await section(name.trim() + ": index agreement", () => checkAgreement(name, impl));
    await section(name.trim() + ": carry boundaries", () => checkCarries(name, impl));
    await section(name.trim() + ": real solves", () => checkRealSolves(name, impl));
    rates[name.trim()] = benchmark(name, impl);
    console.log("");
}

await section("verifier and solver predicates agree", checkPredicates);
console.log("");

const byName = Object.fromEntries(impls.filter(i => i[1]).map(([n, impl]) => [n.trim(), { impl }]));
if (byName['wasm SIMD'] && byName['pure JS']) {
    await section('wasm and JS solvers agree',
                  () => checkDifferential(byName['wasm SIMD'], byName['pure JS']));
    console.log("");
}

if (rates['wasm SIMD'] && rates['pure JS']) {
    console.log("SIMD is " + (rates['wasm SIMD'] / rates['pure JS']).toFixed(2) +
                "x the JS fallback (" +
                (Math.log2(rates['wasm SIMD'] / rates['pure JS'])).toFixed(1) + " bits)");
}
await test("every check ran inside a named test", () => {
    if (failures > claimed) {
        throw new Error((failures - claimed) + ' check(s) failed outside a test');
    }
});

console.log(failures ? "\n" + failures + " FAILURE(S)" : "\nall checks passed");
