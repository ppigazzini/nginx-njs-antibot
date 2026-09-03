/*
 * Grades the suites, not the module.
 *
 *   node test/mutants.mjs [module]
 *
 * Each entry below is a defect and the suite that must notice it. The runner
 * writes the mutated module to a temporary directory with the wasm beside it,
 * runs that suite against it, and reports any mutation the suite let through.
 *
 * A test that cannot fail is worth nothing. This is what measures that.
 *
 * The list is fixed. A generated set has a different survivor list on every
 * run, which fails at random and teaches nothing.
 *
 * Two defects are left out because the suite that catches them is the nginx
 * lane in CI, which needs a server: dropping the nosniff header and dropping
 * the no-store header. Both are grepped for there.
 */

import fs from 'fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const MODULE = process.argv[2] || path.join(ROOT, 'dist', 'antibot.js');
const WASM = path.join(path.dirname(MODULE), 'pow_solver.wasm');

for (const f of [MODULE, WASM]) {
    if (!fs.existsSync(f)) {
        console.error(f + ' not found. This runs against a build; run ./build.sh first.\n' +
                      'usage: node test/mutants.mjs [module]');
        process.exit(2);
    }
}

const SUITES = {
    solver: 'test/solver.test.mjs',
    module: 'test/module.test.mjs',
    fuzz:   'test/module-fuzz.mjs',
};

const MUTANTS = [
    ['accept only the current slot', 'module',
     [['if (parsed.slot !== slot && parsed.slot !== slot - 1) {',
       'if (parsed.slot !== slot) {']]],
    ['accept two slots back', 'module',
     [['if (parsed.slot !== slot && parsed.slot !== slot - 1) {',
       'if (parsed.slot !== slot && parsed.slot !== slot - 1 && parsed.slot !== slot - 2) {']]],
    ['verification always passes', 'module',
     [['        if (!pow_valid(challenge, parsed.nonce)) {',
       '        if (false) {']]],
    /* The fuzzer's accept pass must still notice a gate that takes anything,
       now that it verifies against the slot the cookie carries rather than
       the current one. Widening which slots are accepted is not listed here:
       the fuzzer would need a random nonce to land valid, which happens about
       a fifth of a time per run. The module suite kills that one. */
    ['verification always passes, seen by the fuzzer', 'fuzz',
     [['        if (!pow_valid(challenge, parsed.nonce)) {',
       '        if (false) {']]],
    ['difficulty ignores the remainder bits', 'solver',
     [['    if (remainder && (parseInt(hex[full_nibbles], 16) >> (4 - remainder)) !== 0) {',
       '    if (false) {']]],
    ['identity is not clipped', 'module',
     [['    return text.length > IDENTITY_FIELD_MAX',
       '    return false && text.length > IDENTITY_FIELD_MAX']]],
    ['IPv6 is not aggregated to a /64', 'module',
     [['    return groups.slice(0, 4).join(":") + "::/64";',
       '    return groups.join(":");']]],
    ['only one cookie candidate', 'module',
     [['const MAX_COOKIE_CANDIDATES = 4;',
       'const MAX_COOKIE_CANDIDATES = 1;']]],
    ['re-screening disabled', 'module',
     [['const RESCREEN_RATE = 0.02;',
       'const RESCREEN_RATE = 0;']]],
    ['the site name is not escaped', 'module',
     [['function escape_html(text) {',
       'function escape_html(text) { return text; ']]],
    ['nothing is a document request', 'module',
     [['    return !dest || dest === "document";',
       '    return false;']]],
    ['the secret length is unchecked', 'fuzz',
     [['    return SECRET.length >= 32;',
       '    return true;']]],
    ['the counters do not count an acceptance', 'module',
     [['        count("accepted");', '        ;']]],
    ['the counters do not count a challenge', 'module',
     [['    count("challenges");', '    ;']]],
    /* The guard is removed as well as the throw added: inside the try the
       module absorbs it, which is the behaviour, not a defect. */
    ['counting a full zone refuses the request', 'module',
     [[`    try {
        dict.incr(name, 1, 0);
    } catch (err) {
        // The zone is full or the wrong type. The gate does not depend on it.
    }`,
       `    dict.incr(name, 1, 0);
    throw new Error("the zone is full");`]]],
    ['the logged field is not encoded', 'module',
     [['          " uri=" + log_field(r.uri));',
       '          " uri=" + r.uri);']]],
    /* These two carry a second edit that removes the check which would
       otherwise absorb the first, so the suite has to notice the behaviour
       rather than the validation. */
    ['re-screening on every navigation, unchecked', 'module',
     [['const RESCREEN_RATE = 0.02;', 'const RESCREEN_RATE = 1;'],
      ['if (typeof v !== "number" || !isFinite(v) || v < 0 || v >= 1) {',
       'if (false) {']]],
    ['cookie lifetime below the window, unchecked', 'module',
     [['const COOKIE_TTL = 2 * WINDOW_SIZE;', 'const COOKIE_TTL = 1;'],
      ['if (typeof v !== "number" || !isFinite(v) || Math.floor(v) !== v || v < floor) {',
       'if (false) {']]],
];

const base = fs.readFileSync(MODULE, 'utf8');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'antibot-mutants-'));
fs.copyFileSync(WASM, path.join(dir, 'pow_solver.wasm'));
const env = { ...process.env };
if (!env.ANTIBOT_SECRET || env.ANTIBOT_SECRET.length < 32) {
    env.ANTIBOT_SECRET = '0'.repeat(64);
}

let survived = 0, missing = 0, seq = 0;
for (const [name, suite, edits] of MUTANTS) {
    let text = base, lost = null;
    for (const [find, replace] of edits) {
        const hits = text.split(find).length - 1;
        if (hits !== 1) { lost = find + ' (' + hits + ' matches)'; break; }
        text = text.replace(find, replace);
    }
    if (lost) {
        missing++;
        console.log('  ANCHOR  ' + name + ': ' + lost);
        continue;
    }
    const file = path.join(dir, 'm' + (seq++) + '.js');
    fs.writeFileSync(file, text);
    let killed = false;
    try {
        execFileSync('node', [SUITES[suite], file],
                     { cwd: ROOT, env, stdio: 'pipe', timeout: 900000 });
    } catch {
        killed = true;
    }
    if (killed) {
        console.log('  killed  ' + name.padEnd(38) + ' by ' + SUITES[suite]);
    } else {
        survived++;
        console.log('  SURVIVED ' + name.padEnd(37) + ' ' + SUITES[suite] +
                    ' passed against it');
    }
}

fs.rmSync(dir, { recursive: true, force: true });
const bad = survived + missing;
console.log('\n' + MUTANTS.length + ' mutations: ' + (MUTANTS.length - bad) +
            ' caught, ' + survived + ' survived, ' + missing + ' anchors lost');
process.exit(bad ? 1 : 0);
