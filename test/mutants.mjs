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
 * Three defects are left out because the suite that catches them is the
 * nginx lane in CI, which needs a server: dropping the nosniff header,
 * dropping the no-store header, and checking a value with an anchored
 * pattern, whose $ only njs lets match before a final newline.
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
    /* The second edit verifies an older cookie against its own slot's
       challenge, so a cookie solved two slots back passes and one relabelled
       there still fails on its nonce. */
    ['accept two slots back', 'module',
     [['if (parsed.slot !== slot && parsed.slot !== slot - 1) {',
       'if (parsed.slot !== slot && parsed.slot !== slot - 1 && parsed.slot !== slot - 2) {'],
      ['challenge_previous = expected_challenge(key, slot - 1);',
       'challenge_previous = expected_challenge(key, parsed.slot);']]],
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
    ['the site name is not escaped', 'module',
     [['function escape_html(text) {',
       'function escape_html(text) { return text; ']]],
    ['the challenge log level is ignored', 'module',
     [['function log_challenge(r, message) {',
       'function log_challenge(r, message) { r.log(message); return; ']]],
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
     [['                  " uri=" + log_field(r.variables.request_uri));',
       '                  " uri=" + r.variables.request_uri);']]],
    ['the log line names the internal location', 'module',
     [['                  " uri=" + log_field(r.variables.request_uri));',
       '                  " uri=" + log_field(r.uri));']]],
    ['POW_BITS is not clamped', 'module',
     [['        b = POW_BITS_MAX;', '        ;']]],
    ['Accept-Language is not clipped', 'module',
     [['    const lang = clip(r.headersIn["Accept-Language"] || "");',
       '    const lang = r.headersIn["Accept-Language"] || "";']]],
    ['a number is read with Number()', 'module',
     [['made_of(raw, /[^0-9]/, 1, 15) ? Number(raw) : NaN', 'Number(raw)']]],
    ['translated addresses share a /64', 'module',
     [['    if (groups[0] === "64" && groups[1] === "ff9b") {', '    if (false) {']]],
    ['Teredo clients share a /64', 'module',
     [['    if (groups[0] === "2001" && groups[1] === "0") {', '    if (false) {']]],
    ['a nonce at the cap is accepted', 'module',
     [['    if (Number(nonce) >= POW_MAX_ITERATIONS) {',
       '    if (Number(nonce) > POW_MAX_ITERATIONS) {']]],
    ['a report is not validated', 'module',
     [['    if ((solver !== "wasm" && solver !== "js") || !is_decimal(ms, 10)) {',
       '    if (false) {']]],
    ['a slow solve is not counted', 'module',
     [['        count("solved_slow");', '        ;']]],
    ['the page sends no report', 'module',
     [['navigator.sendBeacon(\\"', 'String(\\"']]],
    ['a warning is written once per zone, whatever it says', 'module',
     [['if (dict.get(CONFIG_WARNED_KEY) === digest) {',
       'if (dict.get(CONFIG_WARNED_KEY) !== undefined) {']]],
    ['the logged URI is not clipped', 'module',
     [['    const s = clip(String(text));', '    const s = String(text);']]],
    ['the workers skip every other block', 'module',
     [['stride=B*lanes,', 'stride=B*lanes*2,']]],
    ['the report path may name another host', 'module',
     [['v.charAt(0) === "/" && v.charAt(1) !== "/"', 'v.charAt(0) === "/"']]],
    /* This carries a second edit that removes the check which would
       otherwise absorb the first, so the suite has to notice the behaviour
       rather than the validation. */
    ['cookie lifetime below the window, unchecked', 'module',
     [['const COOKIE_TTL = null;', 'const COOKIE_TTL = 1;'],
      ['return v < floor ? "is below twice WINDOW_SIZE=" + floor : null;',
       'return null;']]],
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
