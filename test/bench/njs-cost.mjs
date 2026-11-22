/*
 * Server cost per request under nginx and njs: the harness behind the njs
 * figures in docs/security.md.
 *
 *   taskset -c 2,6 node test/bench/njs-cost.mjs [module]
 *   NGINX_MODULES=/path/to/modules taskset -c 2,6 node test/bench/njs-cost.mjs
 *
 * Starts nginx from PATH with one worker under a temporary prefix, plain HTTP
 * on loopback, and calls each handler through its own location, one request
 * at a time over one keep-alive connection. A handler's cost is the median
 * latency of its location minus the median of a location that returns 204
 * without njs, which takes out the client, the connection and nginx itself.
 * Each round sends REQUESTS requests to every location in turn, so drift in
 * the machine lands on all of them alike; the figure is over ROUNDS rounds.
 * The difficulty is 8 bits, so the harness solves its own cookie; verifying
 * costs the same at any difficulty. The challenge line is off, so no log
 * write is measured.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { machine } from './machine.mjs';

const MODULE = path.resolve(process.argv[2] || 'dist/antibot.js');
const ROUNDS = 7;
const REQUESTS = 500;
const PORT = 18490;

let modules = null;
for (const dir of [process.env.NGINX_MODULES, '/usr/lib/nginx/modules',
                   '/usr/lib64/nginx/modules', '/usr/local/nginx/modules',
                   '/usr/share/nginx/modules']) {
    if (dir && fs.existsSync(path.join(dir, 'ngx_http_js_module.so'))) {
        modules = dir;
        break;
    }
}
if (!modules || !fs.existsSync(MODULE)) {
    console.error((modules ? MODULE : 'ngx_http_js_module.so') + ' not found');
    process.exit(2);
}

const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'antibot-njs-cost-'));
fs.mkdirSync(path.join(prefix, 'logs'));
fs.copyFileSync(MODULE, path.join(prefix, 'antibot.js'));
fs.writeFileSync(path.join(prefix, 'version.js'),
                 'function njs_version(r) { r.return(200, njs.version); }\n' +
                 'export default { njs_version };\n');
const temp = ['client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi']
    .map((t) => t + '_temp_path ' + prefix + '/logs;').join(' ');
fs.writeFileSync(path.join(prefix, 'nginx.conf'), `
load_module ${modules}/ngx_http_js_module.so;
pid ${prefix}/nginx.pid;
error_log ${prefix}/logs/error.log error;
worker_processes 1;
env ANTIBOT_SECRET;
env ANTIBOT_POW_BITS;
env ANTIBOT_CHALLENGE_LOG_LEVEL;
events {}
http {
    access_log off;
    ${temp}
    js_path ${prefix};
    js_import antibot.js;
    js_import version.js;
    js_shared_dict_zone zone=antibot:32k type=number;
    server {
        listen 127.0.0.1:${PORT};
        keepalive_requests 1000000;
        location = /static  { return 204; }
        location = /check   { js_content antibot.check; }
        location = /page    { js_content antibot.serve_challenge; }
        location = /version { js_content version.njs_version; }
    }
}
`);
const nginx = (args) => execFileSync('nginx', ['-p', prefix, '-c', prefix + '/nginx.conf', ...args],
                                     { env: { ...process.env,
                                              ANTIBOT_SECRET: crypto.randomBytes(32).toString('hex'),
                                              ANTIBOT_POW_BITS: '8',
                                              ANTIBOT_CHALLENGE_LOG_LEVEL: 'off' },
                                       stdio: ['ignore', 'pipe', 'pipe'] });

const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
const get = (where, headers = {}) => new Promise((resolve, reject) => {
    const t = process.hrtime.bigint();
    http.get({ host: '127.0.0.1', port: PORT, path: where, agent,
               headers: { 'user-agent': 'njs-cost/1', 'accept-language': 'en', ...headers } },
             (res) => {
                 let body = '';
                 res.on('data', (d) => { body += d; });
                 res.on('end', () => resolve({
                     code: res.statusCode, body,
                     us: Number(process.hrtime.bigint() - t) / 1000
                 }));
             }).on('error', reject);
});
const median = (list) => list.slice().sort((a, b) => a - b)[list.length >> 1];

let started = false;
try {
    nginx([]);
    started = true;
    let up = false;
    for (let i = 0; i < 40 && !up; i++) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        up = await get('/static').then(() => true, () => false);
    }
    if (!up) throw new Error('nginx did not answer on ' + PORT);

    const page = (await get('/page')).body;
    const challenge = /var challenge="([0-9a-f]+)"/.exec(page)[1];
    const slot = /var slot="(\d+)"/.exec(page)[1];
    const name = /var v="([^"=]+)="/.exec(page)[1];
    let nonce = 0;
    while (!crypto.createHash('sha256').update(challenge + ':' + nonce)
                 .digest('hex').startsWith('00')) nonce++;
    const cases = [
        ['static, no njs', '/static', {}, 204],
        ['check(), no cookie', '/check', {}, 401],
        ['check(), a valid cookie', '/check', { cookie: name + '=' + slot + '.' + nonce }, 204],
        ['check(), one junk cookie', '/check', { cookie: name + '=' + slot + '.123456789' }, 401],
        ['serve_challenge()', '/page', {}, 200],
    ];
    for (const [label, where, headers, want] of cases) {
        const got = (await get(where, headers)).code;
        if (got !== want) throw new Error(label + ' answered ' + got + ', expected ' + want);
    }
    for (let i = 0; i < 1000; i++) await get('/static');

    const rounds = Object.fromEntries(cases.map(([label]) => [label, []]));
    for (let r = 0; r < ROUNDS; r++) {
        for (const [label, where, headers] of cases) {
            const lat = [];
            for (let i = 0; i < REQUESTS; i++) lat.push((await get(where, headers)).us);
            rounds[label].push(median(lat));
        }
    }

    console.log(machine());
    console.log(spawnSync('nginx', ['-v'], { encoding: 'utf8' }).stderr.trim() +
                ', njs ' + (await get('/version')).body + ', ' + ROUNDS + ' rounds of ' +
                REQUESTS + ' requests per location');
    const base = median(rounds['static, no njs']);
    for (const [label] of cases) {
        const m = median(rounds[label]);
        console.log(label.padEnd(26) + ' median ' + m.toFixed(1).padStart(8) + ' us' +
                    (label === 'static, no njs' ? '' : ', handler ' + (m - base).toFixed(1) + ' us'));
    }
} finally {
    agent.destroy();
    if (started) {
        try { nginx(['-s', 'stop']); } catch { /* already gone */ }
        await new Promise((resolve) => setTimeout(resolve, 300));
    }
    fs.rmSync(prefix, { recursive: true, force: true });
}
