/*
 * A headless Chromium driven over the DevTools protocol, with no dependency:
 * node's WebSocket client speaks the protocol and node:http serves the pages.
 *
 * launch(binary, flags) starts the browser on a fresh profile and resolves
 * with { page(url), close() }. page() opens a tab and resolves with
 * evaluate(expression), which awaits a promise the expression returns and
 * gives back its value.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

export async function launch(binary, flags = []) {
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'antibot-chromium-'));
    const browser = spawn(binary, ['--headless', '--remote-debugging-port=0',
                                   '--no-first-run', '--user-data-dir=' + profile,
                                   ...flags, 'about:blank'],
                          { stdio: ['ignore', 'ignore', 'pipe'] });
    const endpoint = await new Promise((resolve, reject) => {
        let seen = '';
        browser.stderr.on('data', (chunk) => {
            seen += chunk;
            const m = /ws:\/\/\S+/.exec(seen);
            if (m) resolve(m[0]);
        });
        browser.on('exit', (code) => reject(new Error(binary + ' exited with ' + code +
                                                      ': ' + seen.slice(0, 400))));
    });
    const ws = new WebSocket(endpoint);
    await new Promise((resolve) => { ws.onopen = resolve; });
    let id = 0;
    const pending = new Map();
    ws.onmessage = (event) => {
        const m = JSON.parse(event.data);
        if (m.id && pending.has(m.id)) {
            pending.get(m.id)(m);
            pending.delete(m.id);
        }
    };
    const call = (method, params = {}, sessionId) => new Promise((resolve) => {
        const n = ++id;
        pending.set(n, resolve);
        ws.send(JSON.stringify({ id: n, method, params, sessionId }));
    });

    return {
        async page(url) {
            const target = await call('Target.createTarget', { url });
            const attached = await call('Target.attachToTarget',
                                        { targetId: target.result.targetId, flatten: true });
            const sessionId = attached.result.sessionId;
            return {
                async evaluate(expression) {
                    const out = await call('Runtime.evaluate', {
                        expression, awaitPromise: true, returnByValue: true
                    }, sessionId);
                    if (out.result.exceptionDetails) {
                        throw new Error(JSON.stringify(out.result.exceptionDetails).slice(0, 400));
                    }
                    return out.result.result.value;
                }
            };
        },
        close() {
            ws.close();
            browser.kill();
            fs.rmSync(profile, { recursive: true, force: true });
        }
    };
}
