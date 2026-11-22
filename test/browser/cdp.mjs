/*
 * A headless Chromium driven over the DevTools protocol, with no dependency:
 * node's WebSocket client speaks the protocol and node:http serves the pages.
 *
 * launch(binary, flags) starts the browser on a fresh profile and resolves
 * with { page(url), close() }. page() opens a tab and resolves with
 * evaluate(expression), which awaits a promise the expression returns and
 * gives back its value. close() resolves once the browser has exited and its
 * profile is removed: a browser still exiting writes into the profile, and
 * removing it then fails.
 *
 * Every call rejects rather than waits when the connection closes, errors or
 * outlives CALL_TIMEOUT_MS, so a crashed browser fails the harness with a
 * reason instead of holding it until the job times out.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const CALL_TIMEOUT_MS = 600000;

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
            /* The line ends the address, so one cut at a chunk boundary is
               not taken. */
            const m = /DevTools listening on (ws:\/\/\S+)\r?\n/.exec(seen);
            if (m) resolve(m[1]);
        });
        browser.on('exit', (code) => reject(new Error(binary + ' exited with ' + code +
                                                      ': ' + seen.slice(0, 400))));
    });
    const ws = new WebSocket(endpoint);
    let id = 0;
    let broken = null;
    const pending = new Map();
    const breakAll = (why) => {
        broken = broken || new Error(why);
        for (const [, p] of pending) p.reject(broken);
        pending.clear();
    };
    await new Promise((resolve, reject) => {
        ws.onopen = resolve;
        ws.onerror = () => reject(new Error('could not connect to ' + endpoint));
    });
    ws.onerror = () => breakAll('the DevTools connection failed');
    ws.onclose = () => breakAll('the DevTools connection closed');
    browser.on('exit', (code) => breakAll(binary + ' exited with ' + code));
    ws.onmessage = (event) => {
        const m = JSON.parse(event.data);
        if (m.id && pending.has(m.id)) {
            pending.get(m.id).resolve(m);
            pending.delete(m.id);
        }
    };
    const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
        if (broken) {
            reject(broken);
            return;
        }
        const n = ++id;
        const timer = setTimeout(() => {
            pending.delete(n);
            reject(new Error(method + ' took longer than ' + CALL_TIMEOUT_MS + ' ms'));
        }, CALL_TIMEOUT_MS);
        pending.set(n, {
            resolve: (m) => { clearTimeout(timer); resolve(m); },
            reject: (e) => { clearTimeout(timer); reject(e); }
        });
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
        async close() {
            ws.close();
            if (browser.exitCode === null && browser.signalCode === null) {
                const exited = new Promise((resolve) => browser.once('exit', resolve));
                browser.kill();
                await exited;
            }
            fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
        }
    };
}
