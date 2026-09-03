/*
 * Runs the challenge page's inline script in a stub environment.
 *
 * The page script is the only code that touches document, navigator, Worker,
 * Blob and URL.createObjectURL. Parsing it proves nothing, so this provides
 * just enough of those to execute it: Blob keeps the worker source,
 * createObjectURL hands back a token for it, and Worker runs that source in a
 * real thread through the same shim the other tests use.
 *
 * Resolves with the cookies the page set, once it calls location.reload().
 */

import { Worker as NodeWorker } from 'node:worker_threads';

const SHIM = `
import { parentPort, workerData } from 'node:worker_threads';
const self_ = { postMessage: (m) => parentPort.postMessage(m), onmessage: null };
new Function("self", workerData.src)(self_);
parentPort.on('message', (d) => { if (self_.onmessage) self_.onmessage({ data: d }); });
`;

export function runChallengePage(html, options = {}) {
    const cores = options.cores === undefined ? 4 : options.cores;
    const timeoutMs = options.timeoutMs === undefined ? 120000 : options.timeoutMs;
    const withWebAssembly = options.withWebAssembly !== false;
    const failWorkers = options.failWorkers === true;
    /* A browser that did not reach the page over HTTPS discards a
       __Host- Secure cookie without an error. */
    const refuseCookies = options.refuseCookies === true;

    const script = /<script>\n([\s\S]*?)<\/script>/.exec(html)[1];

    return new Promise((resolve, reject) => {
        const sources = new Map();
        const workers = [];
        const cookies = [];
        const violations = [];
        const settle = (extra) => finish(() => resolve({
            cookies: cookies.slice(),
            progress: elements.pct.textContent,
            violations: violations.slice(),
            workers: workers.length,
            ...extra
        }));
        const elements = {
            pct: { textContent: '' },
            /* The page reveals this element to report failure. Resolving here
               reports it at once rather than through the timeout. */
            err: {
                stored: true,
                get hidden() { return this.stored; },
                set hidden(value) {
                    this.stored = value;
                    if (value === false) settle({ failed: true });
                }
            }
        };
        let seq = 0, settled = false, timer = null;

        const finish = (fn) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            Promise.all(workers.map((w) => w.terminate().catch(() => {}))).then(fn, fn);
        };

        class BlobStub {
            constructor(parts) { this.source = parts.join(''); }
        }
        const URLStub = {
            createObjectURL(blob) {
                const token = 'blob:' + (++seq);
                sources.set(token, blob.source);
                return token;
            },
            revokeObjectURL() {}
        };
        class WorkerStub {
            constructor(token) {
                this.onmessage = null;
                this.onerror = null;
                if (failWorkers) {
                    /* Drives the page's onerror path, which no other case
                       reaches. */
                    this.node = { postMessage() {}, terminate: () => Promise.resolve(),
                                  on() {} };
                    workers.push(this.node);
                    setTimeout(() => { if (this.onerror) this.onerror(new Error('worker failed')); }, 0);
                    return;
                }
                this.node = new NodeWorker(SHIM, {
                    eval: true, workerData: { src: sources.get(token) }
                });
                this.node.on('message', (m) => { if (this.onmessage) this.onmessage({ data: m }); });
                this.node.on('error', (e) => { if (this.onerror) this.onerror(e); });
                workers.push(this.node);
            }
            postMessage(m) { this.node.postMessage(m); }
            terminate() { this.node.terminate(); }
        }

        /* A browser rejects a __Host- cookie that is not Secure, is not
           Path=/, or carries a Domain. Accepting anything here would let a
           cookie pass the test that no browser would store. */
        const documentStub = {
            getElementById: (id) => elements[id] || null,
            set cookie(value) {
                const name = value.split('=')[0].trim();
                if (name.startsWith('__Host-')) {
                    if (!/;\s*Secure/i.test(value)) violations.push('no Secure: ' + name);
                    if (!/;\s*Path=\/(;|$)/i.test(value)) violations.push('Path is not /: ' + name);
                    if (/;\s*Domain=/i.test(value)) violations.push('has Domain: ' + name);
                }
                if (refuseCookies) return;
                cookies.push(value);
            },
            /* A browser returns name=value pairs, without the attributes. */
            get cookie() {
                return cookies.map((c) => c.split(';')[0]).join('; ');
            }
        };
        const locationStub = { reload() { settle({ failed: false }); } };
        const navigatorStub = { hardwareConcurrency: cores };
        const windowStub = {
            Worker: WorkerStub, Blob: BlobStub, URL: URLStub,
            WebAssembly: withWebAssembly ? WebAssembly : undefined
        };

        timer = setTimeout(() => {
            finish(() => reject(new Error('the page did not finish within ' + timeoutMs + 'ms')));
        }, timeoutMs);

        try {
            new Function(
                'window', 'document', 'navigator', 'location',
                'Worker', 'Blob', 'URL', 'WebAssembly', 'atob', 'setTimeout',
                script
            )(
                windowStub, documentStub, navigatorStub, locationStub,
                WorkerStub, BlobStub, URLStub,
                withWebAssembly ? WebAssembly : undefined, atob, setTimeout
            );
        } catch (err) {
            finish(() => reject(err));
        }
    });
}
