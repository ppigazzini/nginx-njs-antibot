/*
 * Reads a challenge page on stdin, solves it, and prints the cookie as
 * name=value. Used by the nginx lane to exercise the accept path, which
 * otherwise never runs under njs.
 */

import { runChallengePage } from './page-runner.mjs';

const html = await new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
});

if (!/<script>\n[\s\S]*?<\/script>/.test(html)) {
    console.error('input is not a challenge page (' + html.length +
                  ' bytes). First line: ' + html.split('\n')[0].slice(0, 200));
    process.exit(1);
}

const out = await runChallengePage(html, { cores: 4, timeoutMs: 120000 });
if (out.failed || out.cookies.length !== 1) {
    console.error('the page did not produce a cookie');
    process.exit(1);
}
process.stdout.write(out.cookies[0].split(';')[0]);
