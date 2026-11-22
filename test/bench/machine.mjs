/*
 * The machine a figure is measured on, which docs/ names beside every figure:
 * the CPU model, the logical CPUs the process may run on, and whether that is
 * all of them. Each harness prints it first.
 */

import fs from 'node:fs';
import os from 'node:os';

export function machine() {
    const cpus = os.cpus();
    let allowed = null;
    try {
        const m = /^Cpus_allowed_list:\s*(\S+)$/m.exec(fs.readFileSync('/proc/self/status', 'utf8'));
        if (m) allowed = m[1];
    } catch {
        // Not Linux: the affinity is not readable here.
    }
    const all = '0-' + (cpus.length - 1);
    return cpus[0].model.trim() + ', ' + cpus.length + ' logical CPUs, ' +
        (allowed === null ? 'affinity unknown'
            : 'running on ' + allowed + (allowed === all ? ', not pinned' : ''));
}
