// SPDX-License-Identifier: BSD-3-Clause
// Headless verification of the in-page x86 interpreter.
// Same pass criterion as verify_qemu.py: 3 white, 6 white, 9 green in VGA text memory.
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const vm = require('vm');
const html = fs.readFileSync(__dirname + '/index.html', 'utf8');

// slice 1: PAYLOAD_HEX + BIN construction
const s1 = html.match(/const PAYLOAD_HEX =[\s\S]*?BIN\[510\] = 0x55; BIN\[511\] = 0xAA;/)[0];
// slice 2: the CPU interpreter IIFE (ends right before the VGA renderer comment)
const s2 = html.match(/const CPU = \(\(\) => \{[\s\S]*?\}\)\(\);\n\n\/\* VGA text renderer \*\//)[0]
               .replace(/\n\n\/\* VGA text renderer \*\//, '');

const sandbox = {Uint8Array, parseInt};
vm.runInNewContext(s1 + '\n' + s2 + '\nresult = {CPU, BIN};', sandbox, {timeout: 1000});
const boot = sandbox.result;
const CPU = boot.CPU;
const disk = fs.readFileSync(__dirname + '/../basmos.bin');
const identical = disk.length === boot.BIN.length && disk.every((b, i) => b === boot.BIN[i]);

CPU.reset();
CPU.run(2000000);
const v = CPU.vram(), s = CPU.stats(), domains = CPU.domains(), heartbeat = CPU.heartbeat();

const got  = Array.from(v.slice(0, 6), b => '0x' + b.toString(16).padStart(2, '0'));
const want = ['0x33', '0x0f', '0x36', '0x0f', '0x39', '0x0a'];
const names = ['task0 "3" char @B8000', 'task0 attr white',
               'task1 "6" char @B8002', 'task1 attr white',
               'IPC  "9" char @B8004',  'IPC  attr green'];
let pass = true;
for (let i = 0; i < 6; i++) {
  const ok = got[i] === want[i]; pass = pass && ok;
  console.log('  [' + (ok ? 'PASS' : 'FAIL') + '] ' + names[i] + ': got=' + got[i] + ' want=' + want[i]);
}
const siteClaims = [
  ['JASH capture gallery', 'CAPTURE 01 · IDENTITY'],
  ['immutable SELECT capture', 'PACK WRITES · 0'],
  ['current nucleus budget', 'PRF1|ARTIFACT|JASH|253|3|FF'],
  ['current JASH hash', '5cceb51d8037f790943b4ddc5df42e70025188daa'],
];
for (const [name, claim] of siteClaims) {
  const ok = html.includes(claim); pass = pass && ok;
  console.log('  [' + (ok ? 'PASS' : 'FAIL') + '] site: ' + name);
}
console.log('  crash: ' + (s.crash ? JSON.stringify(s.crash) : 'none'));
console.log('  telemetry: ' + s.insns + ' insns / ' + s.ticks + ' timer irqs / ' +
             s.yields + ' yields / ' + s.sends + ' sends / ' + s.recvs + ' recvs');
console.log('  heartbeat: ' + heartbeat + ' (== ticks: ' +
            (heartbeat === s.ticks) + ')');
const ownDomains = domains.task0 === 0x33 && domains.task1 === 0x39;
console.log('  [' + (ownDomains ? 'PASS' : 'FAIL') + '] private domains: task0=' +
            domains.task0.toString(16).padStart(2, '0') + ' task1=' +
            domains.task1.toString(16).padStart(2, '0'));
console.log('  artifact: ' + (identical ? 'website bytes match basmos.bin' : 'MISMATCH'));
pass = pass && !s.crash && identical && s.ticks > 0 && s.yields === 0
        && heartbeat === s.ticks && ownDomains;

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basmos-js-domain-'));
try {
  const faultPath = path.join(tmp, 'fault.bin');
  const mapPath = path.join(tmp, 'fault.map');
  childProcess.execFileSync(__dirname + '/../basm-nano/basm-nano',
    ['-f', 'bin', '-DDOMAIN_FAULT_PROBE', '--map', mapPath,
     '-o', faultPath, 'basmos.basm'],
    {cwd: __dirname + '/..'});
  const gpOffset = Number(fs.readFileSync(mapPath, 'utf8').match(/^\s*(\d+)\s+\d+\s+gp_handler$/m)[1]);
  const faultOffset = Number(fs.readFileSync(mapPath, 'utf8').match(/^\s*(\d+)\s+\d+\s+domain_fault$/m)[1]);
  CPU.reset(Uint8Array.from(fs.readFileSync(faultPath)));
  CPU.run(10000);
  const fault = CPU.stats(), denied = CPU.domains(), state = CPU.state();
  const gp = !fault.crash && fault.halted && fault.lastException === 13
             && state.eip === 0x7C00 + gpOffset + 1
             && state.frame[0] === 0 && state.frame[1] === 0x7C00 + faultOffset
             && state.frame[2] === 8
             && fault.ticks === 0 && denied.task0 === 0x33 && denied.task1 === 0;
  pass = pass && gp;
  console.log('  [' + (gp ? 'PASS' : 'FAIL') + '] browser segment limit: ' +
              'DS:[0x100] -> #GP' + fault.lastException + ', peer=' +
              denied.task1.toString(16).padStart(2, '0'));
} finally {
  fs.rmSync(tmp, {recursive: true, force: true});
}
console.log(pass
  ? 'RESULT: PASS - in-page interpreter boots the real 512 bytes'
  : 'RESULT: FAIL');
process.exit(pass ? 0 : 1);
