// SPDX-License-Identifier: BSD-3-Clause
// Headless verification of the in-page x86 interpreter.
// Same pass criterion as verify_qemu.py: 3 white, 6 white, 9 green in VGA text memory.
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const crypto = require('crypto');
const vm = require('vm');
const html = fs.readFileSync(__dirname + '/index.html', 'utf8');
let pass = true;
const check = (name, ok, detail = '') => {
  pass = pass && ok;
  console.log('  [' + (ok ? 'PASS' : 'FAIL') + '] ' + name + (detail ? ': ' + detail : ''));
};

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
const artifact = relative => fs.readFileSync(path.join(__dirname, '..', relative));
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const jash = artifact('jash/jash.bin');
const pack = artifact('jash/jash-pack.bin');
const routeSource = html.match(/const BASMOS_SECTIONS[\s\S]*?\nfunction setMeta/)[0]
                        .replace(/\nfunction setMeta$/, '');
const routeSandbox = {};
vm.runInNewContext(routeSource + '\nresult = resolveRoute;', routeSandbox, {timeout: 1000});
const resolveRoute = routeSandbox.result;

CPU.reset();
CPU.run(2000000);
const v = CPU.vram(), s = CPU.stats(), domains = CPU.domains(), heartbeat = CPU.heartbeat();
CPU.run(1);
const capped = CPU.stats();

const got  = Array.from(v.slice(0, 6), b => '0x' + b.toString(16).padStart(2, '0'));
const want = ['0x33', '0x0f', '0x36', '0x0f', '0x39', '0x0a'];
const names = ['task0 "3" char @B8000', 'task0 attr white',
               'task1 "6" char @B8002', 'task1 attr white',
               'IPC  "9" char @B8004',  'IPC  attr green'];
for (let i = 0; i < 6; i++) {
  check(names[i], got[i] === want[i], 'got=' + got[i] + ' want=' + want[i]);
}
const telemetry = {insns: 2000000, ticks: 44, yields: 0, sends: 126144, recvs: 22};
for (const [key, value] of Object.entries(telemetry)) {
  check('exact telemetry ' + key, s[key] === value, 'got=' + s[key] + ' want=' + value);
}
check('exact telemetry heartbeat', heartbeat === 44, 'got=' + heartbeat + ' want=44');
check('2,000,000 instruction hard cap', capped.insns === 2000000);
check('JASH artifact size', jash.length === 256, 'got=' + jash.length + ' want=256');
check('JASH artifact SHA-256', sha256(jash) === '3ed12f5d1d90d006522fab676e796441fb870e8b23083dfd6d1907f8693b536d');
check('J-Pack artifact size', pack.length === 3584, 'got=' + pack.length + ' want=3584');
check('J-Pack artifact SHA-256', sha256(pack) === '97789cb32d65251f9f748bd4efbb4e3c6a8c2a0aff6bc71abd31a9d72d61f3f0');
const routeCases = [
  ['deep JASH', '#/basmos/jash', 'home', 'basmos:jash'],
  ['legacy proof', '#proof', 'home', 'basmos:proof'],
  ['skip paper', '#pg-paper', 'basmos', 'paper:'],
  ['invalid BasmOS section', '#/basmos/nope', 'home', 'basmos:'],
  ['unknown live hash', '#unknown', 'basmos', null],
  ['unknown initial hash', '#unknown', '', 'home:'],
];
for (const [name, hash, current, expected] of routeCases) {
  const resolved = resolveRoute(hash, current);
  const actual = resolved && `${resolved.page}:${resolved.section}`;
  check('route: ' + name, actual === expected, 'got=' + actual + ' want=' + expected);
}

const siteClaims = [
  ['verified JASH image', 'src="jash-live.svg"'],
  ['current nucleus budget', '255+1'],
  ['current Pack size', '3,584-byte data Pack'],
  ['14 exact commands', '14 exact commands'],
  ['current prompt', 'jash@nanokernel.org'],
  ['NK-SIGIL/1', 'NK-SIGIL/1'],
  ['sigil derivation', 'SHA256(basmos-sh.bin || jash.bin)'],
  ['current JASH hash', '3ed12f5d1d90d006522fab676e796441fb870e8b23083dfd6d1907f8693b536d'],
  ['current Pack hash', '97789cb32d65251f9f748bd4efbb4e3c6a8c2a0aff6bc71abd31a9d72d61f3f0'],
  ['GitHub repository', 'https://github.com/FermiHart/BasmOS'],
  ['clone command', 'git clone https://github.com/FermiHart/BasmOS.git'],
  ['toolchain diagnostic', 'make toolchain'],
  ['toolchain installer', 'make toolchain-install'],
  ['direct sector download', 'href="basmos.bin" download'],
  ['transcript evidence link', 'evidence/jash-session.txt'],
  ['session manifest link', 'evidence/jash-session.manifest'],
  ['deep BasmOS links', 'href="#/basmos/proof"'],
  ['legacy BasmOS routes', "BASMOS_SECTIONS.has(legacy[1])"],
  ['reload-safe skip routes', "LEGACY_PAGES[legacy[1]]"],
  ['instant deep-link routing', "scrollIntoView({behavior:'instant',block:'start'})"],
  ['route focus management', "target.focus({preventScroll:true})"],
  ['route live status', 'id="route-status"'],
  ['route stops emulator', "if(page!=='basmos') stopEmulator()"],
  ['no-JS-safe POST', '#post{display:none'],
  ['no-JS POST fallback', '<noscript><style>#post{display:none!important}</style></noscript>'],
  ['reduced-motion handling', '@media(prefers-reduced-motion:reduce)'],
  ['mobile-first POST bypass', '@media(max-width:700px){#post{display:none!important}'],
  ['bounded POST duration', 'watchdog = setTimeout(kill, 3000)'],
  ['repeat-safe B shortcut', "!e.repeat"],
  ['non-editable B shortcut', '&& !editing) boot()'],
  ['accessible byte buttons', "document.createElement('button')"],
  ['roving byte-grid tabindex', 'd.tabIndex = i === selectedIndex ? 0 : -1'],
  ['arrow-key byte navigation', 'ArrowDown:i+COLS'],
  ['responsive byte-grid rebuild', "gridMedia.addEventListener('change', buildByteGrid)"],
  ['responsive grid state', "grid.classList.toggle('filtered', Boolean(pinned))"],
  ['responsive grid focus', 'focus({preventScroll:true})'],
  ['pressed legend state', "setAttribute('aria-pressed'"],
  ['accessible memory table', '<table class="mem" id="memmap">'],
  ['canonical metadata', '<link rel="canonical" href="https://nanokernel.org/">'],
  ['UTF-8 page byte count', 'new TextEncoder().encode(document.documentElement.outerHTML).byteLength'],
  ['August current revision', 'AUGUST 2026 · CURRENT REVISION'],
  ['browser scope', 'does not model paging, the PIC or the PIT'],
  ['exact final telemetry UI', 'exact 2,000,000-instruction telemetry and VGA evidence reached'],
];
for (const [name, claim] of siteClaims) {
  check('site: ' + name, html.includes(claim));
}
const rejectedClaims = ['PACK WRITES · 0', 'PRF1|ARTIFACT|JASH|253|3|FF',
  'jash@basmos.org', '5cceb51d8037f790943b4ddc5df42e70025188daa1ca1da23c3d931a398ba309',
  '399 B payload', 'payload is 399 bytes', '111 bytes remain',
  'Since this report', 'coined “nanokernel”'];
for (const claim of rejectedClaims) check('site rejects stale claim ' + claim, !html.includes(claim));
console.log('  crash: ' + (s.crash ? JSON.stringify(s.crash) : 'none'));
console.log('  telemetry: ' + s.insns + ' insns / ' + s.ticks + ' timer irqs / ' +
             s.yields + ' yields / ' + s.sends + ' sends / ' + s.recvs + ' recvs');
console.log('  heartbeat: ' + heartbeat + ' (== ticks: ' +
            (heartbeat === s.ticks) + ')');
const ownDomains = domains.task0 === 0x33 && domains.task1 === 0x39;
check('private domains', ownDomains, 'task0=' + domains.task0.toString(16).padStart(2, '0') +
      ' task1=' + domains.task1.toString(16).padStart(2, '0'));
console.log('  artifact: ' + (identical ? 'website bytes match basmos.bin' : 'MISMATCH'));
pass = pass && !s.crash && identical && heartbeat === s.ticks && ownDomains;

// Enter PM32 with a 256-byte DS and exercise C7's opcode extension and write width.
const c7Probe = (modrm, offset) => {
  const image = new Uint8Array(512);
  const put = (at, bytes) => image.set(bytes, at);
  put(0, [0xFA, 0x66,0x31,0xC0, 0x8E,0xD8,
    0x0F,0x01,0x16,0x40,0x7C, 0x0F,0x20,0xC0, 0x40, 0x0F,0x22,0xC0,
    0xEA,0x20,0x7C,0x08,0x00]);
  put(0x20, [0x66,0xB8,0x10,0x00, 0x8E,0xD8,
    0x66,0xB8,0x18,0x00, 0x8E,0xD0, 0xBC,0x00,0x08,0x00,0x00,
    0xC7,modrm, offset&255,(offset>>>8)&255,(offset>>>16)&255,(offset>>>24)&255,
    0x44,0x33,0x22,0x11, 0xF4]);
  put(0x40, [0x1F,0x00,0x50,0x7C,0x00,0x00]);
  put(0x50, [0,0,0,0,0,0,0,0,
    0xFF,0xFF,0,0,0,0x9A,0xCF,0,
    0xFF,0x00,0,0,0,0x92,0x40,0,
    0xFF,0xFF,0,0,0,0x92,0xCF,0]);
  CPU.reset(image);
  CPU.run(14);
  return CPU.stats();
};
const c7Width = c7Probe(0x05, 0xFF);
check('C7 validates full dword width at DS limit', !c7Width.crash && c7Width.lastException === 13);
const c7Valid = c7Probe(0x05, 0xFC);
check('C7 /0 accepts an in-range dword', !c7Valid.crash && c7Valid.lastException === null);
const c7Invalid = c7Probe(0x0D, 0xFC);
check('C7 rejects non-/0 encoding', !!c7Invalid.crash && c7Invalid.crash.op === 'c7/1');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'basmos-js-domain-'));
try {
  const build = (define, name) => {
    const binPath = path.join(tmp, name + '.bin');
    const mapPath = path.join(tmp, name + '.map');
    childProcess.execFileSync(__dirname + '/../basm-nano/basm-nano',
      ['-f', 'bin', '-D' + define, '--map', mapPath, '-o', binPath, 'basmos.basm'],
      {cwd: __dirname + '/..'});
    const map = fs.readFileSync(mapPath, 'utf8');
    const sym = s => Number(map.match(new RegExp('^\\s*(\\d+)\\s+\\d+\\s+' + s + '$', 'm'))[1]);
    return {bin: Uint8Array.from(fs.readFileSync(binPath)), sym};
  };

  const data = build('DOMAIN_FAULT_PROBE', 'fault');
  CPU.reset(data.bin);
  CPU.run(10000);
  const fault = CPU.stats(), denied = CPU.domains(), state = CPU.state();
  const gp = !fault.crash && fault.halted && fault.lastException === 13
             && state.eip === 0x7C00 + data.sym('gp_handler') + 1
             && state.frame[0] === 0
             && state.frame[1] === data.sym('domain_fault') - data.sym('task0')
             && state.frame[2] === 0x30
             && fault.ticks === 0 && denied.task0 === 0x33 && denied.task1 === 0;
  check('browser data window', gp, 'DS:[0x100] -> #GP' + fault.lastException +
        ' at CS:0x' + state.frame[2].toString(16) + ', peer=' +
        denied.task1.toString(16).padStart(2, '0'));

  const code = build('DOMAIN_CODE_FAULT_PROBE', 'codefault');
  CPU.reset(code.bin);
  CPU.run(10000);
  const cfault = CPU.stats(), cstate = CPU.state();
  const cgp = !cfault.crash && cfault.halted && cfault.lastException === 13
              && cstate.eip === 0x7C00 + code.sym('gp_handler') + 1
              && cstate.frame[0] === 0
              && cstate.frame[1] === code.sym('domain_code_fault') - code.sym('task0')
              && cstate.frame[2] === 0x30
              && cfault.ticks === 0
              && CPU.vram()[0] === 0x33 && CPU.vram()[2] !== 0x36;
  check('browser code window', cgp, 'jmp task1 -> #GP' + cfault.lastException +
        ' at CS:0x' + cstate.frame[2].toString(16) + ', task1 code never ran');
} finally {
  fs.rmSync(tmp, {recursive: true, force: true});
}
console.log(pass
  ? 'RESULT: PASS - in-page interpreter boots the real 512 bytes'
  : 'RESULT: FAIL');
process.exit(pass ? 0 : 1);
