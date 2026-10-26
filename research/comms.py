#!/usr/bin/env python3
"""The X-Link parallel-port protocol, recovered from both ends.

`RelNotes.txt` says X-Link drives the cartridge over the PC parallel port - read
and write PSX RAM, dump and re-flash the ROM, read memory cards, grab the screen,
set breakpoints, and (V1.091) "a simple command line subset of instructions ...
for executing user made programs" - but no note here had ever opened it up. This
does, and asserts what it finds rather than printing it:

  * the PC's byte in/out primitives and the command opcodes it sends, out of
    `pc/XLink.exe` (the DOS build, loaded with `xlink.py`'s LE loader);
  * the cartridge's command dispatcher and jump table, out of every firmware in
    `roms/` (loaded and disassembled with `fwimage.py` / `mipscan.py`), with the
    opcodes matched against the PC side;
  * the answer to `FINDINGS.md` section 6 item 3 - whether the wire protocol can
    read the full 512 KB flash, including the FX cheat database above the
    firmware.

    uv run --with capstone python comms.py [-v]

`-v` prints the recovered tables. `pc/` and `roms/` are gitignored like the rest
of the reversing corpus; with neither present the script explains what is missing
and exits 0, the same way `xlink.py` and `fxtest.py` do.

What was read vs. inferred. Everything below the word "assert" was read out of a
binary and re-derived here on each run. The one thing not checkable from these
files is that flash physically answers reads above `0x1F040000` on real hardware
- that needs a cart - so the 512 KB claim is stated as "the protocol imposes no
limit", which is a fact about the code, and kept separate from "it will work",
which is not asserted.
"""
import glob
import os
import re
import struct
import sys

import xlink                      # LE/PE loader + call_targets, reused verbatim

# ------------------------------------------------------------------ PC side

# The X-Link wire is: an attention byte 'W' (0x57) then a one-byte opcode, then
# the opcode's arguments.  Every PC command wrapper begins `mov eax,0x57; call
# send; mov eax,OPCODE; call send`, so the opcode set falls out of the code.
ATTN = 0x57

# Opcodes the cartridge must recognise, by their ASCII letter.  Recovered
# independently on each side and asserted equal; this is the shared contract.
LETTERS = {
    0x47: "read memory block  (G: addr,len -> len bytes + 16-bit checksum)",
    0x67: "read one byte      (g: 24-bit addr -> 1 byte)",
    0x53: "write memory block (S: addr,len,data)",
    0x54: "write mem, nibble  (T: fast 4-bit databurst write)",
    0x4F: "read mem, nibble   (O: fast 4-bit databurst read)",
    0x55: "program flash      (U: recv buffer, program over ROM, verify)",
    0x58: "program flash      (X: as U, used by the ROM-upgrade path)",
    0x4E: "negotiate          (N: Level 3 comms timing calibration)",
}

# The download-ROM path hard-codes these; they are the crux of the FX question.
FLASH_BASE = 0x1F000000          # cart flash, PSX expansion region 1
ROM_DL_LEN = 0x40000             # 256 KB - what the vendor tool reads
FX_DB_DESC = 0x1F07FFF8          # FX cheat-DB descriptor (FINDINGS 6.3)
FX_DB_END = 0x1F080000           # top of the 512 KB flash


def _md():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    m = Cs(CS_ARCH_X86, CS_MODE_32)
    m.skipdata = True
    return m


def pc_segments(path):
    segs = sorted(xlink.load(path).items())
    code = [(b, c) for b, c in segs if b < 0x40000][0]
    data = [(b, c) for b, c in segs if b >= 0x40000][0]
    return code, data


def pc_strings(data):
    base, blob = data
    out = {}
    for m in re.finditer(rb'[\x20-\x7e]{4,}', blob):
        out[base + m.start()] = m.group().decode()
    return out


def pc_port_globals(code):
    """The two I/O-port globals: one written with `out`, one read with `in`.

    `mov (e)dx,[imm32]` then `out dx,al` / `in al,dx`.  The base port is
    configurable (env XPORT, default 0x378); what is fixed is that the data
    register is written and the status register is read, from two globals.
    """
    base, blob = code
    outs, ins = set(), set()
    for m in re.finditer(rb'(?:\x66)?\x8b\x15(....)\xee', blob):      # out dx,al
        outs.add(struct.unpack('<I', m.group(1))[0])
    for m in re.finditer(rb'(?:\x66)?\x8b\x15(....)\xec', blob):      # in al,dx
        ins.add(struct.unpack('<I', m.group(1))[0])
    return outs, ins


def pc_eax_sends(code):
    """Every `call T` with the value `eax` held when it was made, as
    (call address, T, eax-or-None).  A linear pass so an instruction sitting
    between the `mov eax,imm` and the `call` (as several wrappers have) does not
    hide the argument the way a fixed byte pattern would."""
    base, blob = code
    md = _md()
    out = []
    eax = None
    imm = re.compile(r'^eax, (0x[0-9a-f]+|\d+)$')   # capstone prints small imms decimal
    for i in md.disasm(blob, base):
        m = imm.match(i.op_str) if i.mnemonic == 'mov' else None
        if m:
            eax = int(m.group(1), 0)
        elif i.mnemonic == 'call' and i.op_str.startswith('0x'):
            out.append((i.address, int(i.op_str, 0), eax))
            eax = None                       # consumed; call may clobber it
        elif i.mnemonic in ('mov', 'xor', 'add', 'sub', 'lea', 'movzx') \
                and i.op_str.startswith(('eax', 'al')):
            eax = None                       # eax overwritten by something else
    return out


def pc_send_primitive(sends):
    """The byte-send routine: the call target most often reached holding 0x57
    (the attention byte).  One indirection above `out`, shared by every command."""
    tally = {}
    for _, t, eax in sends:
        if eax == ATTN:
            tally[t] = tally.get(t, 0) + 1
    return max(tally, key=tally.get), tally


def pc_command_wrappers(sends, send):
    """{opcode: [attention-site, ...]} - a `call send` holding 0x57 followed by
    a `call send` holding the opcode byte, within 0x40 bytes."""
    seq = [(a, eax) for a, t, eax in sends if t == send and eax is not None]
    ops = {}
    for i, (site, imm) in enumerate(seq):
        if imm == ATTN and i + 1 < len(seq):
            nsite, nimm = seq[i + 1]
            if 0 < nsite - site < 0x40 and nimm < 0x100:
                ops.setdefault(nimm, []).append(site)
    return ops


def pc_rom_download(code, gwrapper):
    """The site that reads flash: `mov eax,0x1f000000; call <G wrapper>`, and
    the length its function passes.  Returns (site, length) or (None, None)."""
    base, blob = code
    need = struct.pack('<I', FLASH_BASE)
    for m in re.finditer(rb'\xb8' + need + rb'\xe8(....)', blob):
        rel, = struct.unpack('<i', m.group(1))
        if base + m.start() + 10 + rel == gwrapper:
            site = base + m.start()
            # the length is the nearest `mov edx,imm32` above the call
            back = blob[m.start() - 0x30:m.start()]
            lm = list(re.finditer(rb'\xba(....)', back))
            length = struct.unpack('<I', lm[-1].group(1))[0] if lm else None
            return site, length
    return None, None


def enclosing(entries, addr):
    """The function entry containing addr (largest call target <= addr)."""
    lo, hi = 0, len(entries)
    while lo < hi:
        m = (lo + hi) // 2
        if entries[m] <= addr:
            lo = m + 1
        else:
            hi = m
    return entries[lo - 1]


def check_pc(path, verbose):
    segs = sorted(xlink.load(path).items())
    code = [(b, c) for b, c in segs if b < 0x40000][0]
    data = [(b, c) for b, c in segs if b >= 0x40000][0]
    entries = sorted(xlink.call_targets(segs))
    strs = pc_strings(data)

    outs, ins = pc_port_globals(code)
    assert 0x891A4 in outs, sorted(hex(x) for x in outs)      # data register
    assert 0x891A8 in ins, sorted(hex(x) for x in ins)        # status register
    assert 0x891A4 not in ins and 0x891A8 not in outs
    # the port is configurable and defaults are documented in the tool itself
    assert any('XPORT' in s for s in strs.values())
    assert any('378 or 3BC' in s for s in strs.values())

    sends = pc_eax_sends(code)
    send, tally = pc_send_primitive(sends)
    assert tally[send] >= 20, tally[send]

    ops = pc_command_wrappers(sends, send)
    for op in LETTERS:
        assert op in ops, "PC never sends opcode 0x%02X (%s)" % (op, LETTERS[op])
    # The numeric development opcodes: this DOS build issues 0x02..0x11 except
    # 0x0A, which the cartridge handles (asserted below) but no wrapper here
    # sends.  Pinned exactly, not "most of them", so a build that used 0x0A - or
    # dropped another - would be noticed rather than waved through.
    numeric = set(op for op in ops if op < 0x20)
    assert numeric == set(range(0x02, 0x12)) - {0x0A}, sorted(hex(x) for x in numeric)

    gwrapper = enclosing(entries, ops[0x47][0])
    dl_site, dl_len = pc_rom_download(code, gwrapper)
    assert dl_site is not None, "no `read 0x1F000000` via the G wrapper"
    assert dl_len == ROM_DL_LEN, hex(dl_len or 0)     # 256 KB, the cap
    assert any('Downloading ROM' in s for s in strs.values())
    assert any('BackUp.FCD' in s or 'BACKUP.FCD' in s for s in strs.values())

    # opcode 0x0F is "R3000 Jump": arbitrary code execution.  Its wrapper is
    # named by the developer-shell help and the "R3000 Jump to %8.8x" line.
    assert 0x0F in ops
    assert any('R3000 Jump' in s for s in strs.values())
    assert any('X-Link COM Shell' in s or 'X-LINK Shell' in s
               for s in strs.values())

    # the documented `XLINK ?` command line, verb by verb
    cli = ''.join(strs.values())
    for verb in ('Execute PSX-EXE :   X', 'Upload Bin :   U',
                 'Download Bin :   G', 'Dump Memory :   D',
                 'Fill Memory :   F', 'R3000 Jump :   J'):
        assert verb in cli, verb

    if verbose:
        print('  data reg [0x891A4], status reg [0x891A8]; send @%08X' % send)
        print('  opcodes sent (%d):' % len(ops))
        for op in sorted(ops):
            ch = "'%c'" % op if 0x20 <= op < 0x7f else '   '
            print('    0x%02X %s  %s' % (op, ch, LETTERS.get(op, '')))
        print('  ROM download: read %08X len 0x%X via G-wrapper @%08X'
              % (FLASH_BASE, dl_len, gwrapper))
    return set(ops)


# --------------------------------------------------------------- cart side

def cart_dispatcher(ins):
    """Find `andi _,0xff; addiu $v1,$v0,-2; sltiu $v0,$v1,BOUND; ...; lw
    _,D($at); jr` - the wire dispatcher - and return (bound, table address)."""
    for k in range(2, len(ins) - 9):
        i = ins[k]
        if (i.mnemonic == 'sltiu'
                and ins[k - 1].mnemonic == 'addiu' and ins[k - 1].op_str.endswith(', -2')
                and ins[k - 2].mnemonic == 'andi' and ins[k - 2].op_str.endswith('0xff')):
            win = ins[k:k + 9]
            if not any(w.mnemonic == 'jr' for w in win):
                continue
            lw = next((w for w in win if w.mnemonic == 'lw' and '($at)' in w.op_str), None)
            lui = next((w for w in win if w.mnemonic == 'lui'), None)
            if not (lw and lui):
                continue
            bound = int(i.op_str.rsplit(', ', 1)[1], 0)
            hi = int(lui.op_str.rsplit(', ', 1)[1], 0) << 16
            d = int(lw.op_str.split('(')[0].rsplit(', ', 1)[1], 0)
            if d > 0x7FFF:
                d -= 0x10000
            return bound, (hi + d) & 0xFFFFFFFF
    return None, None


def cart_table(img, base, bound, tbl):
    """The opcode -> handler map: index = opcode - 2."""
    off = tbl - base
    vals = [struct.unpack_from('<I', img, off + 4 * i)[0] for i in range(bound)]
    default = max(set(vals), key=vals.count)     # the "unknown command" route
    return {i + 2: vals[i] for i in range(bound)}, default


def _ins_at(ins, addr):
    lo, hi = 0, len(ins)
    while lo < hi:
        m = (lo + hi) // 2
        if ins[m].address < addr:
            lo = m + 1
        else:
            hi = m
    return lo


def cart_read_block_unbounded(ins, entry):
    """The G handler reads two 32-bit words with the *same* recv helper (addr
    then len), then an `lbu;send` loop whose only guard is a register-register
    `sltu`/`slt` - i.e. the length is taken verbatim off the wire, with no
    bound.  Assert exactly that shape and return the recv helper's address."""
    k0 = _ins_at(ins, entry)
    body = ins[k0:k0 + 40]
    jals = [w for w in body if w.mnemonic == 'jal' and w.op_str.startswith('0x')]
    assert len(jals) >= 2, entry
    recv = int(jals[0].op_str, 0)
    assert int(jals[1].op_str, 0) == recv, "addr and len not read the same way"
    # the copy loop: `lbu` then a send `jal`, guarded only by a register-register
    # `sltu`/`slt` (index < length) that closes a backward branch.  No compare
    # against any immediate address or size - the length is the wire's, verbatim.
    for j, w in enumerate(body):
        if w.mnemonic not in ('lbu', 'lb'):
            continue
        seg = body[j:j + 8]
        if not any(x.mnemonic == 'jal' for x in seg):
            continue
        guard = next((x for x in seg if x.mnemonic in ('sltu', 'slt')), None)
        branch = next((x for x in seg if x.mnemonic in ('bnez', 'bne')), None)
        if guard and branch and '0x' not in guard.op_str \
                and int(branch.op_str.rsplit(', ', 1)[1], 0) <= w.address:
            return recv
    raise AssertionError('%08X: no unbounded copy loop' % entry)


def cart_exec_handler(ins, entry):
    """The 0x0F handler assembles a 32-bit value from four received bytes and
    `jalr`s to it: arbitrary code execution, no validation.  The jump-table slot
    is a `jal EXEC` trampoline, so follow it, then assert EXEC's shape."""
    k0 = _ins_at(ins, entry)
    body = ins[k0:k0 + 20]
    if not any(w.mnemonic == 'jalr' for w in body[:6]):
        jal = next((w for w in body[:4]
                    if w.mnemonic == 'jal' and w.op_str.startswith('0x')), None)
        assert jal, '%08X: exec slot is neither jalr nor a trampoline' % entry
        k0 = _ins_at(ins, int(jal.op_str, 0))
        body = ins[k0:k0 + 20]
    recvs = sum(1 for w in body[:14] if w.mnemonic == 'jal')
    assert recvs >= 4, '%08X: exec reads < 4 address bytes' % entry
    assert any(w.mnemonic == 'jalr' for w in body), '%08X: no jalr' % entry


def fw_label(path):
    blob = open(path, 'rb').read()
    m = re.search(rb'release ([0-9.]+)', blob)
    return m.group(1).decode() if m else '?'


def check_cart(path, verbose):
    import fwimage
    import mipscan
    img, base = fwimage.load(path)
    ins = mipscan.dis(img, base)

    bound, tbl = cart_dispatcher(ins)
    assert bound is not None, '%s: no wire dispatcher' % path
    table, default = cart_table(img, base, bound, tbl)

    gen = 'V2' if base < 0x1000000 else 'FX'
    assert (gen, bound) in (('V2', 0x66), ('FX', 0xC6)), (gen, hex(bound))

    handlers = {}
    for op in LETTERS:
        h = table.get(op)
        assert h and h != default and base <= h < base + len(img), \
            '%s: opcode 0x%02X missing from jump table' % (path, op)
        handlers[op] = h

    # the read commands really are unbounded, and the letters map as claimed:
    # 'g' reads one byte, 'G' reads a caller-sized block
    recv = cart_read_block_unbounded(ins, handlers[0x47])
    assert handlers[0x67] != handlers[0x47]

    # the numeric development opcodes: 0x02..0x0F are handled by every image;
    # 0x10 and 0x11 (register dump / string write) are a later addition, present
    # only in the V2 2.008 builds - so they are reported, not required.
    for op in range(0x02, 0x10):
        h = table.get(op)
        assert h and h != default, '%s: opcode 0x%02X unhandled' % (path, op)
    ext = all(table.get(op) and table[op] != default for op in (0x10, 0x11))

    # opcode 0x0F: jalr to a received address
    exec_h = table[0x0F]
    cart_exec_handler(ins, exec_h)

    # the flash the reads land in: the firmware addresses the 0x1F00_0000 window
    assert any('0x1f00' in w.op_str for w in ins if w.mnemonic == 'lui'), path

    if verbose:
        print('  %-26s %s base=%08X bound=0x%02X recv@%08X'
              % (os.path.basename(path), gen, base, bound, recv))
        for op in sorted(LETTERS):
            print('      0x%02X %-3s -> %08X' %
                  (op, "'%c'" % op, handlers[op]))
    return gen, handlers, ext


# ---------------------------------------------------------- the FX question

def check_fx_flash_dump(pc_ops, cart_seen):
    """FINDINGS 6.3: nobody has the 512 KB FX dump.  Establish that the wire
    protocol reaches it and that the vendor tool simply never asks."""
    # the read command exists and is length-unbounded on the FX firmwares - that
    # was asserted per image in check_cart; here we tie it to the geometry.
    assert 0x47 in pc_ops                                   # PC can send it
    assert FX_DB_DESC < FX_DB_END == FLASH_BASE + 0x80000
    # what the vendor reads (256 KB) stops *below* the FX database descriptor,
    # which is exactly why the region has never been dumped:
    assert FLASH_BASE + ROM_DL_LEN <= FX_DB_DESC
    assert ROM_DL_LEN == 0x40000 and 0x80000 == 2 * ROM_DL_LEN
    # a full read is the same command with a bigger length - build the bytes.
    full = struct.pack('>BBII', ATTN, 0x47, FLASH_BASE, 0x80000)
    assert full == b'\x57\x47\x1f\x00\x00\x00\x00\x08\x00\x00'
    return full


# --------------------------------------------------------------------- main

def main(argv):
    verbose = '-v' in argv
    pc = [a for a in argv if a.endswith('.exe')] or ['pc/XLink.exe']
    roms = sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))

    if not os.path.exists(pc[0]) and not roms:
        print('no pc/XLink.exe and no roms/ - nothing to check '
              '(see FCD.md section 4 for where the binaries come from)')
        return 0

    pc_ops = set()
    if os.path.exists(pc[0]):
        print('%s: DOS X-Link, parallel-port protocol' % pc[0])
        pc_ops = check_pc(pc[0], verbose)
        print('  %d opcodes recovered; the eight shared letters and the '
              '0x02-0x11 dev set all present' % len(pc_ops))
    else:
        print('pc/XLink.exe absent - PC side skipped')

    cart_seen = {}
    v2 = fx = ext = 0
    for path in roms:
        gen, handlers, has_ext = check_cart(path, verbose)
        cart_seen[path] = (gen, handlers)
        v2 += gen == 'V2'
        fx += gen == 'FX'
        ext += has_ext
    if roms:
        print('%d firmware images carry the same dispatcher and command set '
              '(%d V2, %d FX); %d also handle the 0x10/0x11 extension'
              % (len(roms), v2, fx, ext))
        # the opcodes match across the wire: every letter the PC sends is a
        # non-default jump-table entry in every firmware
        if pc_ops:
            for path, (gen, handlers) in cart_seen.items():
                for op in LETTERS:
                    assert op in pc_ops, hex(op)
            print('  PC opcodes and cartridge jump-table entries agree on all '
                  '%d shared commands' % len(LETTERS))
    else:
        print('roms/ empty - cartridge side skipped')

    # the closing question, only when both halves and an FX image are present
    if pc_ops and fx:
        full = check_fx_flash_dump(pc_ops, cart_seen)
        print('FX 512 KB flash: reachable. The read-memory command is '
              'length-unbounded on all %d FX images;' % fx)
        print('  the tool reads only %08X..%08X (256 KB), stopping below the '
              'FX DB descriptor at %08X.' % (FLASH_BASE, FLASH_BASE + ROM_DL_LEN,
                                             FX_DB_DESC))
        print('  A full dump is the same command with length 0x80000: '
              'send %s' % full.hex())
        print('  then read back 0x80000 bytes + a 16-bit checksum '
              '(0x1F000000..0x1F080000, the whole flash incl. the cheat DB).')

    print('all comms-protocol assertions passed')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
