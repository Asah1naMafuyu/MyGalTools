#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
disassembler.py -- WBUG_SCN v0.3 (WILD_BUG / REIMI) script disassembler.

Usage:
    python disassembler.py <script.WBI | directory> [-o <output>] [--encoding cp932]

The output is a semantic listing (`*.asm.txt`) that assembler.py can turn back
into a byte-identical script.  Text stored in the script data segment is shown
inline at every referencing instruction with a stable id (its original offset).

Format details: see opcodelist.py and vm_analysis.md.
"""
import argparse
import os
import struct
import sys
import traceback

import opcodelist as O


# ---------------------------------------------------------------------------
# virtual machine byte reader (faithful to sub_427643 / sub_4276B8)
# ---------------------------------------------------------------------------
class CodeReader:
    """4-byte little-endian dword buffer, exactly like the interpreter.

    A 4-byte immediate (kind 3) is read at the *next* dword boundary and the
    bytes still buffered from the current dword are skipped; the interpreter
    leaves them in the buffer and they are executed as NOP filler afterwards.
    """

    def __init__(self, code):
        self.code = code
        self.pc = 0
        self.buf = 0
        self.cnt = 0

    def pos(self):
        return self.pc - self.cnt

    def byte(self):
        if self.cnt == 0:
            if self.pc + 4 > len(self.code):
                raise EOFError("code exhausted at 0x%X" % self.pc)
            self.buf = int.from_bytes(self.code[self.pc:self.pc + 4], "little")
            self.pc += 4
            self.cnt = 4
        b = self.buf & 0xFF
        self.buf >>= 8
        self.cnt -= 1
        return b

    def dword(self):
        if self.pc + 4 > len(self.code):
            raise EOFError("code exhausted at 0x%X" % self.pc)
        v = int.from_bytes(self.code[self.pc:self.pc + 4], "little")
        self.pc += 4
        return v


def parse_operand(r):
    b = r.byte()
    mode = b >> 4
    kind = b & 0xF
    if kind not in O.KINDS:
        raise ValueError("bad operand kind 0x%X (descriptor 0x%02X at 0x%X)"
                         % (kind, b, r.pos() - 1))
    if kind == 0x3:
        v = r.dword()
        if v >= 0x80000000:
            v -= 0x100000000
    elif kind in O.KIND_VALUES:
        v = O.KIND_VALUES[kind]
    else:
        name, ln, signed = O.KINDS[kind]
        raw = bytes(r.byte() for _ in range(ln))
        v = int.from_bytes(raw, "little")
        if signed and v & (1 << (8 * ln - 1)):
            v -= 1 << (8 * ln)
    return {"mode": mode, "kind": kind, "value": v, "raw": b}


def read_instructions(code, flags):
    """Decode the complete code section."""
    r = CodeReader(code)
    ins = []
    n = len(code)
    while r.pos() < n:
        off = r.pos()
        op = r.byte()
        if op == 0x3F:
            ins.append({"off": off, "op": op, "args": [], "line": None,
                        "file": None, "size": r.pos() - off})
            continue
        count = r.byte()
        file_no = line = None
        if flags & 1:
            file_no = r.byte()
            lo = r.byte()
            hi = r.byte()
            line = lo | (hi << 8)
        args = [parse_operand(r) for _ in range(count)]
        ins.append({"off": off, "op": op, "args": args, "line": line,
                    "file": file_no, "size": r.pos() - off})
    if r.pos() != n:
        raise ValueError("instruction stream ended at 0x%X of 0x%X" % (r.pos(), n))
    return ins


# ---------------------------------------------------------------------------
# script container
# ---------------------------------------------------------------------------
def parse_script(data):
    if len(data) < O.HEADER_SIZE or data[:13] != O.MAGIC[:13]:
        raise ValueError("not a WBUG_SCN v0.3 script")
    h = {"magic": data[:16]}
    for name, off in O.HEADER_FIELDS:
        h[name] = struct.unpack_from("<I", data, off)[0]
    if data[h["code_off"]:h["code_off"] + h["code_size"]] is None:
        raise ValueError("bad code section")
    h["code"] = data[h["code_off"]:h["code_off"] + h["code_size"]]
    h["dataseg"] = data[h["data_off"]:h["data_off"] + h["data_size"]]
    h["extra"] = b""
    if h["extra_off"] != 0xFFFFFFFF and h["extra_size"]:
        h["extra"] = data[h["extra_off"]:h["extra_off"] + h["extra_size"]]
    h["names"] = []
    if h["name_off"] != 0xFFFFFFFF and h["name_count"]:
        for i in range(h["name_count"]):
            base = h["name_off"] + i * 36
            raw = data[base:base + 36]
            if len(raw) < 36:
                break
            h["names"].append({
                "name": raw[:32].rstrip(b"\x00"),
                "entry": struct.unpack_from("<I", raw, 32)[0],
            })
    h["data"] = data
    return h


# ---------------------------------------------------------------------------
# text encoding / escaping
# ---------------------------------------------------------------------------
CONTROL_ESCAPE = {0x0A: "{{0A}}", 0x0D: "{{0D}}", 0x09: "{{09}}"}


def render_text(raw, encoding):
    """Render bytes as a quoted string body with {{XX}} placeholders."""
    try:
        s = raw.decode(encoding, "surrogateescape")
    except LookupError:
        s = raw.decode("latin-1")
    out = []
    for ch in s:
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("{{%02X}}" % (o - 0xDC00))
        elif o in CONTROL_ESCAPE:
            out.append(CONTROL_ESCAPE[o])
        elif o < 0x20 or 0x7F <= o <= 0x9F:
            out.append("{{%02X}}" % (o & 0xFF))
        elif o == 0x5C:          # backslash
            out.append("\\\\")
        elif o == 0x22:          # double quote
            out.append('\\"')
        else:
            out.append(ch)
    return "".join(out)


def parse_text_literal(body, encoding):
    """Inverse of render_text: quoted string body -> bytes."""
    out = bytearray()
    lit = []
    i = 0
    n = len(body)

    def flush():
        if lit:
            try:
                out.extend("".join(lit).encode(encoding))
            except UnicodeEncodeError as exc:
                raise ValueError("text cannot be encoded as %s: %r" % (encoding, exc.object[exc.start:exc.end]))
            lit.clear()

    while i < n:
        ch = body[i]
        if ch == "\\" and i + 1 < n and body[i + 1] in '\\"':
            lit.append(body[i + 1])
            i += 2
        elif ch == "{" and body.startswith("{{", i):
            j = body.find("}}", i + 2)
            if j < 0:
                raise ValueError("unterminated placeholder")
            hexs = body[i + 2:j]
            flush()
            out.append(int(hexs, 16))
            i = j + 2
        else:
            lit.append(ch)
            i += 1
    flush()
    return bytes(out)


# ---------------------------------------------------------------------------
# data segment model: TEXT records and GAP byte runs
# ---------------------------------------------------------------------------
def build_pool(dataseg, refs):
    items = []
    pos = 0
    n = len(dataseg)
    refset = set(x for x in refs if 0 <= x < n)
    while pos < n:
        start = pos
        if pos in refset or dataseg[pos] != 0:
            end = dataseg.find(b"\x00", pos)
            if end < 0:
                items.append({"kind": "GAP", "id": start, "data": dataseg[start:]})
                pos = n
                continue
            items.append({"kind": "TEXT", "id": start, "text": dataseg[start:end]})
            pos = end + 1
        else:
            nxt = pos + 1
            while nxt < n and dataseg[nxt] == 0 and nxt not in refset:
                nxt += 1
            items.append({"kind": "GAP", "id": start, "data": dataseg[start:nxt]})
            pos = nxt
    return items


# ---------------------------------------------------------------------------
# listing generation
# ---------------------------------------------------------------------------
def canonical_kind(op, idx, mode, value):
    forced = O.FORCED_KIND.get((op, idx))
    if forced is not None:
        return forced
    if mode == 0x1:
        return 0x3
    if mode in (0x4, 0x6):
        return 0x0 if 0 <= value <= 0xFF else O.kind_for_value(value)
    return O.kind_for_value(value)


def render_operand(op, idx, arg, texts, encoding, labels):
    mode = arg["mode"]
    value = arg["value"]
    kind = arg["kind"]
    if mode == 0x1:
        s = labels.get(value, "loc_%04X" % value)
    elif mode == 0x2:
        item = texts.get(value)
        if item is not None:
            s = 'Text(0x%04X) "%s"' % (value, render_text(item, encoding))
        else:
            s = "Data(0x%04X)" % value
    elif mode == 0x3:
        s = "v%d" % value
    elif mode == 0x4:
        s = "bit[%d]" % value
    elif mode == 0x5:
        s = "byte[0x%X]" % value
    elif mode == 0x6:
        s = "dword[0x%X]" % value
    elif mode in (0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF):
        s = "%s[0x%X]" % (O.MODES[mode]["name"], value)
    else:
        if value < 0:
            s = "#-%d" % (-value)
        else:
            s = "#%d" % value
    want = canonical_kind(op, idx, mode, value)
    if want != kind:
        s += " {k=%X}" % kind
    return s


def disassemble(data, encoding="cp932", source_name=""):
    h = parse_script(data)
    ins = read_instructions(h["code"], h["flags"])
    refs = [a["value"] for x in ins for a in x["args"] if a["mode"] == 0x2]
    items = build_pool(h["dataseg"], refs)
    texts = {it["id"]: it["text"] for it in items if it["kind"] == "TEXT"}

    labels = {}
    targets = set()
    targets.add(h["entry"])
    for x in ins:
        for a in x["args"]:
            if a["mode"] == 0x1:
                targets.add(a["value"])
    for nm in h["names"]:
        targets.add(nm["entry"])
    for off in sorted(targets):
        labels[off] = "loc_%04X" % off

    L = []
    L.append("; WBUG_SCN v0.3 disassembly")
    if source_name:
        L.append("; source: %s" % os.path.basename(source_name))
    L.append("; encoding: %s" % encoding)
    L.append("; code 0x%X bytes, data 0x%X bytes (%d strings)"
             % (h["code_size"], h["data_size"], len(texts)))
    L.append("")
    L.append(".version 0.3")
    L.append(".flags 0x%X" % h["flags"])
    if h["entry"] in labels:
        L.append(".entry %s" % labels[h["entry"]])
    else:
        L.append(".entry 0x%04X" % h["entry"])
    if h["extra"]:
        L.append('.extra "%s"' % render_text(h["extra"].rstrip(b"\x00"), encoding))
    for nm in h["names"]:
        entry = labels.get(nm["entry"], "loc_%04X" % nm["entry"])
        L.append('.name "%s", %s' % (render_text(nm["name"], encoding), entry))
    L.append("")
    L.append(".code")

    for x in ins:
        off = x["off"]
        if off in labels:
            L.append("")
            L.append("%s:" % labels[off])
        if x["op"] == 0x3F:
            continue
        if x["line"] is not None:
            if x["file"]:
                L.append("    .line %d, %d" % (x["line"], x["file"]))
            else:
                L.append("    .line %d" % x["line"])
        ops = ", ".join(render_operand(x["op"], i, a, texts, encoding, labels)
                        for i, a in enumerate(x["args"]))
        line = "    %s" % O.mnemonic(x["op"])
        if ops:
            line += "  " + ops
        L.append(line)

    extras = [it for it in items if it["kind"] == "GAP" or it["id"] not in refs]
    if extras:
        L.append("")
        L.append(".data")
        for it in extras:
            if it["kind"] == "GAP":
                L.append("")
                L.append("gap_%04X:" % it["id"])
                chunk = it["data"]
                for i in range(0, len(chunk), 16):
                    part = chunk[i:i + 16]
                    L.append("    .bytes " + ", ".join("0x%02X" % b for b in part))
            else:
                L.append("")
                L.append("text_%04X:" % it["id"])
                L.append('    .text "%s"' % render_text(it["text"], encoding))
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def process_file(path, out_path, encoding):
    with open(path, "rb") as f:
        data = f.read()
    text = disassemble(data, encoding, path)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    # the listing itself is always UTF-8; --encoding only describes the
    # encoding of the strings embedded in the script
    with open(out_path, "w", encoding="utf-8", errors="replace", newline="\n") as f:
        f.write(text)
    print("disassembled %s -> %s" % (path, out_path))


def collect_inputs(path):
    if os.path.isdir(path):
        out = []
        for root, _dirs, names in os.walk(path):
            for n in sorted(names):
                if n.lower().endswith(".wbi"):
                    out.append(os.path.join(root, n))
        return out
    return [path]


def main(argv=None):
    ap = argparse.ArgumentParser(description="WBUG_SCN v0.3 disassembler")
    ap.add_argument("input", help="script file or directory")
    ap.add_argument("-o", "--output", help="output file or directory")
    ap.add_argument("--encoding", default="cp932",
                    help="encoding of the strings embedded in the script (default cp932); "
                         "the listing itself is always written as UTF-8")
    args = ap.parse_args(argv)

    inputs = collect_inputs(args.input)
    if not inputs:
        print("no .WBI files found")
        return 1
    is_dir = os.path.isdir(args.input) or len(inputs) > 1
    ok = 0
    for path in inputs:
        if is_dir:
            outdir = args.output if args.output else os.path.dirname(os.path.abspath(path))
            base = os.path.splitext(os.path.basename(path))[0]
            out_path = os.path.join(outdir, base + ".asm.txt")
        else:
            base = os.path.splitext(os.path.basename(path))[0]
            if args.output and os.path.isdir(args.output):
                out_path = os.path.join(args.output, base + ".asm.txt")
            else:
                out_path = args.output or (os.path.splitext(path)[0] + ".asm.txt")
        try:
            process_file(path, out_path, args.encoding)
            ok += 1
        except ValueError as exc:
            print("skip %s: %s" % (path, exc))
        except Exception as exc:
            print("ERROR %s: %s" % (path, exc))
            traceback.print_exc()
    print("done: %d/%d" % (ok, len(inputs)))
    return 0 if ok == len(inputs) else 1


if __name__ == "__main__":
    sys.exit(main())
