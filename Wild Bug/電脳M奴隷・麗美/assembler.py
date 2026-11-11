#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
assembler.py -- WBUG_SCN v0.3 (WILD_BUG / REIMI) script assembler.

Usage:
    python assembler.py <script.asm.txt | directory> [-o <output.WBI>] [--encoding gbk]

Reads the semantic listing produced by disassembler.py and rebuilds the script
bit for bit.  Text records are laid out in the data segment, instruction
padding is regenerated with 0x3F (NOP) and every data reference is recomputed.
"""
import argparse
import os
import re
import struct
import sys
import traceback

import opcodelist as O


class AsmError(Exception):
    pass


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def strip_comment(line):
    out = []
    quote = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and quote and i + 1 < len(line):
            out.append(ch)
            out.append(line[i + 1])
            i += 2
            continue
        if ch == '"':
            quote = not quote
        if ch == ";" and not quote:
            break
        out.append(ch)
        i += 1
    return "".join(out).rstrip()


def parse_int(s):
    s = s.strip()
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    v = int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    return -v if neg else v


def escape_text_body(body, encoding):
    """asdis textual body (with {{XX}}, \\\\ and \\\") -> bytes"""
    import disassembler as D
    return D.parse_text_literal(body, encoding)


# ---------------------------------------------------------------------------
# parsed representation
# ---------------------------------------------------------------------------
class AsmFile:
    def __init__(self):
        self.version = "0.3"
        self.flags = 0
        self.entry = None
        self.extra = None
        self.names = []          # (name, label)
        self.instructions = []   # dict(op, args, line, file)
        self.labels = {}         # label -> instruction index
        self.texts = {}          # id -> bytes
        self.gaps = {}           # id -> bytes
        self.encoding = None
        self.code_size_hint = None
        self.pending_data_label = None


ARG_RE_KIND = re.compile(r"\s*\{k=([0-9A-Fa-f]+)\}\s*$")


def split_args(s):
    """Split an argument list on commas that are outside quotes/parens."""
    out = []
    buf = []
    quote = False
    depth = 0
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and quote and i + 1 < len(s):
            buf.append(ch)
            buf.append(s[i + 1])
            i += 2
            continue
        if ch == '"':
            quote = not quote
        elif not quote and ch == "(":
            depth += 1
        elif not quote and ch == ")":
            depth -= 1
        if ch == "," and not quote and depth == 0:
            out.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if "".join(buf).strip():
        out.append("".join(buf).strip())
    return out


def parse_arg(s, encoding):
    s = s.strip()
    kind = None
    m = ARG_RE_KIND.search(s)
    if m:
        kind = int(m.group(1), 16)
        s = s[:m.start()].strip()
    if s.startswith("Text("):
        m = re.match(r'Text\(0x([0-9A-Fa-f]+)\)\s+"(.*)"$', s, re.S)
        if not m:
            raise AsmError("bad text operand: %r" % s)
        tid = int(m.group(1), 16)
        body = escape_text_body(m.group(2), encoding)
        return {"mode": 2, "kind": kind, "text": (tid, body)}
    m = re.match(r"Data\(0x([0-9A-Fa-f]+)\)$", s)
    if m:
        return {"mode": 2, "kind": kind, "value": int(m.group(1), 16), "text": None}
    if s.startswith("#"):
        return {"mode": 0, "kind": kind, "value": parse_int(s[1:])}
    m = re.match(r"(loc_[0-9A-Fa-f]+)$", s)
    if m:
        return {"mode": 1, "kind": kind, "label": m.group(1)}
    m = re.match(r"v(\d+)$", s)
    if m:
        return {"mode": 3, "kind": kind, "value": int(m.group(1))}
    m = re.match(r"bit\[(\d+)\]$", s)
    if m:
        return {"mode": 4, "kind": kind, "value": int(m.group(1))}
    m = re.match(r"byte\[(0x[0-9A-Fa-f]+|-?\d+)\]$", s)
    if m:
        return {"mode": 5, "kind": kind, "value": parse_int(m.group(1))}
    m = re.match(r"dword\[(0x[0-9A-Fa-f]+|-?\d+)\]$", s)
    if m:
        return {"mode": 6, "kind": kind, "value": parse_int(m.group(1))}
    m = re.match(r"(\w+)\[(0x[0-9A-Fa-f]+|-?\d+)\]$", s)
    if m:
        for mode, info in O.MODES.items():
            if info["name"] == m.group(1):
                return {"mode": mode, "kind": kind, "value": parse_int(m.group(2))}
    raise AsmError("cannot parse operand %r" % s)


def parse_asm(text, encoding):
    a = AsmFile()
    section = None
    pending_line = None
    pending_file = 0
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line.strip():
            continue
        s = line.strip()
        if s.startswith("; encoding:"):
            continue
        if s.startswith(".version"):
            a.version = s.split(None, 1)[1] if " " in s else "0.3"
            continue
        if s.startswith(".flags"):
            a.flags = parse_int(s.split(None, 1)[1])
            continue
        if s.startswith(".entry"):
            a.entry = s.split(None, 1)[1].strip()
            continue
        if s.startswith(".extra"):
            m = re.match(r'\.extra\s+"(.*)"$', s, re.S)
            if not m:
                raise AsmError("bad .extra")
            a.extra = escape_text_body(m.group(1), encoding)
            continue
        if s.startswith(".name"):
            m = re.match(r'\.name\s+"(.*)"\s*,\s*(\S+)$', s, re.S)
            if not m:
                raise AsmError("bad .name")
            a.names.append((escape_text_body(m.group(1), encoding), m.group(2)))
            continue
        if s.startswith(".code"):
            section = "code"
            continue
        if s.startswith(".data"):
            section = "data"
            continue
        if s.startswith(".line"):
            parts = s.split(None, 1)[1].split(",")
            pending_line = parse_int(parts[0])
            pending_file = parse_int(parts[1]) if len(parts) > 1 else 0
            continue
        if s.startswith(".text"):
            m = re.match(r'\.text\s+"(.*)"$', s, re.S)
            if not m:
                raise AsmError("bad .text")
            if a.pending_data_label is None:
                raise AsmError(".text without label")
            a.texts[a.pending_data_label] = escape_text_body(m.group(1), encoding)
            a.pending_data_label = None
            continue
        if s.startswith(".bytes"):
            vals = [parse_int(x.strip()) for x in s.split(None, 1)[1].split(",")]
            if a.pending_data_label is None:
                raise AsmError(".bytes without label")
            a.gaps[a.pending_data_label] = bytes(v & 0xFF for v in vals)
            a.pending_data_label = None
            continue
        if s.startswith("."):
            raise AsmError("unknown directive %r" % s)
        if s.endswith(":"):
            label = s[:-1].strip()
            if section == "code":
                a.labels[label] = len(a.instructions)
            else:
                m = re.match(r"(?:text|gap)_([0-9A-Fa-f]+)$", label)
                if not m:
                    raise AsmError("bad data label %r" % label)
                a.pending_data_label = int(m.group(1), 16)
            continue
        if section != "code":
            raise AsmError("instruction outside .code: %r" % s)
        parts = s.split(None, 1)
        mn = parts[0]
        op = O.opcode_of(mn)
        if op is None:
            raise AsmError("unknown mnemonic %r" % mn)
        args = split_args(parts[1]) if len(parts) > 1 else []
        parsed = [parse_arg(x, encoding) for x in args]
        for p in parsed:
            if p.get("text") is not None:
                tid, body = p["text"]
                prev = a.texts.get(tid)
                if prev is not None and prev != body:
                    raise AsmError("text id 0x%X defined twice with different content" % tid)
                a.texts[tid] = body
        a.instructions.append({"op": op, "args": parsed, "line": pending_line,
                               "file": pending_file})
        pending_line = None
        pending_file = 0
    return a


# ---------------------------------------------------------------------------
# encoding
# ---------------------------------------------------------------------------
def encode_insn(ins, code_len, labels, text_off, flags):
    """Return the bytes of one instruction (without the leading alignment)."""
    buf = bytearray()
    buf.append(ins["op"])
    if ins["op"] != 0x3F:
        buf.append(len(ins["args"]))
        if flags & 1:
            buf.append(ins.get("file") or 0)
            line = ins.get("line") or 0
            buf.append(line & 0xFF)
            buf.append((line >> 8) & 0xFF)
        for idx, a in enumerate(ins["args"]):
            mode = a["mode"]
            value = a.get("value")
            if a.get("text") is not None:
                value = text_off.get(a["text"][0])
                if value is None:
                    raise AsmError("text id 0x%X is not defined" % a["text"][0])
            if mode == 1:
                if a.get("label") is None:
                    raise AsmError("jump without label")
                if a["label"] not in labels:
                    raise AsmError("undefined label %s" % a["label"])
                value = labels[a["label"]]
            if value is None:
                raise AsmError("operand without value")
            kind = a["kind"]
            if kind is None:
                forced = O.FORCED_KIND.get((ins["op"], idx))
                if forced is not None:
                    kind = forced
                elif mode == 1:
                    kind = 0x3
                elif mode in (0x4, 0x6):
                    kind = 0x0 if 0 <= value <= 0xFF else O.kind_for_value(value)
                else:
                    kind = O.kind_for_value(value)
            buf.append((mode << 4) | kind)
            if kind == 0x3:
                while (code_len + len(buf)) % 4:
                    buf.append(0x3F)
                buf.extend(struct.pack("<I", value & 0xFFFFFFFF))
            elif kind in O.KIND_VALUES:
                if value != O.KIND_VALUES[kind]:
                    raise AsmError("constant operand kind mismatch (value %d, kind %X)"
                                   % (value, kind))
            else:
                name, ln, signed = O.KINDS[kind]
                if not fits(value, ln, signed):
                    # upgrade the kind rather than emit a truncated value
                    kind = O.kind_for_value(value)
                    name, ln, signed = O.KINDS[kind]
                    if kind == 0x3:
                        buf[-1] = (mode << 4) | kind
                        while (code_len + len(buf)) % 4:
                            buf.append(0x3F)
                        buf.extend(struct.pack("<I", value & 0xFFFFFFFF))
                        continue
                    if not fits(value, ln, signed):
                        raise AsmError("operand value %d out of range" % value)
                    buf[-1] = (mode << 4) | kind
                buf.extend(int(value & ((1 << (8 * ln)) - 1)).to_bytes(ln, "little"))
    return bytes(buf)


def fits(value, ln, signed):
    if signed:
        lo = -(1 << (8 * ln - 1))
        hi = (1 << (8 * ln - 1)) - 1
        return lo <= value <= hi
    return 0 <= value <= (1 << (8 * ln)) - 1


def assemble(a):
    encoding = a.encoding or "cp932"
    # ---- data segment -----------------------------------------------------
    items = []
    for tid, body in a.texts.items():
        items.append(("TEXT", tid, body))
    for gid, body in a.gaps.items():
        items.append(("GAP", gid, body))
    items.sort(key=lambda x: x[1])
    data = bytearray()
    text_off = {}
    for kind, ident, body in items:
        if kind == "TEXT":
            text_off[ident] = len(data)
            data.extend(body)
            data.append(0)
        else:
            data.extend(body)
    # ---- code layout ------------------------------------------------------
    labels = {}
    for name, idx in a.labels.items():
        labels[name] = 0
    code = b""
    for _ in range(12):
        buf = bytearray()
        pc = 0
        new_labels = {}
        for idx, ins in enumerate(a.instructions):
            while pc % 4:
                buf.append(0x3F)
                pc += 1
            for name, lidx in a.labels.items():
                if lidx == idx and name not in new_labels:
                    new_labels[name] = pc
            chunk = encode_insn(ins, pc, {**labels, **new_labels}, text_off, a.flags)
            buf.extend(chunk)
            pc += len(chunk)
        while pc % 4:
            buf.append(0x3F)
            pc += 1
        code = bytes(buf)
        if new_labels == labels:
            break
        labels = {**new_labels}
    # ---- sections ---------------------------------------------------------
    pos = O.HEADER_SIZE
    name_blob = b""
    if a.names:
        nb = bytearray()
        for nm, label in a.names:
            raw = nm.ljust(32, b"\x00")[:32]
            entry = labels.get(label, 0)
            nb += raw + struct.pack("<I", entry)
        name_blob = bytes(nb)
    extra = a.extra or b""
    if extra:
        # module name string: name + NUL + one pad byte, rounded to 4 bytes
        need = ((len(extra) + 2 + 3) // 4) * 4
        extra = extra + b"\x00" * (need - len(extra))
    name_off = pos if name_blob else 0xFFFFFFFF
    if name_blob:
        pos += len(name_blob)
    extra_off = pos if extra else 0xFFFFFFFF
    if extra:
        pos += len(extra)
    code_off = pos
    pos += len(code)
    data_off = pos
    pos += len(data)
    hdr = bytearray(O.HEADER_SIZE)
    hdr[0:16] = O.MAGIC
    struct.pack_into("<10I", hdr, 0x10, a.flags, labels.get(a.entry, 0),
                     code_off, len(code), data_off, len(data),
                     name_off, len(a.names), extra_off, len(extra))
    return bytes(hdr) + name_blob + extra + code + bytes(data)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def detect_encoding(text, default):
    m = re.search(r"^;\s*encoding:\s*([A-Za-z0-9_\-]+)", text, re.M)
    return m.group(1) if m else default


def assemble_file(path, out_path, encoding):
    raw = open(path, "rb").read()
    head = raw[:400].decode("latin-1")
    enc = encoding or detect_encoding(head, "cp932")
    # listings are written as UTF-8; fall back to the declared script encoding
    # for old listings that still use it for the whole file
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode(enc, "replace")
    a = parse_asm(text, enc)
    a.encoding = enc
    blob = assemble(a)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(blob)
    print("assembled %s -> %s (%d bytes)" % (path, out_path, len(blob)))


def collect_inputs(path):
    if os.path.isdir(path):
        out = []
        for root, _dirs, names in os.walk(path):
            for n in sorted(names):
                if n.lower().endswith(".asm.txt"):
                    out.append(os.path.join(root, n))
        return out
    return [path]


def source_output_name(path):
    """从汇编头部的 `; source: xxx.WBI` 取原文件名，取不到返回 None。"""
    try:
        with open(path, "rb") as f:
            head = f.read(2048).decode("utf-8", "replace")
    except OSError:
        return None
    m = re.search(r"^;\s*source:\s*(\S+)\s*$", head, re.M)
    if not m:
        return None
    name = os.path.basename(m.group(1).strip())
    return name if os.path.splitext(name)[1] else None


def main(argv=None):
    ap = argparse.ArgumentParser(description="WBUG_SCN v0.3 assembler")
    ap.add_argument("input", help="asm file or directory")
    ap.add_argument("-o", "--output", help="output file or directory")
    ap.add_argument("--encoding", default=None,
                    help="encoding used to write the strings back into the script "
                         "(default: from the listing header, else cp932); the listing "
                         "itself is read as UTF-8")
    args = ap.parse_args(argv)
    inputs = collect_inputs(args.input)
    if not inputs:
        print("no .asm.txt files found")
        return 1
    is_dir = os.path.isdir(args.input) or len(inputs) > 1
    out_is_dir = bool(args.output) and (
        os.path.isdir(args.output) or args.output.endswith(("/", "\\"))
        or not os.path.splitext(args.output)[1])
    ok = 0
    for path in inputs:
        out_name = source_output_name(path)
        if out_name is None:
            base = os.path.basename(path)
            if base.lower().endswith(".asm.txt"):
                base = base[:-8]
            out_name = base + ".WBI"
        if is_dir:
            outdir = args.output if args.output else os.path.dirname(os.path.abspath(path))
            out_path = os.path.join(outdir, out_name)
        elif args.output and not out_is_dir:
            out_path = args.output
        elif args.output:
            out_path = os.path.join(args.output, out_name)
        else:
            out_path = os.path.join(os.path.dirname(os.path.abspath(path)), out_name)
        try:
            assemble_file(path, out_path, args.encoding)
            ok += 1
        except Exception as exc:
            msg = str(exc)
            if "cannot be encoded as cp932" in msg:
                msg += "（中文译文请用 --encoding gbk 汇编）"
            print("ERROR %s: %s" % (path, msg))
            traceback.print_exc()
    print("done: %d/%d" % (ok, len(inputs)))
    return 0 if ok == len(inputs) else 1


if __name__ == "__main__":
    sys.exit(main())
