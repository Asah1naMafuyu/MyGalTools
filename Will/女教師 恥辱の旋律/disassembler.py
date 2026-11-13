#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""disassembler.py - 把 Will Co. .scr 字节码反汇编成可编辑的 UTF-8 语义汇编。

用法:
    python disassembler.py <脚本文件或目录> [-o <输出目录或文件>] [--encoding cp932]

    - 输入目录时批量处理其中的 *.scr，输出到同目录（或 -o 指定目录）。
    - 输出默认命名 <输入文件名>.asm.txt。
    - asm.txt 为 UTF-8，字符串按 --encoding（默认 cp932）解码后以可读文本给出，
      无法解码的字节用 {{XX}} 占位，换行序列写作 \\n，反斜杠写作 \\\\。

指令长度与操作数布局来自 Chijyoku.exe 的脚本 VM（sub_405160），见 opcodelist.py。
遇到未知 opcode 会报错退出并给出偏移，不会静默跳过。
"""

import argparse
import os
import struct
import sys

from opcodelist import OPCODES

# 0x01 中 flags 低 4 位的比较运算
CMP_NAME = {1: ">=", 2: "<=", 3: "==", 4: "!=", 5: ">", 6: "<"}


# --------------------------------------------------------------------------
# 文本编解码
# --------------------------------------------------------------------------
def decode_text(raw, encoding):
    s = raw.decode(encoding, errors="surrogateescape")
    out = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        o = ord(ch)
        if ch == "\\" and i + 1 < n and s[i + 1] == "n":
            out.append("\\n")
            i += 2
            continue
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("{{%02X}}" % (o - 0xDC00))
        elif o == 0x0A:
            out.append("{{0A}}")
        elif o == 0x0D:
            out.append("{{0D}}")
        elif o < 0x20 or o == 0x7F:
            out.append("{{%02X}}" % o)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------
# 解析
# --------------------------------------------------------------------------
def cstr_end(data, pos, limit):
    q = data.find(b"\x00", pos, limit)
    if q < 0:
        raise ValueError("字符串没有终止符 @ 0x%X" % pos)
    return q


def parse_select(data, pos, encoding):
    """解析 0x02 选择块，返回 (总长度, 选项列表)。"""
    count = data[pos + 1]
    b1 = data[pos + 2]
    q = pos + 3
    opts = []
    for _ in range(count):
        if q + 2 > len(data):
            raise ValueError("SELECT 记录越界 @ 0x%X" % q)
        w = struct.unpack_from("<H", data, q)[0]
        q += 2
        e = cstr_end(data, q, len(data))
        text = data[q:e]
        q = e + 1
        t = data[q]
        q += 1
        if t == 7:
            e = cstr_end(data, q, len(data))
            opts.append((w, t, text, data[q:e]))
            q = e + 1
        elif t == 3:
            if q + 7 > len(data):
                raise ValueError("SELECT type3 越界 @ 0x%X" % q)
            opts.append((w, t, text, data[q:q + 7]))
            q += 7
        elif t == 6:
            if q + 5 > len(data):
                raise ValueError("SELECT type6 越界 @ 0x%X" % q)
            opts.append((w, t, text, data[q:q + 5]))
            q += 5
        else:
            raise ValueError("SELECT 选项类型 %d 未知 @ 0x%X" % (t, q - 1))
    return q - pos, b1, count, opts


def parse(data, encoding):
    """返回指令列表 [(pos, op, length, extra)]。"""
    out = []
    p = 0
    n = len(data)
    while p < n:
        op = data[p]
        info = OPCODES.get(op)
        if info is None:
            raise ValueError("未知 opcode 0x%02X @ 0x%X" % (op, p))
        if info.get("special") == "select":
            length, b1, count, opts = parse_select(data, p, encoding)
            out.append((p, op, length, (b1, count, opts)))
        else:
            size = 1
            for _, typ in info["fields"]:
                if typ == "str":
                    size += cstr_end(data, p + size, n) - (p + size) + 1
                elif typ == "u8":
                    size += 1
                elif typ == "u16":
                    size += 2
                elif typ in ("u32", "rel32", "abs32"):
                    size += 4
                else:
                    raise ValueError("字段类型 %r 不支持" % typ)
            out.append((p, op, size, None))
        p += out[-1][2]
    return out


def collect_labels(data, instrs):
    labels = set()
    for pos, op, ln, extra in instrs:
        if op == 0x01:
            rel = struct.unpack_from("<i", data, pos + 6)[0]
            labels.add(pos + ln + rel)
        elif op == 0x06:
            labels.add(struct.unpack_from("<I", data, pos + 1)[0])
    starts = {p for p, _, _, _ in instrs}
    starts.add(len(data))
    bad = sorted(t for t in labels if t not in starts)
    if bad:
        raise ValueError("跳转目标不是指令边界: " + ", ".join("0x%X" % t for t in bad[:8]))
    return labels


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------
def fmt_label(t):
    return "loc_%08X" % t


def render(data, instrs, labels, name, encoding):
    lines = []
    lines.append("; ============================================================")
    lines.append("; Will Co. 脚本反汇编: %s" % name)
    lines.append("; 字节码指令集依据 Chijyoku.exe sub_405160 逆向")
    lines.append("; 文本编码: %s (asm.txt 本身为 UTF-8)" % encoding)
    lines.append("; ============================================================")
    lines.append(".encoding %s" % encoding)
    lines.append("")

    by_pos = {p: (op, ln, extra) for p, op, ln, extra in instrs}
    pos = 0
    first = True
    while pos < len(data):
        op, ln, extra = by_pos[pos]
        if pos in labels:
            if not first:
                lines.append("")
            lines.append("%s:" % fmt_label(pos))
            first = False
        info = OPCODES[op]
        mnem = info["name"]
        if info.get("special") == "select":
            b1, count, opts = extra
            lines.append("    %s %d, 0x%02X" % (mnem, count, b1))
            for w, t, text, payload in opts:
                if t == 7:
                    lines.append('      OPT 0x%04X, %d, "%s", "%s"'
                                 % (w, t, decode_text(text, encoding),
                                    decode_text(payload, encoding)))
                else:
                    nums = ", ".join("0x%02X" % b for b in payload)
                    lines.append('      OPT 0x%04X, %d, "%s", %s'
                                 % (w, t, decode_text(text, encoding), nums))
            lines.append("    SELECT_END")
        else:
            args = []
            off = pos + 1
            for fname, typ in info["fields"]:
                if typ == "u8":
                    args.append("%d" % data[off]); off += 1
                elif typ == "u16":
                    args.append("0x%04X" % struct.unpack_from("<H", data, off)[0]); off += 2
                elif typ == "u32":
                    args.append("0x%08X" % struct.unpack_from("<I", data, off)[0]); off += 4
                elif typ == "abs32":
                    t = struct.unpack_from("<I", data, off)[0]; off += 4
                    args.append(fmt_label(t))
                elif typ == "rel32":
                    r = struct.unpack_from("<i", data, off)[0]; off += 4
                    args.append(fmt_label(pos + ln + r))
                elif typ == "str":
                    e = cstr_end(data, off, len(data))
                    args.append('"%s"' % decode_text(data[off:e], encoding))
                    off = e + 1
                else:
                    raise ValueError("字段类型 %r 不支持" % typ)
            line = "    %s" % mnem
            if args:
                line += " " + ", ".join(args)
            if op == 0x01:
                fl = data[pos + 1]
                cmpn = CMP_NAME.get(fl & 0xF)
                if cmpn:
                    line += "    ; cmp %s%s" % (cmpn, ", 变量" if fl & 0x10 else "")
            lines.append(line)
        pos += ln
    if len(data) in labels:
        if not first:
            lines.append("")
        lines.append("%s:" % fmt_label(len(data)))
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
def process_file(path, out_path, encoding):
    with open(path, "rb") as f:
        data = f.read()
    instrs = parse(data, encoding)
    labels = collect_labels(data, instrs)
    text = render(data, instrs, labels, os.path.basename(path), encoding)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return len(instrs)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Will Co. .scr -> UTF-8 语义汇编")
    ap.add_argument("input", help="脚本文件或目录")
    ap.add_argument("-o", "--out", help="输出文件或目录")
    ap.add_argument("--encoding", default="cp932", help="脚本文本编码 (默认 cp932)")
    args = ap.parse_args(argv)

    try:
        if os.path.isdir(args.input):
            files = sorted(x for x in os.listdir(args.input) if x.lower().endswith(".scr"))
            if not files:
                print("目录中没有 .scr 文件: %s" % args.input, file=sys.stderr)
                return 1
            outdir = args.out or args.input
            ok = 0
            total_ins = 0
            for fn in files:
                src = os.path.join(args.input, fn)
                dst = os.path.join(outdir, fn + ".asm.txt")
                n = process_file(src, dst, args.encoding)
                ok += 1
                total_ins += n
            print("反汇编完成: %d 个文件, %d 条指令 -> %s" % (ok, total_ins, outdir))
        else:
            if not os.path.isfile(args.input):
                print("输入不存在: %s" % args.input, file=sys.stderr)
                return 1
            out = args.out or (args.input + ".asm.txt")
            n = process_file(args.input, out, args.encoding)
            print("反汇编完成: %s (%d 条指令)" % (out, n))
    except ValueError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
