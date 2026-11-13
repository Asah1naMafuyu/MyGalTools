#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""assembler.py - 把 UTF-8 语义汇编重新汇编成 Will Co. .scr 字节码。

用法:
    python assembler.py <asm.txt 或目录> [-o <输出文件或目录>] [--encoding cp932]

    - 输入目录时批量处理其中的 *.asm.txt，输出到同目录（或 -o 指定目录）。
    - 输出默认命名 <输入文件名去掉 .asm.txt>，即 ``TU17.scr.asm.txt`` -> ``TU17.scr``；
      没有 .scr 后缀时自动补上。
    - 汇编器根据标签重新计算所有 0x01/0x06 的跳转偏移，因此可以安全地
      修改文本长度（字符串变长后，后续指令与跳转目标会自动重定位）。
"""

import argparse
import os
import re
import struct
import sys

from opcodelist import OPCODES

BY_NAME = {v["name"]: k for k, v in OPCODES.items()}

LABEL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):$")
SELECT_END = "SELECT_END"


class AsmError(Exception):
    pass


# --------------------------------------------------------------------------
def unquote(s):
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        raise AsmError("字符串格式错误: %r" % s)
    return s[1:-1]


def text_to_bytes(s, encoding):
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\\":
            if i + 1 >= n:
                raise AsmError("字符串末尾有孤立反斜杠")
            nxt = s[i + 1]
            if nxt == "n":
                out += b"\\n"          # 引擎的换行序列 0x5C 0x6E
            elif nxt == "\\":
                out += b"\\"
            elif nxt == '"':
                out += b'"'
            else:
                raise AsmError("未知转义 \\%s" % nxt)
            i += 2
            continue
        if s.startswith("{{", i):
            j = s.find("}}", i)
            if j < 0:
                raise AsmError("占位符缺少 }}: %r" % s[i:])
            hx = s[i + 2:j]
            try:
                out.append(int(hx, 16) & 0xFF)
            except ValueError:
                raise AsmError("非法占位符 {{%s}}" % hx)
            i = j + 2
            continue
        out += ch.encode(encoding)
        i += 1
    return bytes(out)


def split_args(s):
    """按逗号切分（忽略引号内与 {{}} 内的逗号）。"""
    out = []
    cur = []
    q = False
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if q:
            cur.append(ch)
            if ch == "\\" and i + 1 < n:
                cur.append(s[i + 1])
                i += 2
                continue
            if ch == '"':
                q = False
            i += 1
            continue
        if ch == '"':
            q = True
            cur.append(ch)
        elif ch == ",":
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail or out:
        out.append(tail)
    return out


def strip_comment(line):
    q = False
    i = 0
    while i < len(line):
        ch = line[i]
        if q:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                q = False
        else:
            if ch == '"':
                q = True
            elif ch == ";":
                return line[:i]
        i += 1
    return line


# --------------------------------------------------------------------------
# 第一遍：解析 + 计算长度
# --------------------------------------------------------------------------
def parse_int(s):
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)


def build_items(text):
    items = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        i += 1
        line = strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith(".encoding"):
            items.append({"kind": "encoding", "value": line.split()[1]})
            continue
        m = LABEL_RE.match(line)
        if m:
            items.append({"kind": "label", "name": m.group(1)})
            continue
        parts = line.split(None, 1)
        mnem = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        if mnem not in BY_NAME:
            raise AsmError("第 %d 行: 未知指令 %r" % (i, mnem))
        op = BY_NAME[mnem]
        info = OPCODES[op]
        if info.get("special") == "select":
            args = split_args(rest)
            if len(args) != 2:
                raise AsmError("第 %d 行: SELECT 需要 2 个参数" % i)
            b1 = parse_int(args[1])
            count = parse_int(args[0])
            opts = []
            got = 0
            while i < n:
                l2 = strip_comment(lines[i]).strip()
                i += 1
                if not l2:
                    continue
                if l2 == SELECT_END:
                    break
                if not l2.startswith("OPT "):
                    raise AsmError("第 %d 行: SELECT 块内只能是 OPT/SELECT_END" % i)
                a = split_args(l2[4:].strip())
                if len(a) < 3:
                    raise AsmError("第 %d 行: OPT 参数不足" % i)
                w = parse_int(a[0])
                t = parse_int(a[1])
                txt = unquote(a[2])
                if t == 7:
                    payload = ("str", unquote(a[3]))
                elif t in (3, 6):
                    payload = ("raw", [parse_int(x) for x in a[3:]])
                else:
                    raise AsmError("第 %d 行: OPT 类型 %d 未知" % (i, t))
                opts.append((w, t, txt, payload))
                got += 1
            else:
                raise AsmError("SELECT 块缺少 SELECT_END")
            if got != count:
                raise AsmError("SELECT 声明 %d 项，实际 %d 项" % (count, got))
            items.append({"kind": "select", "op": op, "b1": b1,
                          "count": count, "opts": opts, "line": i})
            continue
        args = split_args(rest) if rest else []
        fields = info["fields"]
        if len(args) != len(fields):
            raise AsmError("第 %d 行: %s 需要 %d 个参数，实际 %d 个"
                           % (i, mnem, len(fields), len(args)))
        items.append({"kind": "instr", "op": op, "args": args, "line": i})
    return items


def item_size(it, encoding):
    if it["kind"] in ("label", "encoding"):
        return 0
    if it["kind"] == "select":
        size = 3
        for w, t, txt, payload in it["opts"]:
            size += 2 + len(text_to_bytes(txt, encoding)) + 1 + 1
            if t == 7:
                size += len(text_to_bytes(payload[1], encoding)) + 1
            else:
                size += len(payload[1])
        return size
    op = it["op"]
    size = 1
    for (fname, typ), arg in zip(OPCODES[op]["fields"], it["args"]):
        if typ == "str":
            size += len(text_to_bytes(unquote(arg), encoding)) + 1
        elif typ == "u8":
            size += 1
        elif typ == "u16":
            size += 2
        elif typ in ("u32", "rel32", "abs32"):
            size += 4
    return size


# --------------------------------------------------------------------------
# 第二遍：编码
# --------------------------------------------------------------------------
def emit(items, encoding):
    # 第一遍: 计算地址
    pos = 0
    labels = {}
    for it in items:
        if it["kind"] == "label":
            if it["name"] in labels:
                raise AsmError("重复标签: %s" % it["name"])
            labels[it["name"]] = pos
        else:
            it["pos"] = pos
            it["size"] = item_size(it, encoding)
            pos += it["size"]
    total = pos

    out = bytearray()

    def num(arg, bits, name):
        v = parse_int(arg)
        if v < 0 or v >= (1 << bits):
            raise AsmError("%s 值超出范围: %s" % (name, arg))
        return v

    for it in items:
        if it["kind"] in ("label", "encoding"):
            continue
        if it["kind"] == "select":
            out.append(it["op"])
            out.append(it["count"] & 0xFF)
            out.append(it["b1"] & 0xFF)
            for w, t, txt, payload in it["opts"]:
                out += struct.pack("<H", w)
                out += text_to_bytes(txt, encoding) + b"\x00"
                out.append(t)
                if t == 7:
                    out += text_to_bytes(payload[1], encoding) + b"\x00"
                else:
                    if len(payload[1]) != (7 if t == 3 else 5):
                        raise AsmError("OPT type%d 载荷长度应为 %d"
                                       % (t, 7 if t == 3 else 5))
                    out += bytes(payload[1])
            continue
        op = it["op"]
        out.append(op)
        for (fname, typ), arg in zip(OPCODES[op]["fields"], it["args"]):
            if typ == "u8":
                out.append(num(arg, 8, fname))
            elif typ == "u16":
                out += struct.pack("<H", num(arg, 16, fname))
            elif typ == "u32":
                out += struct.pack("<I", num(arg, 32, fname))
            elif typ == "abs32":
                name = arg.strip()
                if name not in labels:
                    raise AsmError("未定义标签: %s" % name)
                out += struct.pack("<I", labels[name])
            elif typ == "rel32":
                name = arg.strip()
                if name not in labels:
                    raise AsmError("未定义标签: %s" % name)
                rel = labels[name] - (it["pos"] + it["size"])
                out += struct.pack("<i", rel)
            elif typ == "str":
                out += text_to_bytes(unquote(arg), encoding) + b"\x00"
        if len(out) != it["pos"] + it["size"]:
            raise AsmError("内部长度不一致 @ 0x%X" % it["pos"])
    if len(out) != total:
        raise AsmError("总长度不一致: %d != %d" % (len(out), total))
    return bytes(out)


# --------------------------------------------------------------------------
def default_scr_name(base):
    """默认输出名：TU17.scr.asm.txt -> TU17.scr；没有 .scr 后缀时补上。"""
    if base.lower().endswith(".scr"):
        return base
    return base + ".scr"


def process_file(path, out_path, encoding_override):
    with open(path, "r", encoding="utf-8-sig") as f:
        text = f.read()
    items = build_items(text)
    enc = encoding_override
    if enc is None:
        enc = "cp932"
        for it in items:
            if it["kind"] == "encoding":
                enc = it["value"]
                break
    data = emit(items, enc)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(data)
    return len(data)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Will Co. 语义汇编 -> .scr 字节码")
    ap.add_argument("input", help="asm.txt 文件或目录")
    ap.add_argument("-o", "--out", help="输出文件或目录")
    ap.add_argument("--encoding", default=None,
                    help="字符串输出编码 (默认读取 .encoding，缺省 cp932)")
    args = ap.parse_args(argv)

    try:
        if os.path.isdir(args.input):
            files = sorted(x for x in os.listdir(args.input)
                           if x.lower().endswith(".asm.txt"))
            if not files:
                print("目录中没有 .asm.txt 文件: %s" % args.input, file=sys.stderr)
                return 1
            outdir = args.out or args.input
            total = 0
            for fn in files:
                src = os.path.join(args.input, fn)
                base = fn[:-len(".asm.txt")]
                dst = os.path.join(outdir, default_scr_name(base))
                total += process_file(src, dst, args.encoding)
            print("汇编完成: %d 个文件, 共 %d 字节 -> %s" % (len(files), total, outdir))
        else:
            if not os.path.isfile(args.input):
                print("输入不存在: %s" % args.input, file=sys.stderr)
                return 1
            out = args.out
            if not out:
                base = args.input
                if base.lower().endswith(".asm.txt"):
                    base = base[:-len(".asm.txt")]
                else:
                    base = os.path.splitext(base)[0]
                out = default_scr_name(base)
            size = process_file(args.input, out, args.encoding)
            print("汇编完成: %s (%d 字节)" % (out, size))
    except (AsmError, ValueError) as e:
        print("错误: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
