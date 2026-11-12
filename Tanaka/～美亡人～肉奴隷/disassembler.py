#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
disassembler.py - MIBOUJIN (Tanaka 系 SCB) 脚本反汇编器

用法：
    python disassembler.py <脚本文件或目录> [-o <输出目录或文件>] [--encoding cp932]

输入为单个脚本时，默认输出 <脚本>.asm.txt；
输入为目录时，默认输出 <目录>_asm/ 下的 <脚本名>.asm.txt。
输出的 asm.txt 为 UTF-8，文本字符串按 --encoding 解码。
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

import opcodelist

TEXT_CMDS = set(opcodelist.TEXT_COMMANDS)


class AsmError(Exception):
    pass


def _is_lead(b: int, encoding: str) -> bool:
    e = encoding.lower().replace("_", "-")
    if e in ("cp932", "shift-jis", "shiftjis", "sjis", "ms932", "windows-31j"):
        return 0x81 <= b <= 0x9F or 0xE0 <= b <= 0xFC
    if e.startswith("gb") or e in ("cp936", "euc-cn"):
        return 0x81 <= b <= 0xFE
    return b >= 0x81


def decode_text(buf: bytes, encoding: str) -> str:
    """把文本字节转成可读字符串；不可安全还原的字节写成 {{XX}}。"""
    out = []
    i = 0
    n = len(buf)
    while i < n:
        b = buf[i]
        if b < 0x20 or b == 0x7F:
            out.append("{{%02X}}" % b)
            i += 1
        elif _is_lead(b, encoding) and i + 1 < n:
            pair = buf[i:i + 2]
            try:
                ch = pair.decode(encoding)
            except Exception:
                ch = None
            if ch is not None and len(ch) == 1 and ch.encode(encoding) == pair:
                out.append(ch)
                i += 2
                continue
            out.append("{{%02X}}" % b)
            i += 1
        elif b < 0x80:
            ch = chr(b)
            if ch == '"':
                out.append('\\"')
            elif ch == "\\":
                out.append("\\\\")
            elif ch == "{":
                out.append("\\{")
            else:
                out.append(ch)
            i += 1
        else:
            out.append("{{%02X}}" % b)
            i += 1
    return "".join(out)


def qtext(buf: bytes, encoding: str) -> str:
    return '"' + decode_text(buf, encoding) + '"'


def u16(buf: bytes, pos: int) -> int:
    if pos + 2 > len(buf):
        raise AsmError("u16 越界")
    return buf[pos] | (buf[pos + 1] << 8)


def cstr(buf: bytes, pos: int, encoding: str):
    end = buf.find(b"\x00", pos)
    if end < 0:
        raise AsmError("缺少字符串终止符")
    return qtext(buf[pos:end], encoding), end + 1


def fmt_op(ch: int) -> str:
    c = chr(ch)
    if c == "'":
        return '"\'"'
    return "'%s'" % c


def format_instruction(cmd: int, a: bytes, encoding: str) -> str:
    if cmd in TEXT_CMDS:
        if not a or a[-1] != 0:
            raise AsmError("文本命令缺少 0x00 结尾")
        return "%s %s" % (opcodelist.TEXT_COMMANDS[cmd], qtext(a[:-1], encoding))

    if cmd == 0x21:  # LABEL
        if len(a) < 3 or a[-1] != 0:
            raise AsmError("LABEL 参数错误")
        # 样本中前缀恒为 2 字节：00 00 / 00 40 / 21 40
        pre = 2
        parts = ["0x%02X" % b for b in a[:pre]]
        parts.append(qtext(a[pre:-1], encoding))
        return "LABEL " + ", ".join(parts)

    if cmd == 0x23:  # CHAR
        if len(a) != 10:
            raise AsmError("CHAR 长度错误")
        return "CHAR %s, %d, %d, %d" % (
            qtext(a[:4], encoding), u16(a, 4), u16(a, 6), u16(a, 8))

    if cmd == 0x24:  # ANGLE
        s1, p = cstr(a, 4, encoding)
        s2, p = cstr(a, p, encoding)
        s3, p = cstr(a, p, encoding)
        if p != len(a):
            raise AsmError("ANGLE 尾部多余字节")
        return "ANGLE %d, %d, %s, %s, %s" % (u16(a, 0), u16(a, 2), s1, s2, s3)

    if cmd == 0x2E:  # IF
        if not a:
            raise AsmError("IF 无参数")
        mode = a[0]
        if mode == 0x01 and len(a) >= 2:
            sub = a[1]
            if sub == 0x46 and len(a) == 5:
                return "IF_F %s, %d" % (fmt_op(a[2]), u16(a, 3))
            if sub == 0x52 and len(a) == 7:
                return "IF_R %s, %d, %d" % (fmt_op(a[2]), u16(a, 3), u16(a, 5))
            raise AsmError("IF 子码 1 未知: %02X" % sub)
        if mode in (0x05, 0x06):
            if len(a) != 3:
                raise AsmError("IF_V 长度错误")
            return "IF_V %d, %d" % (mode, u16(a, 1))
        if len(a) != 1:
            raise AsmError("IF 单字节码长度错误")
        return "IF_C %d" % mode

    if cmd == 0x40:  # RET
        if len(a) != 1:
            raise AsmError("RET 长度错误")
        return "RET %d" % a[0]

    if cmd == 0x43:
        if len(a) != 2:
            raise AsmError("CMD43 长度错误")
        return "CMD43 %d, %d" % (a[0], a[1])

    if cmd == 0x46:  # FLAG
        if len(a) != 3:
            raise AsmError("FLAG 长度错误")
        return "FLAG %s, %d" % (fmt_op(a[0]), u16(a, 1))

    if cmd == 0x47:  # BG
        s, p = cstr(a, 6, encoding)
        if p != len(a):
            raise AsmError("BG 尾部多余字节")
        return "BG %d, %d, %d, %s" % (u16(a, 0), u16(a, 2), u16(a, 4), s)

    if cmd == 0x52:  # VAR
        if len(a) != 5:
            raise AsmError("VAR 长度错误")
        return "VAR %s, %d, %d" % (fmt_op(a[0]), u16(a, 1), u16(a, 3))

    if cmd == 0x57:  # SND
        if not a:
            raise AsmError("SND 无参数")
        kind = a[0]
        if kind == ord("M") and len(a) == 3:
            return "SND 'M', %d" % u16(a, 1)
        if kind == ord("V"):
            s, p = cstr(a, 3, encoding)
            if p + 1 != len(a):
                raise AsmError("SND 'V' 尾部格式错误")
            return "SND 'V', %s, %s, %d" % (fmt_op(a[1]), s, a[p])
        raise AsmError("SND 未知子类型 %02X" % kind)

    raise AsmError("未知指令 0x%02X" % cmd)


def disassemble_bytes(data: bytes, encoding: str, source_name: str = "",
                      include_header: bool = True):
    lines = []
    i = 0
    n = len(data)
    terminated = False
    while i < n:
        if data[i] == 0:
            terminated = True
            i += 1
            break
        L = data[i]
        if L < 2:
            raise AsmError("偏移 0x%X: 指令长度 %d 非法" % (i, L))
        if i + L > n:
            raise AsmError("偏移 0x%X: 指令越过文件末尾" % i)
        cmd = data[i + 1]
        args = data[i + 2:i + L]
        lines.append(format_instruction(cmd, args, encoding))
        i += L

    if not terminated:
        raise AsmError("脚本缺少 0x00 结束符")

    out = []
    if include_header:
        out.append("; MIBOUJIN script")
        if source_name:
            out.append("; source: %s" % source_name)
        out.append("; encoding: %s" % encoding)
        out.append("; size: %d" % n)
        out.append("; sha256: %s" % hashlib.sha256(data).hexdigest())
        out.append("")
    out.extend(lines)
    out.append("END")
    pad = data[i:]
    if pad:
        out.append(".byte " + ", ".join("0x%02X" % b for b in pad))
    if include_header:
        out.append("")
    return "\n".join(out), i


def quote_text(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("{", "\\{") + '"'


def disassemble_scb(path: Path, out_path: Path, encoding: str):
    import scb_format
    scb = scb_format.ScbFile(path.read_bytes(), encoding)
    out = [
        "; MIBOUJIN.SCB container",
        "; encoding: %s" % encoding,
        "; blocks: %d" % scb.count,
        "",
        ".header",
        "count %d" % scb.count,
        "",
        ".table",
    ]
    for e in scb.entries:
        name = scb_format.decode_text(e["payload"], encoding)
        out.append('%d %s ; rec=%d' % (e["index"], quote_text(name),
                                        e["record_size"] - 4))
    out.append("")
    for i, b in enumerate(scb.blocks):
        body, _ = disassemble_bytes(b["payload"], encoding, include_header=False)
        out.append(".block %d ; size=%d" % (i, len(b["payload"])))
        out.append(body)
        out.append("")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    print("反汇编 SCB: %s -> %s (%d 块)" % (path, out_path, scb.count))


def disassemble_file(path: Path, out_path: Path, encoding: str):
    data = path.read_bytes()
    text, _ = disassemble_bytes(data, encoding, path.name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8", newline="\n")
    print("反汇编: %s -> %s (%d 字节)" % (path, out_path, len(data)))


def iter_inputs(src: Path):
    if src.is_dir():
        for p in sorted(src.iterdir()):
            if p.is_file() and p.name != "scb.json" and not p.name.endswith(".asm.txt"):
                yield p
    else:
        yield src


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description="MIBOUJIN SCB 脚本反汇编器")
    ap.add_argument("input", nargs="?")
    ap.add_argument("-o", "--output")
    ap.add_argument("--encoding", default="cp932")
    args = ap.parse_args(argv)

    if not args.input:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        args.input = filedialog.askdirectory(title="选择脚本目录") or filedialog.askopenfilename()
        root.destroy()
        if not args.input:
            return 2

    src = Path(args.input)
    if not src.exists():
        print("错误: 找不到 %s" % src, file=sys.stderr)
        return 2

    try:
        if src.is_file():
            is_scb = src.suffix.lower() == ".scb"
            if args.output and Path(args.output).is_dir():
                out = Path(args.output) / ((src.stem if is_scb else src.name) + ".asm.txt")
            else:
                out = (Path(args.output) if args.output
                       else src.with_name((src.stem if is_scb else src.name) + ".asm.txt"))
            if is_scb:
                disassemble_scb(src, out, args.encoding)
            else:
                disassemble_file(src, out, args.encoding)
        else:
            outdir = Path(args.output) if args.output else src.with_name(src.name + "_asm")
            for p in iter_inputs(src):
                try:
                    disassemble_file(p, outdir / (p.name + ".asm.txt"), args.encoding)
                except AsmError as e:
                    print("错误: %s: %s" % (p, e), file=sys.stderr)
                    return 1
    except AsmError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
