#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
assembler.py - MIBOUJIN (Tanaka 系 SCB) 脚本汇编器

用法：
    python assembler.py <asm.txt 或目录> [-o <输出文件/目录>] [--encoding gbk]

输入为单个 asm.txt 时，默认输出 <脚本名>.rebuild；
输入为目录时，默认输出 <目录>_rebuild/ 下的 <脚本名>.rebuild。
asm.txt 按 UTF-8 读取，字符串按 --encoding 编码（默认 gbk，可用 --encoding cp932）。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import opcodelist

TEXT_CMDS = {v: k for k, v in opcodelist.TEXT_COMMANDS.items()}
FIXED_CP932_CMDS = {"LABEL", "CHAR", "ANGLE", "TITLE", "ENDING", "SCENE",
                    "SPEAKER", "BG", "SND"}


class AsmError(Exception):
    pass


def split_operands(s: str):
    parts = []
    cur = []
    i = 0
    quote = None
    while i < len(s):
        c = s[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "\"'":
            quote = c
            cur.append(c)
            i += 1
            continue
        if c == ",":
            parts.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    tail = "".join(cur).strip()
    if tail or parts:
        parts.append(tail)
    return parts


def unescape_string(s: str, encoding: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt in '"\\{':
                out += nxt.encode(encoding)
                i += 2
                continue
            raise AsmError("未知转义 \\%s" % nxt)
        if s.startswith("{{", i) and i + 4 < len(s) and s[i + 4:i + 6] == "}}":
            try:
                out.append(int(s[i + 2:i + 4], 16))
            except ValueError:
                raise AsmError("非法占位符 %s" % s[i:i + 6])
            i += 6
            continue
        try:
            out += s[i].encode(encoding)
        except UnicodeEncodeError:
            raise AsmError("字符 %r 无法用 %s 编码" % (s[i], encoding))
        i += 1
    return bytes(out)


def unescape_plain(body):
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] in '\\"{}':
            out.append(body[i + 1])
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def parse_string(tok: str, encoding: str) -> bytes:
    if len(tok) < 2 or tok[0] != '"' or tok[-1] != '"':
        raise AsmError("应为字符串: %s" % tok)
    return unescape_string(tok[1:-1], encoding)


def parse_op(tok: str) -> int:
    tok = tok.strip()
    if tok.startswith("'") and tok.endswith("'") and len(tok) == 3:
        return ord(tok[1])
    if tok.startswith('"') and tok.endswith('"') and len(tok) == 3:
        return ord(tok[1])
    return parse_int(tok)


def parse_int(tok: str) -> int:
    tok = tok.strip()
    try:
        return int(tok, 0)
    except ValueError:
        raise AsmError("应为整数: %s" % tok)


def need(v: int, lo: int, hi: int, what: str):
    if not (lo <= v <= hi):
        raise AsmError("%s 超出范围: %d" % (what, v))


def u16(v: int) -> bytes:
    need(v, 0, 0xFFFF, "u16")
    return bytes([v & 0xFF, (v >> 8) & 0xFF])


def u8(v: int) -> bytes:
    need(v, 0, 0xFF, "u8")
    return bytes([v])


def cstr(b: bytes) -> bytes:
    if b"\x00" in b:
        raise AsmError("C 字符串中不能含 0x00")
    return b + b"\x00"


def encode_instruction(mnemonic: str, ops, encoding: str, string_encoding=None) -> bytes:
    # 非可修改文本（SCENE/LABEL/...）默认按原 CP932 编码；
    # 章节名 LABEL 由 string_encoding 单独指定为 GBK。
    senc = string_encoding or ("cp932" if mnemonic in FIXED_CP932_CMDS else encoding)
    if mnemonic in TEXT_CMDS:
        cmd = TEXT_CMDS[mnemonic]
        if len(ops) != 1:
            raise AsmError("%s 需要 1 个字符串" % mnemonic)
        body = parse_string(ops[0], senc) + b"\x00"
        return bytes([2 + len(body), cmd]) + body

    if mnemonic == "LABEL":
        if len(ops) < 2:
            raise AsmError("LABEL 参数不足")
        pre = [parse_int(x) for x in ops[:-1]]
        text = parse_string(ops[-1], senc)
        if len(pre) != 2:
            raise AsmError("LABEL 前缀必须正好 2 字节")
        body = bytes(u8(x)[0] for x in pre) + text + b"\x00"
        return bytes([2 + len(body), 0x21]) + body

    if mnemonic == "CHAR":
        if len(ops) != 4:
            raise AsmError("CHAR 需要 4 个参数")
        name = parse_string(ops[0], senc)
        if len(name) != 4:
            raise AsmError("CHAR 名字必须正好 4 字节")
        body = name + u16(parse_int(ops[1])) + u16(parse_int(ops[2])) + u16(parse_int(ops[3]))
        return bytes([2 + len(body), 0x23]) + body

    if mnemonic == "ANGLE":
        if len(ops) != 5:
            raise AsmError("ANGLE 需要 5 个参数")
        body = u16(parse_int(ops[0])) + u16(parse_int(ops[1]))
        for x in ops[2:]:
            body += cstr(parse_string(x, senc))
        return bytes([2 + len(body), 0x24]) + body

    if mnemonic.startswith("IF_"):
        if mnemonic == "IF_F":
            if len(ops) != 2:
                raise AsmError("IF_F 需要 2 个参数")
            body = bytes([0x01, 0x46, parse_op(ops[0])]) + u16(parse_int(ops[1]))
        elif mnemonic == "IF_R":
            if len(ops) != 3:
                raise AsmError("IF_R 需要 3 个参数")
            body = bytes([0x01, 0x52, parse_op(ops[0])]) + u16(parse_int(ops[1])) + u16(parse_int(ops[2]))
        elif mnemonic == "IF_V":
            if len(ops) != 2:
                raise AsmError("IF_V 需要 2 个参数")
            body = bytes([parse_int(ops[0]) & 0xFF]) + u16(parse_int(ops[1]))
        elif mnemonic == "IF_C":
            if len(ops) != 1:
                raise AsmError("IF_C 需要 1 个参数")
            body = bytes([parse_int(ops[0]) & 0xFF])
        else:
            raise AsmError("未知指令 %s" % mnemonic)
        return bytes([2 + len(body), 0x2E]) + body

    if mnemonic == "RET":
        if len(ops) != 1:
            raise AsmError("RET 需要 1 个参数")
        body = u8(parse_int(ops[0]))
        return bytes([2 + len(body), 0x40]) + body

    if mnemonic == "CMD43":
        if len(ops) != 2:
            raise AsmError("CMD43 需要 2 个参数")
        body = u8(parse_int(ops[0])) + u8(parse_int(ops[1]))
        return bytes([2 + len(body), 0x43]) + body

    if mnemonic == "FLAG":
        if len(ops) != 2:
            raise AsmError("FLAG 需要 2 个参数")
        body = bytes([parse_op(ops[0])]) + u16(parse_int(ops[1]))
        return bytes([2 + len(body), 0x46]) + body

    if mnemonic == "BG":
        if len(ops) != 4:
            raise AsmError("BG 需要 4 个参数")
        body = u16(parse_int(ops[0])) + u16(parse_int(ops[1])) + u16(parse_int(ops[2]))
        body += cstr(parse_string(ops[3], senc))
        return bytes([2 + len(body), 0x47]) + body

    if mnemonic == "VAR":
        if len(ops) != 3:
            raise AsmError("VAR 需要 3 个参数")
        body = bytes([parse_op(ops[0])]) + u16(parse_int(ops[1])) + u16(parse_int(ops[2]))
        return bytes([2 + len(body), 0x52]) + body

    if mnemonic == "SND":
        if not ops:
            raise AsmError("SND 参数不足")
        kind = parse_op(ops[0])
        if kind == ord("M"):
            if len(ops) != 2:
                raise AsmError("SND 'M' 需要编号")
            body = b"M" + u16(parse_int(ops[1]))
        elif kind == ord("V"):
            if len(ops) != 4:
                raise AsmError("SND 'V' 需要子类型、名字和标志字节")
            body = b"V" + bytes([parse_op(ops[1])]) + b"\x00"
            body += cstr(parse_string(ops[2], senc)) + u8(parse_int(ops[3]))
        else:
            raise AsmError("SND 子类型只支持 'M' / 'V'")
        return bytes([2 + len(body), 0x57]) + body

    raise AsmError("未知指令 %s" % mnemonic)


def detect_encoding(lines, default):
    encoding = default
    for ln in lines:
        s = ln.strip()
        if s.startswith("; encoding:"):
            if not encoding:
                encoding = s.split(":", 1)[1].strip()
            break
        if s and not s.startswith(";"):
            break
    return encoding or "gbk"


def assemble_body(lines, encoding: str, base_lineno: int = 1,
                  special_labels=None, special_encoding=None) -> bytes:
    out = bytearray()
    ended = False
    for lineno, ln in enumerate(lines, base_lineno):
        s = ln.strip()
        if not s or s.startswith(";"):
            continue
        if s.startswith(".byte"):
            for tok in s[5:].split(","):
                tok = tok.strip()
                if tok:
                    out.append(parse_int(tok) & 0xFF)
            continue
        if s == "END":
            if ended:
                raise AsmError("第 %d 行: 重复 END" % lineno)
            out.append(0)
            ended = True
            continue
        if ended:
            raise AsmError("第 %d 行: END 之后只能有 .byte" % lineno)
        parts = s.split(None, 1)
        mnemonic = parts[0]
        ops = split_operands(parts[1]) if len(parts) > 1 else []
        str_enc = None
        if mnemonic == "LABEL" and special_labels and len(ops) >= 3:
            tok = ops[-1].strip()
            if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
                if unescape_plain(tok[1:-1]) in special_labels:
                    str_enc = special_encoding or encoding
        try:
            rec = encode_instruction(mnemonic, ops, encoding, str_enc)
        except AsmError as e:
            raise AsmError("第 %d 行: %s" % (lineno, e))
        if rec[0] != len(rec):
            raise AsmError("第 %d 行: 指令长度溢出" % lineno)
        out += rec
    if not ended:
        raise AsmError("缺少 END")
    return bytes(out)


def assemble_text(text: str, default_encoding):
    lines = text.splitlines()
    encoding = detect_encoding(lines, default_encoding)
    return assemble_body(lines, encoding)


def is_scb_asm(text: str) -> bool:
    return any(ln.strip() == ".table" for ln in text.splitlines())


def assemble_scb(text: str, default_encoding, editable=None, table_editable=None):
    import scb_format
    lines = text.splitlines()
    encoding = detect_encoding(lines, default_encoding)
    if editable is None:
        editable = set(range(58, 100))
    editable = set(editable)
    if table_editable is None:
        table_editable = editable
    table_editable = set(table_editable)

    table = {}
    table_rec = {}
    block_target = {}
    blocks = {}
    section = None
    block_lines = []
    block_idx = None
    count_hint = 0

    def flush_block():
        nonlocal block_lines, block_idx
        if block_idx is not None:
            enc = encoding if block_idx in editable else "cp932"
            special = {table[i] for i in table_editable if i in table}
            blocks[block_idx] = assemble_body(
                block_lines, enc, special_labels=special,
                special_encoding=encoding)
            target = block_target.get(block_idx)
            if target and len(blocks[block_idx]) < target:
                blocks[block_idx] += b"\x00" * (target - len(blocks[block_idx]))
        block_lines = []
        block_idx = None

    for lineno, ln in enumerate(lines, 1):
        s = ln.strip()
        if not s or s.startswith(";"):
            continue
        if s == ".header":
            flush_block()
            section = "header"
            continue
        if s == ".table":
            flush_block()
            section = "table"
            continue
        if s.startswith(".block"):
            flush_block()
            section = "block"
            head = s.split(";", 1)[0].strip()
            try:
                block_idx = int(head.split()[1])
            except Exception:
                raise AsmError("第 %d 行: .block 缺少序号" % lineno)
            if "; size=" in s:
                try:
                    block_target[block_idx] = int(s.split("; size=", 1)[1].strip())
                except ValueError:
                    raise AsmError("第 %d 行: size= 不是整数" % lineno)
            continue
        if section == "header":
            if s.startswith("count"):
                try:
                    count_hint = int(s.split()[1])
                except Exception:
                    pass
            continue
        if section == "table":
            rec_len = None
            if "; rec=" in s:
                s, meta = s.split("; rec=", 1)
                try:
                    rec_len = int(meta.strip())
                except ValueError:
                    raise AsmError("第 %d 行: rec= 不是整数" % lineno)
            parts = s.split(None, 1)
            if len(parts) != 2:
                raise AsmError("第 %d 行: 表项格式应为 序号 \"文本\"" % lineno)
            try:
                idx = int(parts[0])
            except ValueError:
                raise AsmError("第 %d 行: 表项序号不是整数" % lineno)
            name_tok = parts[1].strip()
            if len(name_tok) < 2 or name_tok[0] != '"' or name_tok[-1] != '"':
                raise AsmError("第 %d 行: 表项文本必须用双引号" % lineno)
            table[idx] = unescape_plain(name_tok[1:-1])
            if rec_len:
                table_rec[idx] = rec_len
            continue
        if section == "block":
            block_lines.append(ln)
            continue
        raise AsmError("第 %d 行: 不在任何段内: %s" % (lineno, s))
    flush_block()

    if not table:
        raise AsmError("缺少 .table")
    count = count_hint or len(table)
    if count != len(table) or len(blocks) != count:
        raise AsmError("表项 %d、块 %d、header count %d 不一致"
                       % (len(table), len(blocks), count))

    entries = []
    for i in range(count):
        if i not in table:
            raise AsmError("缺少表项 %d" % i)
        if i not in blocks:
            raise AsmError("缺少块 %d" % i)
        entries.append(scb_format.encode_title(
            table[i], encoding if i in table_editable else "cp932",
            table_rec.get(i)))
    block_payloads = [blocks[i] for i in range(count)]
    return scb_format.build(entries, block_payloads, encoding)


def parse_range(s):
    out = set()
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out


def assemble_file(path: Path, out_path: Path, encoding: str, scb_mode: bool = False,
                  editable=None, table_editable=None):
    text = path.read_text(encoding="utf-8")
    data = (assemble_scb(text, encoding, editable, table_editable)
            if scb_mode else assemble_text(text, encoding))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    kind = "SCB" if scb_mode else "script"
    print("汇编 %s: %s -> %s (%d 字节)" % (kind, path, out_path, len(data)))


def iter_inputs(src: Path):
    if src.is_dir():
        for p in sorted(src.iterdir()):
            if p.is_file() and p.name.endswith(".asm.txt"):
                yield p
    else:
        yield src


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description="MIBOUJIN SCB 脚本汇编器")
    ap.add_argument("input", nargs="?")
    ap.add_argument("-o", "--output")
    ap.add_argument("--encoding", default=None)
    ap.add_argument("--editable", default="58-99",
                    help="可修改文本的块序号，默认 58-99；其余保持 CP932")
    ap.add_argument("--table-editable", default=None,
                    help="可修改的 .table 序号，默认与 --editable 相同；空串表示全部保持 CP932")
    args = ap.parse_args(argv)

    if not args.input:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        args.input = filedialog.askdirectory(title="选择 asm 目录") or filedialog.askopenfilename()
        root.destroy()
        if not args.input:
            return 2

    src = Path(args.input)
    if not src.exists():
        print("错误: 找不到 %s" % src, file=sys.stderr)
        return 2

    enc = args.encoding
    editable = parse_range(args.editable)
    table_editable = (None if args.table_editable is None
                      else parse_range(args.table_editable))
    try:
        if src.is_file():
            stem = src.name
            if stem.endswith(".asm.txt"):
                stem = stem[:-8]
            elif stem.endswith(".txt"):
                stem = stem[:-4]
            scb_mode = is_scb_asm(src.read_text(encoding="utf-8"))
            if args.output and Path(args.output).is_dir():
                out = Path(args.output) / (stem + (".rebuild.SCB" if scb_mode else ".rebuild"))
            else:
                out = (Path(args.output) if args.output
                       else src.with_name(stem + (".rebuild.SCB" if scb_mode else ".rebuild")))
            assemble_file(src, out, enc, scb_mode, editable, table_editable)
        else:
            outdir = Path(args.output) if args.output else src.with_name(src.name + "_rebuild")
            for p in iter_inputs(src):
                stem = p.name[:-8] if p.name.endswith(".asm.txt") else p.stem
                try:
                    scb_mode = is_scb_asm(p.read_text(encoding="utf-8"))
                    suffix = ".rebuild.SCB" if scb_mode else ".rebuild"
                    assemble_file(p, outdir / (stem + suffix), enc, scb_mode,
                                  editable, table_editable)
                except AsmError as e:
                    print("错误: %s: %s" % (p, e), file=sys.stderr)
                    return 1
    except AsmError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
