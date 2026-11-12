#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scb_tool.py - MIBOUJIN.SCB 解包 / 重封包工具

封包结构（little-endian，证据来自 MIBOUJIN.EXE 的 sub_409BCC / sub_40A2A0）：

    0x00 u32 file_size | 0x04 u32 count | 0x08 u32 table_size
    0x0C u32 max_block_size
    0x10 字符串表 count 条：{u32 block_offset, u8 record_len, u8[record_len-1] 文本}
    之后 脚本块 count 个：{u32 block_size, u8[block_size-4] 脚本}

本样本无压缩/无加密。

用法（与“其他示例”的 Tanaka SCB 工具风格一致）：

    python scb_tool.py info   MIBOUJIN.SCB
    python scb_tool.py unpack MIBOUJIN.SCB          -> MIBOUJIN/ + MIBOUJIN.titles.txt
    python scb_tool.py titles MIBOUJIN.SCB          -> 单独导出 MIBOUJIN.titles.txt
    python scb_tool.py pack   MIBOUJIN.SCB          -> new/MIBOUJIN.SCB
    python scb_tool.py pack   MIBOUJIN -o out.SCB   -> 同上，显式指定原始包
    python scb_tool.py verify MIBOUJIN.SCB

标题表 <封包名>.titles.txt 放在封包文件夹**外面**，一行一条：
    「序号<TAB>文本」。pack 时自动读取并应用到字符串表，不需要逐个改。

脚本目录结构：
    MIBOUJIN/            与封包同名，里面只有脚本文件
    MIBOUJIN.titles.txt  标题表（UTF-8，可整批编辑）

解包目录：与封包同名的文件夹，里面只有脚本文件，文件名就是章节/场景名，
没有扩展名，也没有 json / strings 等附加文件。

重封包时以原始 SCB 的表项顺序和名字为准，用同名脚本文件替换对应块；
文件不存在则沿用原块。脚本长度变化会同步重算块偏移、块大小和头部字段。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import sys
import tempfile
from pathlib import Path

from scb_format import (
    ALIGN,
    HEADER_SIZE,
    ScbError,
    ScbFile,
    decode_text as _decode_text,
    encode_title as _encode_title,
    safe_name as _safe_name,
)

ScbArchive = ScbFile


def cmd_info(args):
    data = Path(args.input).read_bytes()
    encoding = getattr(args, "encoding", None) or "cp932"
    scb = ScbArchive(data, encoding)
    print("文件: %s" % args.input)
    print("大小: 0x%X (%d)" % (scb.file_size, scb.file_size))
    print("条目/脚本块数: %d" % scb.count)
    print("字符串表: 0x10 - 0x%X (0x%X 字节)" % (scb.data_offset, scb.table_size))
    print("脚本块区: 0x%X - 0x%X" % (scb.data_offset, scb.file_size))
    print("最大脚本块: 0x%X (%d)" % (scb.max_block_size, scb.max_block_size))
    print("压缩/加密: 无（脚本块与字符串表均为明文，文本编码 %s）" % encoding)
    print("")
    print("idx  block_off  rec  block  text")
    for e, b in zip(scb.entries, scb.blocks):
        print("%3d  0x%08X  %3d  %5d  %s"
              % (e["index"], e["block_offset"], e["record_size"], b["size"],
                 _decode_text(e["payload"], encoding)))


def _titles_path_for(scb_path: Path) -> Path:
    return scb_path.with_suffix(".titles.txt")


def _encode_title(text: str, encoding: str = "cp932") -> bytes:
    try:
        raw = text.encode(encoding) + b"\x00"
    except UnicodeEncodeError:
        # GBK 不含 '・' 等日文符号；汉化标题里换掉即可，这里用 '?' 占位
        raw = text.encode(encoding, errors="replace") + b"\x00"
    while (4 + 1 + len(raw)) % ALIGN != 0:
        raw += b"\x00"
    if len(raw) > 0xFE:
        raise ScbError("标题过长（最多约 240 字节）")
    return raw


def export_titles(scb: ScbArchive, path: Path, encoding: str = "cp932"):
    lines = [
        "# MIBOUJIN.SCB 标题表（文本编码: %s）" % encoding,
        "# encoding: %s" % encoding,
        "# 格式：序号<TAB>文本；只改 TAB 后面的文字，序号不要动",
        "# 空行和 # 开头的行会被忽略",
        "",
    ]
    for e in scb.entries:
        lines.append("%d\t%s" % (e["index"], _decode_text(e["payload"], scb.encoding)))
    path.write_text("\n".join(lines) + "\n", encoding=encoding,
                    errors="replace", newline="\n")
    print("标题表已导出: %s（%d 条，%s）" % (path, scb.count, encoding))


def _titles_encoding(path: Path, default: str = "cp932") -> str:
    """读取标题表头部 `# encoding: xxx`，没有则用 default。"""
    raw = path.read_bytes()
    for line in raw.splitlines()[:8]:
        s = line.decode("ascii", "ignore").strip()
        if s.lower().startswith("# encoding:"):
            enc = s.split(":", 1)[1].strip()
            if enc:
                return enc
    return default


def read_titles(path: Path, encoding: str | None = None) -> dict:
    enc = encoding or _titles_encoding(path)
    overrides = {}
    for lineno, line in enumerate(path.read_text(encoding=enc).splitlines(), 1):
        s = line.rstrip("\r\n")
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        if "\t" in s:
            head, text = s.split("\t", 1)
        else:
            parts = s.split(None, 1)
            if len(parts) != 2:
                raise ScbError("%s 第 %d 行格式应为「序号<TAB>文本」" % (path, lineno))
            head, text = parts
        try:
            idx = int(head.strip())
        except ValueError:
            raise ScbError("%s 第 %d 行序号不是整数: %r" % (path, lineno, head))
        if text.strip() == "":
            continue
        overrides[idx] = _encode_title(text, enc)
    return overrides


def cmd_titles(args):
    src = Path(args.input)
    encoding = getattr(args, "encoding", None) or "cp932"
    scb_encoding = getattr(args, "scb_encoding", None) or "cp932"
    scb = ScbArchive(src.read_bytes(), scb_encoding)
    out = Path(args.output) if args.output else _titles_path_for(src)
    if out.exists() and not args.force and args.output is None:
        raise ScbError("标题表已存在: %s（加 --force 覆盖）" % out)
    export_titles(scb, out, encoding)
    return 0


def cmd_unpack(args):
    src = Path(args.input)
    encoding = getattr(args, "encoding", None) or "cp932"
    scb = ScbArchive(src.read_bytes(), encoding)
    out = Path(args.output) if args.output else src.with_name(src.stem)
    if out.exists():
        if not args.force:
            raise ScbError("输出目录已存在: %s（加 --force 覆盖）" % out)
        shutil.rmtree(out)
    out.mkdir(parents=True)

    names = scb.names()
    for name, block in zip(names, scb.blocks):
        (out / name).write_bytes(block["payload"])

    print("解包完成: %s" % out)
    print("  %d 个脚本，文件名即章节/场景名，无后缀、无附加文件" % len(names))

    if getattr(args, "write_titles", True):
        titles = _titles_path_for(src)
        if titles.exists() and not getattr(args, "refresh_titles", False):
            print("  标题表已存在，保留你的修改: %s（--refresh-titles 可覆盖）" % titles)
        else:
            export_titles(scb, titles, encoding)
    return 0


def _align_block(payload: bytes) -> bytes:
    """块负载补齐到 4 字节；0x00 结束符之后的填充不会被 VM 执行。"""
    pad = (-len(payload)) % ALIGN
    return payload + b"\x00" * pad


def _pack_from_reference(scb: ScbArchive, folder: Path, out: Path, title_payloads=None):
    names = scb.names()
    title_payloads = title_payloads or {}

    table = bytearray()
    positions = []
    for e in scb.entries:
        positions.append(len(table))
        payload = title_payloads.get(e["index"], e["payload"])
        rec_len = 1 + len(payload)
        if rec_len > 0xFF:
            raise ScbError("条目 %d 名字过长" % e["index"])
        table += b"\x00\x00\x00\x00"
        table += bytes([rec_len])
        table += payload

    data_offset = HEADER_SIZE + len(table)
    pad = (-data_offset) % 0x100
    if pad:
        table += b"\x00" * pad
    table_size = len(table)
    data_offset = HEADER_SIZE + table_size

    blocks_area = bytearray()
    max_block = 0
    pos = data_offset
    replaced = 0
    missing = []
    for e, name, block in zip(scb.entries, names, scb.blocks):
        p = folder / name
        if p.is_file():
            payload = _align_block(p.read_bytes())
            replaced += 1
        else:
            payload = block["payload"]
            missing.append(name)
        size = 4 + len(payload)
        struct.pack_into("<I", table, positions[e["index"]], pos)
        blocks_area += struct.pack("<I", size) + payload
        max_block = max(max_block, size)
        pos += size

    total = HEADER_SIZE + table_size + len(blocks_area)
    header = struct.pack("<4I", total, scb.count, table_size, max_block)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(header + bytes(table) + bytes(blocks_area))
    print("重封包完成: %s" % out)
    print("  大小 0x%X，替换 %d/%d 个脚本%s，标题修改 %d 条"
          % (total, replaced, scb.count,
             "" if not missing else "，%d 个沿用原块" % len(missing),
             len(title_payloads)))
    return 0


def _pack_from_legacy(src: Path, out: Path):
    """兼容旧版解包目录（scb.json + strings/ + blocks/）。"""
    meta = json.loads((src / "scb.json").read_text(encoding="utf-8"))
    entries = sorted(meta["entries"], key=lambda e: e["index"])
    count = len(entries)

    table = bytearray()
    entry_pos = {}
    for e in entries:
        i = e["index"]
        rel = e.get("string_file") or ("strings/%03d.bin" % i)
        p = src / rel
        if not p.exists():
            p = src / "strings" / ("%03d.bin" % i)
        payload = p.read_bytes()
        pad = (-(4 + 1 + len(payload))) % ALIGN
        rec_len = 1 + len(payload) + pad
        if rec_len > 0xFF:
            raise ScbError("第 %d 条字符串记录过长" % i)
        entry_pos[i] = len(table)
        table += b"\x00\x00\x00\x00"
        table += bytes([rec_len])
        table += payload + b"\x00" * pad

    data_offset = HEADER_SIZE + len(table)
    pad = (-data_offset) % 0x100
    if pad:
        table += b"\x00" * pad
    table_size = len(table)
    data_offset = HEADER_SIZE + table_size
    blocks_area = bytearray()
    max_block = 0
    pos = data_offset
    for e in entries:
        i = e["index"]
        rel = e.get("block_file") or ("blocks/%03d.bin" % i)
        p = src / rel
        if not p.exists():
            p = src / "blocks" / ("%03d.bin" % i)
        payload = _align_block(p.read_bytes())
        size = 4 + len(payload)
        struct.pack_into("<I", table, entry_pos[i], pos)
        blocks_area += struct.pack("<I", size) + payload
        max_block = max(max_block, size)
        pos += size

    total = HEADER_SIZE + table_size + len(blocks_area)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(
        struct.pack("<4I", total, count, table_size, max_block)
        + bytes(table) + bytes(blocks_area)
    )
    print("重封包完成（旧版目录）: %s" % out)
    return 0


def _locate_pack_inputs(input_path: Path, scb_arg: str | None):
    """返回 (原始 SCB 路径, 脚本目录)。目录模式下找不到 SCB 则返回 (None, 目录)。"""
    if input_path.is_file():
        folder = input_path.with_name(input_path.stem)
        return input_path, folder
    folder = input_path
    if scb_arg:
        return Path(scb_arg), folder
    cand = folder.with_name(folder.name + ".SCB")
    if cand.is_file():
        return cand, folder
    cand2 = folder.with_name(folder.name + ".scb")
    if cand2.is_file():
        return cand2, folder
    return None, folder


def cmd_pack(args):
    src = Path(args.input)
    scb_path, folder = _locate_pack_inputs(src, args.scb)
    if scb_path is None:
        if (folder / "scb.json").exists():
            out = Path(args.output) if args.output else folder.with_name("new") / (folder.name + ".SCB")
            return _pack_from_legacy(folder, out)
        raise ScbError(
            "找不到原始 SCB：请把 %s.SCB 放在同级目录，或用 --scb 指定" % folder.name
        )
    encoding = getattr(args, "encoding", None) or "cp932"
    src_enc = getattr(args, "scb_encoding", None) or "cp932"
    scb = ScbArchive(scb_path.read_bytes(), src_enc)
    out = Path(args.output) if args.output else scb_path.with_name("new") / scb_path.name

    overrides = {}
    titles_path = None
    if not getattr(args, "no_titles", False):
        titles_arg = getattr(args, "titles", None)
        if titles_arg:
            titles_path = Path(titles_arg)
        else:
            cand = _titles_path_for(scb_path)
            if cand.exists():
                titles_path = cand
        if titles_path:
            if not titles_path.exists():
                raise ScbError("找不到标题表: %s" % titles_path)
            overrides = read_titles(titles_path, getattr(args, "encoding", None))
            bad = [i for i in overrides if i < 0 or i >= scb.count]
            if bad:
                raise ScbError("标题表序号越界: %s" % bad[:5])
            # 只保留真正改动的条目，避免无谓重编码
            overrides = {
                i: p for i, p in overrides.items()
                if p != scb.entries[i]["payload"]
            }
            print("使用标题表: %s（实际修改 %d 条）" % (titles_path, len(overrides)))
    return _pack_from_reference(scb, folder, out, overrides)


def cmd_title(args):
    """修改字符串表里某一条的文本（章节名/菜单名），块内容不变。"""
    src = Path(args.input)
    encoding = getattr(args, "encoding", None) or "cp932"
    scb = ScbArchive(src.read_bytes(), encoding)
    idx = args.index
    if idx < 0:
        idx += scb.count
    if not 0 <= idx < scb.count:
        raise ScbError("条目序号越界: %d（共 %d 条）" % (args.index, scb.count))

    old = _decode_text(scb.entries[idx]["payload"], encoding)
    raw = _encode_title(args.text, encoding)

    table = bytearray()
    positions = []
    for e in scb.entries:
        payload = raw if e["index"] == idx else e["payload"]
        positions.append(len(table))
        table += b"\x00\x00\x00\x00"
        table += bytes([1 + len(payload)])
        table += payload

    data_offset = HEADER_SIZE + len(table)
    pad = (-data_offset) % 0x100
    if pad:
        table += b"\x00" * pad
    table_size = len(table)
    pos = HEADER_SIZE + table_size
    blocks_area = bytearray()
    max_block = 0
    for e, b in zip(scb.entries, scb.blocks):
        payload = b["payload"]
        size = 4 + len(payload)
        struct.pack_into("<I", table, positions[e["index"]], pos)
        blocks_area += struct.pack("<I", size) + payload
        max_block = max(max_block, size)
        pos += size

    total = HEADER_SIZE + table_size + len(blocks_area)
    out = Path(args.output) if args.output else src.with_name("new") / src.name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(
        struct.pack("<4I", total, scb.count, table_size, max_block)
        + bytes(table) + bytes(blocks_area)
    )
    print("修改条目 %d: %s -> %s" % (idx, old, args.text))
    print("输出: %s (0x%X 字节)" % (out, total))
    return 0


def cmd_verify(args):
    src = Path(args.input)
    data = src.read_bytes()
    encoding = getattr(args, "encoding", None) or "cp932"
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        folder = tmp / src.stem
        cmd_unpack(argparse.Namespace(input=str(src), output=str(folder), force=True,
                                      encoding=encoding, refresh_titles=True,
                                      write_titles=False))
        rebuilt = tmp / "new" / src.name
        cmd_pack(argparse.Namespace(input=str(src), output=str(rebuilt), scb=None,
                                    titles=None, no_titles=True, encoding=encoding))
        new = rebuilt.read_bytes()
    same = new == data
    print("原始 SHA-256:   %s" % hashlib.sha256(data).hexdigest())
    print("重建 SHA-256:   %s" % hashlib.sha256(new).hexdigest())
    print("字节级一致: %s" % ("是" if same else "否"))
    return 0 if same else 1


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    p = argparse.ArgumentParser(description="MIBOUJIN.SCB 解包/重封包工具")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("info", help="查看封包结构")
    s.add_argument("input")
    s.add_argument("--encoding", default="cp932", help="文本编码，默认 cp932；GBK 用 gbk")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("unpack", help="解包为同名目录（只有脚本文件）")
    s.add_argument("input")
    s.add_argument("-o", "--output")
    s.add_argument("--force", action="store_true")
    s.add_argument("--encoding", default="cp932")
    s.add_argument("--refresh-titles", action="store_true",
                   help="覆盖已存在的 <封包名>.titles.txt")
    s.set_defaults(func=cmd_unpack)

    s = sub.add_parser("titles", help="单独导出标题表")
    s.add_argument("input")
    s.add_argument("-o", "--output")
    s.add_argument("--force", action="store_true")
    s.add_argument("--encoding", default="cp932", help="标题表文本编码，GBK 用 gbk")
    s.add_argument("--scb-encoding", default="cp932", help="原始 SCB 字符串表编码")
    s.set_defaults(func=cmd_titles)

    s = sub.add_parser("pack", help="用同名脚本目录重封包")
    s.add_argument("input", help="原始 SCB，或解包目录")
    s.add_argument("-o", "--output")
    s.add_argument("--scb", help="显式指定原始 SCB")
    s.add_argument("--titles", help="标题表路径（默认自动找 <封包名>.titles.txt）")
    s.add_argument("--no-titles", action="store_true", help="忽略标题表")
    s.add_argument("--encoding", default=None,
                   help="标题表编码（默认读文件头，缺省 cp932；GBK 用 gbk）")
    s.add_argument("--scb-encoding", default="cp932",
                   help="原始 SCB 字符串表的编码，默认 cp932")
    s.set_defaults(func=cmd_pack)

    s = sub.add_parser("title", help="修改章节/菜单标题（字符串表条目）")
    s.add_argument("input")
    s.add_argument("index", type=int, help="条目序号，从 0 开始；-1 表示最后一条")
    s.add_argument("text", help="新标题")
    s.add_argument("-o", "--output")
    s.add_argument("--encoding", default="cp932", help="新标题编码，GBK 用 gbk")
    s.set_defaults(func=cmd_title)

    s = sub.add_parser("verify", help="解包->重封包->逐字节验证")
    s.add_argument("input")
    s.add_argument("--encoding", default="cp932")
    s.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except ScbError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
