#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract.py — 从 .scr 直接提取 json（一页一条 message）
=====================================================

VNOVEL 脚本本身就是「xor 0x44 之后的纯文本」：CRLF 分行的命令/注释/对白，
跳转全部走标签，所以增删行安全，不需要反汇编。本工具直接：

    .scr（解密）→ 按行分类 → 对白按“页”合并 → json

规则：

  * 只提取对白行；``;`` 注释、``:`` 标签、``#`` 命令、空行不提取；
  * 一页一条 message：页首是 ``　`` / ``「`` / ``（`` / ``『``，页尾是 ``●▲`` / ``▲`` / ``■``；
  * 页尾标记从 message 剥离，注入时补回；``　`` 缩进单独记在 ``indent``；
  * ``「●``（引号单独一行 + 停顿符）与后面同一页正文合并成一条；
  * 章节标题（``;第二章…■``）默认不提取——它们画在背景图里。

用法：

    python extract.py Scr -o json_jp
    python extract.py Scr/S00_01.scr -o json_jp --encoding cp932
    python extract.py Scr -o json_jp --recursive
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

CIPHER_KEY = 0x44
SCR_SUFFIX = ".scr"

# 页尾标记（出现在行末、不属于正文）
MARKERS = "\u25cf\u25b2\u25a0"          # ● ▲ ■

# 页首字符：全角空格缩进、开引号/开括号
PAGE_OPEN = "\u3000\u300c\uff08\u300e"  # 　「（『

TITLE_RE = re.compile(r"^第[0-9一二三四五六七八九十百千]+章")
ENDING_RE = re.compile(r"^完$")


# ---------------------------------------------------------------------------
# 文件读写（xor 0x44）
# ---------------------------------------------------------------------------

def is_plain(raw: bytes) -> bool:
    """首字节是 ';' 时引擎按明文处理，否则整个文件 xor 0x44。"""
    return raw[:1] == b";"


def read_scr(path: Path):
    """按字节切行。返回 (行字节列表, 换行符, 是否保留末尾换行, 是否明文)。"""
    raw = path.read_bytes()
    plain = raw if is_plain(raw) else bytes(b ^ CIPHER_KEY for b in raw)
    eol = b"\r\n" if b"\r\n" in plain else b"\n"
    final_newline = plain.endswith(eol)
    body = plain[: -len(eol)] if final_newline else plain
    return body.split(eol), eol, final_newline, is_plain(raw)


def write_scr(path: Path, byte_lines, eol, final_newline, plain: bool):
    data = eol.join(byte_lines) + (eol if final_newline else b"")
    if not plain:
        data = bytes(b ^ CIPHER_KEY for b in data)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def decode_file(path: Path, encoding: str):
    """返回 (行文本列表, 换行符, 是否保留末尾换行, 是否明文)。"""
    byte_lines, eol, final_newline, plain = read_scr(path)
    return [x.decode(encoding) for x in byte_lines], eol, final_newline, plain


# ---------------------------------------------------------------------------
# 行分类
# ---------------------------------------------------------------------------

def classify(line: str):
    """把一行拆成 (kind, payload)。kind: T 对白 / C 注释 / L 标签 / I 命令 / O 空行。"""
    if not line.strip():
        return "O", ""
    if line.startswith(";"):
        return "C", line[1:]
    if line.startswith(":"):
        return "L", line[1:]
    if line.startswith("#"):
        return "I", line
    return "T", line


def strip_marker(s: str):
    """剥离行尾页标记，返回 (正文, 标记)。"""
    k = len(s)
    while k > 0 and s[k - 1] in MARKERS:
        k -= 1
    return s[:k], s[k:]


# ---------------------------------------------------------------------------
# 聚合
# ---------------------------------------------------------------------------

def collect_entries(records, include_titles=False):
    """扫描行记录，返回条目列表。start/body_start/end 是行下标。"""
    entries = []
    i, n = 0, len(records)

    while i < n:
        kind, payload = records[i]

        # ---- 注释：默认不提取 ----
        if kind == "C":
            if include_titles:
                body, marker = strip_marker(payload)
                if TITLE_RE.match(body) or ENDING_RE.match(body):
                    entries.append({
                        "kind": "title", "start": i, "end": i + 1, "body_start": i,
                        "lead": None, "lead_marker": "",
                        "message": body, "indent": False, "marker": marker,
                        "marker_own_line": False,
                    })
            i += 1
            continue

        if kind != "T":
            i += 1
            continue

        # ---- 正文页 ----
        body, marker = strip_marker(payload)
        lead, lead_marker = None, ""
        body_start = i

        # 特例：`「●` 引号单独一行 + 停顿符，和后面同一页的正文合并成一条
        if marker == "\u25cf" and body.startswith("\u300c"):
            j = i + 1
            while j < n and records[j][0] != "T":
                j += 1
            if j < n:
                lead, lead_marker, body_start = body, marker, j

        indent = records[body_start][1].startswith("\u3000")
        j = body_start
        parts = []
        page_marker = ""
        marker_own_line = False
        while j < n and records[j][0] == "T":
            part, mk = strip_marker(records[j][1])
            # 新的一页：以缩进或开引号开头（原文里有不带页标记的静默分页）
            if j > body_start and part[:1] in PAGE_OPEN:
                break
            if not part and mk:
                # 页标记单独占一行
                page_marker = mk
                marker_own_line = True
                j += 1
                break
            if part.startswith("\u3000"):
                part = part[1:]
            parts.append(part)
            j += 1
            if mk:
                page_marker = mk
                break

        entries.append({
            "kind": "text", "start": i, "end": j, "body_start": body_start,
            "lead": lead, "lead_marker": lead_marker,
            "message": (lead or "") + "".join(parts), "indent": indent,
            "marker": page_marker, "marker_own_line": marker_own_line,
        })
        i = j

    return entries


def parse_scr(path: Path, encoding: str, **kw):
    lines, eol, final_newline, plain = decode_file(path, encoding)
    records = [classify(x) for x in lines]
    return lines, records, collect_entries(records, **kw), eol, final_newline, plain


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

def json_name(scr_name: str) -> str:
    return scr_name + ".json"


def write_json(path: Path, data, bom=True):
    text = json.dumps(data, ensure_ascii=False, indent=2)
    path.write_text(text, encoding="utf-8-sig" if bom else "utf-8", newline="\r\n")


def iter_scr(root: Path, recursive=False):
    for cur, dirs, files in os.walk(root):
        if not recursive:
            dirs[:] = []
        for fn in sorted(files):
            if fn.lower().endswith(SCR_SUFFIX):
                yield Path(cur) / fn


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="extract.py",
        description="从 .scr 直接提取 json（xor44 解密，一页一条 message）",
        epilog="示例:\n"
               "  python extract.py Scr -o json_jp\n"
               "  python extract.py Scr/S00_01.scr -o json_jp\n"
               "  python extract.py Scr -o json_jp --recursive",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help=".scr 文件或目录")
    parser.add_argument("-o", "--out", default="json_jp", help="输出目录（默认 json_jp）")
    parser.add_argument("--encoding", default="cp932", help="源脚本编码（默认 cp932）")
    parser.add_argument("--include-titles", action="store_true",
                        help="额外提取章节标题注释（默认不提取：标题画在背景图里）")
    parser.add_argument("--no-bom", action="store_true",
                        help="JSON 不写 UTF-8 BOM（默认带 BOM）")
    parser.add_argument("--recursive", action="store_true", help="递归处理子目录")
    args = parser.parse_args(argv)

    src = Path(args.input)
    if not src.exists():
        print("输入不存在: %s" % src, file=sys.stderr)
        return 2
    files = list(iter_scr(src, args.recursive)) if src.is_dir() else [src]
    if not files:
        print("没有找到 .scr 文件: %s" % src, file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"source": str(src.resolve()), "encoding": args.encoding,
                "files": [], "total": 0}
    for f in files:
        lines, records, entries, eol, final_newline, plain = parse_scr(
            f, args.encoding, include_titles=args.include_titles)
        dst = out_dir / json_name(f.name)
        write_json(dst, [{"message": e["message"]} for e in entries], bom=not args.no_bom)
        manifest["files"].append({"scr": f.name, "json": dst.name,
                                  "entries": len(entries),
                                  "cipher": "none" if plain else "xor44"})
        manifest["total"] += len(entries)
        print("[OK] %s -> %s  (%d 条)" % (f.name, dst.name, len(entries)))

    write_json(out_dir / "manifest.json", manifest, bom=not args.no_bom)
    print("完成：%d 个脚本，%d 条 -> %s/" % (len(files), manifest["total"], out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
