#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
asm_json_miboujin.py -- MIBOUJIN 脚本 asm.txt <-> 翻译 JSON

针对本引擎的 asm 语法（TEXT "..."、TITLE "..."、ENDING "..."、ANGLE ...），
不是 asm_json.py 里的 Text(0xNNNN) 语法。

提取规则：
  * TEXT 以 /c 或 /p 结尾为一段；同段内多行拼接成一条 message；
  * 每行行首的全角空格 U+3000 在提取时去掉，注入时只给段首补回；
  * /c、/p 不进入 message，注入时补到该段最后一行；
  * 默认只提取 TEXT；TITLE/ENDING/ANGLE/LABEL/SCENE 属于场景标题、界面固定
    用语或内部标识，默认不提取，可用 --types 按需开启；
  * SPEAKER 不提取（游戏里显示的是名字图片）；
  * SCENE、LABEL、CHAR、BG、SND 默认不提取（内部标识/资源名）。

注入规则：
  * message 为空或等于 pre_jp 时保留原行，保证空注入逐字节不变；
  * 否则按 25 个全角字符（=50 个半角宽度）重新分行，段首补回全角空格，
    最后一行补回 /c 或 /p；
  * TITLE/ENDING/ANGLE 只替换字符串，不重新分行。

用法：
    python asm_json_miboujin.py extract -s MIBOUJIN_asm -o json_jp
    python asm_json_miboujin.py inject  -s MIBOUJIN_asm -j json_cn -o MIBOUJIN_asm_cn
    python asm_json_miboujin.py inject  -s MIBOUJIN_asm -j json_cn --in-place
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata

import scb_format

TEXT_CMDS = {}
OPTIONAL_CMDS = {
    "TITLE": 0,
    "ENDING": 0,
    "ANGLE": 2,
    "LABEL": -1,
    "SCENE": 0,
}
MARKER_RE = re.compile(r"/([cp])$")
INSN_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s+)(.*)$")
ENC_RE = re.compile(r"^(;\s*encoding:\s*)([A-Za-z0-9_\-]+)\s*$")
PLACEHOLDER_RE = re.compile(r"\{\{[0-9A-Fa-f]{2}\}\}")


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def split_args(s):
    """按逗号切分参数，忽略引号/括号内部。返回 [(start,end), ...]。"""
    spans = []
    buf_start = 0
    quote = False
    depth = 0
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\\" and quote and i + 1 < n:
            i += 2
            continue
        if ch == '"':
            quote = not quote
        elif not quote and ch == "(":
            depth += 1
        elif not quote and ch == ")":
            depth -= 1
        elif ch == "," and not quote and depth == 0:
            j = i
            while j > buf_start and s[j - 1] in " \t":
                j -= 1
            spans.append((buf_start, j))
            buf_start = i + 1
            while buf_start < n and s[buf_start] in " \t":
                buf_start += 1
        i += 1
    j = n
    while j > buf_start and s[j - 1] in " \t":
        j -= 1
    if j > buf_start:
        spans.append((buf_start, j))
    return spans


def parse_quoted(tok):
    tok = tok.strip()
    if len(tok) < 2 or tok[0] != '"' or tok[-1] != '"':
        return None
    return unescape_body(tok[1:-1])


def unescape_body(body):
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


def escape_body(text):
    # {{XX}} 是字节占位符，必须原样保留；只转义真正的字面量
    parts = re.split(r"(\{\{[0-9A-Fa-f]{2}\}\})", text)
    out = []
    for part in parts:
        if PLACEHOLDER_RE.fullmatch(part):
            out.append(part)
        else:
            out.append(part.replace("\\", "\\\\").replace('"', '\\"').replace("{", "\\{"))
    return "".join(out)


def get_arg_text(line, index):
    """返回 (start,end,text)；start/end 是 line 内字符串 body 的区间。"""
    m = INSN_RE.match(line.rstrip("\r\n"))
    if not m:
        return None
    args_off = m.start(4)
    arg_text = m.group(4)
    spans = split_args(arg_text)
    if index == -1:
        index = len(spans) - 1
    if index < 0 or index >= len(spans):
        return None
    a0, a1 = spans[index]
    arg = arg_text[a0:a1]
    if len(arg) < 2 or arg[0] != '"' or arg[-1] != '"':
        return None
    # 找到 body 在整行中的位置
    quote_pos = args_off + a0
    start = quote_pos + 1
    end = start + len(arg) - 2
    return start, end, unescape_body(arg[1:-1])


def char_width(ch):
    if ch == "\u3000":
        return 2
    # W/F 全角；A（ambiguous，如 …、±、×）在日文环境按全角计
    if unicodedata.east_asian_width(ch) in ("W", "F", "A"):
        return 2
    return 1


def wrap_text(text, width=50):
    """按半角宽度换行（25 全角 = 50）。{{XX}} 占位符不占宽度且不会被切开。"""
    tokens = []
    pos = 0
    for m in PLACEHOLDER_RE.finditer(text):
        if m.start() > pos:
            tokens.extend((ch, char_width(ch)) for ch in text[pos:m.start()])
        tokens.append((m.group(0), 0))
        pos = m.end()
    if pos < len(text):
        tokens.extend((ch, char_width(ch)) for ch in text[pos:])

    lines = []
    cur = []
    cur_w = 0
    for tok, w in tokens:
        if cur and cur_w + w > width:
            lines.append("".join(cur))
            cur = []
            cur_w = 0
        cur.append(tok)
        cur_w += w
    if cur or not lines:
        lines.append("".join(cur))
    return lines


# ---------------------------------------------------------------------------
# 扫描
# ---------------------------------------------------------------------------
def scan_file(lines, enabled):
    """返回 items: TEXT 段落与非 TEXT 文本项，按出现顺序。"""
    items = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i].rstrip("\r\n")
        m = INSN_RE.match(line)
        if not m:
            i += 1
            continue
        op = m.group(2)
        if op == "TEXT" and enabled.get("TEXT", True):
            start_line = i
            segs = []
            marker = ""
            leading = False
            while i < n:
                cur = lines[i].rstrip("\r\n")
                cm = INSN_RE.match(cur)
                if not cm or cm.group(2) != "TEXT":
                    break
                got = get_arg_text(cur, 0)
                if got is None:
                    break
                text = got[2]
                if not segs:
                    leading = text.startswith("\u3000")
                text = text.lstrip("\u3000")
                mm = MARKER_RE.search(text)
                if mm:
                    marker = mm.group(1)
                    text = text[:mm.start()]
                    segs.append(text)
                    i += 1
                    break
                segs.append(text)
                i += 1
            items.append({
                "type": "TEXT",
                "text": "".join(segs),
                "start_line": start_line,
                "end_line": i - 1,
                "marker": marker,
                "leading": leading,
            })
            continue
        if op in enabled and op != "TEXT":
            idx = OPTIONAL_CMDS.get(op, TEXT_CMDS.get(op, 0))
            got = get_arg_text(line, idx)
            if got is not None and got[2].strip():
                items.append({
                    "type": op,
                    "text": got[2],
                    "start_line": i,
                    "end_line": i,
                    "arg_index": idx,
                    "leading": False,
                    "marker": "",
                })
        i += 1
    return items


def make_id(stem, seq):
    return "%s#%04d" % (stem, seq)


def stem_of(path):
    base = os.path.basename(path)
    return base[:-8] if base.lower().endswith(".asm.txt") else os.path.splitext(base)[0]


def collect_asm(src):
    if os.path.isdir(src):
        return [os.path.join(src, f) for f in sorted(os.listdir(src))
                if f.lower().endswith(".asm.txt")]
    return [src]


def parse_types(s):
    if not s:
        return dict(TEXT_CMDS, TEXT=True)
    out = {"TEXT": True}
    for name in s.split(","):
        name = name.strip().upper()
        if name == "TEXT":
            out["TEXT"] = True
        elif name in TEXT_CMDS:
            out[name] = TEXT_CMDS[name]
        elif name in OPTIONAL_CMDS:
            out[name] = OPTIONAL_CMDS[name]
        else:
            raise SystemExit("未知类型: %s（可选 TEXT,TITLE,ENDING,ANGLE,LABEL,SCENE）" % name)
    return out


# ---------------------------------------------------------------------------
# SCB 单文件 asm（.table/.block）支持
# ---------------------------------------------------------------------------
SCB_TABLE_RE = re.compile(
    r'^(\s*)(\d+)(\s+)("(?:\\.|[^"\\])*")(?:\s*;\s*rec=\d+)?\s*$')
SCB_BLOCK_RE = re.compile(r"^\s*\.block\s+(\d+)\s*(?:;\s*size=\d+)?\s*$")
LABEL_RE = re.compile(
    r'^(\s*LABEL\s+0x[0-9A-Fa-f]+,\s*0x[0-9A-Fa-f]+,\s*)'
    r'("(?:\\.|[^"\\])*")(\s*)$')


def is_scb_asm_text(text: str) -> bool:
    return any(ln.strip() == ".table" for ln in text.splitlines())


def parse_scb_layout(lines):
    """返回 tables{idx:(line_no,name)} 与 blocks{idx:[body_start,body_end)}。"""
    tables = {}
    blocks = {}
    section = None
    cur = None
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s == ".header":
            if cur is not None:
                blocks[cur][1] = i
                cur = None
            section = "header"
            continue
        if s == ".table":
            if cur is not None:
                blocks[cur][1] = i
                cur = None
            section = "table"
            continue
        m = SCB_BLOCK_RE.match(s)
        if m:
            if cur is not None:
                blocks[cur][1] = i
            cur = int(m.group(1))
            blocks[cur] = [i + 1, len(lines)]
            section = "block"
            continue
        if section == "table":
            m = SCB_TABLE_RE.match(s)
            if m:
                tables[int(m.group(2))] = (i, unescape_body(m.group(4)[1:-1]))
    if cur is not None:
        blocks[cur][1] = len(lines)
    return tables, blocks


def render_text_lines(it, new, width):
    body = new.lstrip("\u3000")
    if it["leading"]:
        body = "\u3000" + body
    wrapped = wrap_text(body, width * 2)
    out = []
    for k, seg in enumerate(wrapped):
        suffix = it["marker"] if k == len(wrapped) - 1 else ""
        out.append('TEXT "%s%s"\n' % (escape_body(seg), ("/" + suffix) if suffix else ""))
    return out


def extract_scb(path, args, enabled):
    lines = open(path, encoding="utf-8").read().splitlines()
    tables, blocks = parse_scb_layout(lines)
    chapters = set() if args.no_chapters else parse_chapter_range(args.chapters)
    os.makedirs(args.out, exist_ok=True)
    total = 0
    per_type = {}
    all_entries = []

    for idx in sorted(blocks):
        start, end = blocks[idx]
        name = tables.get(idx, (0, ""))[1]
        stem = scb_format.safe_name(name, idx)
        items = scan_file(lines[start:end], enabled)
        entries = []
        for seq, it in enumerate(items, 1):
            if it["type"] != "TEXT" and not it["text"].strip():
                continue
            per_type[it["type"]] = per_type.get(it["type"], 0) + 1
            entries.append({
                "id": make_id(stem, seq),
                "pre_jp": it["text"],
                "message": it["text"],
            })
        if idx in chapters and name:
            entries.append({
                "id": "%s#CHAPTER%04d" % (stem, idx),
                "pre_jp": name,
                "message": name,
            })
            per_type["CHAPTER"] = per_type.get("CHAPTER", 0) + 1
        all_entries.extend(entries)
        total += len(entries)
        if not args.merged and entries:
            out_path = os.path.join(args.out, stem + ".json")
            with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(entries, f, ensure_ascii=False, indent=2)
                f.write("\n")
            print("%s#%d -> %s (%d)" % (os.path.basename(path), idx,
                                        os.path.basename(out_path), len(entries)))
    if args.merged:
        out_path = os.path.join(args.out, "messages.json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(all_entries, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("merged -> %s (%d)" % (out_path, len(all_entries)))
    print("done: %d texts" % total)
    for k in sorted(per_type):
        print("  %-8s %d" % (k, per_type[k]))
    return 0


def inject_scb(path, args, enabled):
    raw = open(path, encoding="utf-8", newline="").read()
    lines = raw.splitlines(keepends=True)
    tables, blocks = parse_scb_layout(lines)

    chapter_re = re.compile(r"#CHAPTER(\d+)$")
    chapter_updates = {}
    chapter_renames = {}
    block_json = {}

    for idx, (start, end) in blocks.items():
        name = tables.get(idx, (0, ""))[1]
        stem = scb_format.safe_name(name, idx)
        jp = find_json(args.json, stem)
        if not jp:
            continue
        data = json.load(open(jp, encoding="utf-8-sig"))
        if not isinstance(data, list):
            raise SystemExit("%s 不是 JSON 数组" % jp)
        by_id = {}
        for e in data:
            if not isinstance(e, dict) or "id" not in e:
                continue
            by_id[e["id"]] = e
            m = chapter_re.search(e["id"])
            if m:
                new = e.get("message") or e.get("pre_jp")
                old = e.get("pre_jp")
                if isinstance(new, str) and new:
                    chapter_updates[int(m.group(1))] = new
                    if isinstance(old, str) and old:
                        chapter_renames[old] = new
        block_json[idx] = (stem, by_id)

    # 先改 .table（只换字符串，行数不变）
    changed_tables = 0
    for idx, new in chapter_updates.items():
        if idx not in tables:
            continue
        li = tables[idx][0]
        line = lines[li]
        m = SCB_TABLE_RE.match(line.rstrip("\r\n"))
        if not m:
            continue
        s = m.start(4) + 1
        e = m.end(4) - 1
        lines[li] = line[:s] + escape_body(new) + line[e:]
        changed_tables += 1

    # 章节名同时是 block 43 里的 LABEL 键，必须跟 .table 同步改
    changed_labels = 0
    if chapter_renames:
        for i, line in enumerate(lines):
            m = LABEL_RE.match(line.rstrip("\r\n"))
            if not m:
                continue
            old = unescape_body(m.group(2)[1:-1])
            if old not in chapter_renames:
                continue
            lines[i] = m.group(1) + '"' + escape_body(chapter_renames[old]) + '"' + m.group(3) + line[len(line.rstrip("\r\n")):]
            changed_labels += 1

    # 再改 .block（从后往前，避免行号变化）
    changed_texts = 0
    for idx in sorted(blocks, key=lambda i: blocks[i][0], reverse=True):
        if idx not in block_json:
            continue
        stem, by_id = block_json[idx]
        start, end = blocks[idx]
        body = lines[start:end]
        items = scan_file(body, enabled)
        replacements = []
        for seq, it in enumerate(items, 1):
            ent = by_id.get(make_id(stem, seq))
            if ent is None:
                continue
            new = ent.get("message")
            if not new:
                new = ent.get("pre_jp") or it["text"]
            if not isinstance(new, str) or new == it["text"]:
                continue
            if it["type"] == "TEXT":
                replacements.append((it["start_line"], it["end_line"],
                                     render_text_lines(it, new, args.width)))
                changed_texts += 1
            else:
                line = body[it["start_line"]]
                got = get_arg_text(line, it["arg_index"])
                if got is None:
                    continue
                s, e, _ = got
                body[it["start_line"]] = line[:s] + escape_body(new) + line[e:]
                changed_texts += 1
        for s, e, new_lines in sorted(replacements, reverse=True):
            body[s:e + 1] = new_lines
        lines[start:end] = body

    if args.encoding:
        for i, line in enumerate(lines):
            b = line.rstrip("\r\n")
            m = ENC_RE.match(b)
            if m:
                lines[i] = m.group(1) + args.encoding + line[len(b):]
                break

    text = "".join(lines)
    if args.in_place:
        bak = path + ".bak"
        if not os.path.exists(bak):
            open(bak, "w", encoding="utf-8", newline="").write(raw)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        out = path
    elif args.out:
        if os.path.isdir(args.out):
            out = os.path.join(args.out, os.path.basename(path))
        else:
            out = args.out
        with open(out, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    else:
        base = os.path.basename(path)
        stem = base[:-8] if base.lower().endswith(".asm.txt") else os.path.splitext(base)[0]
        out = os.path.join(os.path.dirname(path), stem + "_cn.asm.txt")
        with open(out, "w", encoding="utf-8", newline="") as f:
            f.write(text)

    print("注入 SCB asm: %s" % out)
    print("  .table 改 %d 条，LABEL 章节名改 %d 条，.block 文本改 %d 条"
          % (changed_tables, changed_labels, changed_texts))
    return 0


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------
def guess_scb(src):
    p = os.path.abspath(src)
    if not os.path.isdir(p):
        return None
    parent = os.path.dirname(p)
    base = os.path.basename(p)
    if base.endswith("_asm"):
        base = base[:-4]
    for cand in (base + ".SCB", base + ".scb"):
        q = os.path.join(parent, cand)
        if os.path.isfile(q):
            return q
    return None


def parse_chapter_range(s):
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


def chapter_entries(scb_path, scb_encoding, indices):
    scb = scb_format.ScbFile(open(scb_path, "rb").read(), scb_encoding)
    out = {}
    for idx in sorted(indices):
        if not 0 <= idx < scb.count:
            continue
        name = scb_format.decode_text(scb.entries[idx]["payload"], scb_encoding)
        stem = scb_format.safe_name(name, idx)
        out[stem] = (idx, name)
    return out


def cmd_extract(args):
    enabled = parse_types(args.types)
    files = collect_asm(args.src)
    if len(files) == 1 and os.path.isfile(files[0]):
        if is_scb_asm_text(open(files[0], encoding="utf-8").read()):
            return extract_scb(files[0], args, enabled)
    os.makedirs(args.out, exist_ok=True)
    total = 0
    per_type = {}
    all_entries = []

    scb_path = args.scb or guess_scb(args.src)
    chapters = {}
    if scb_path and not args.no_chapters:
        chapters = chapter_entries(scb_path, args.scb_encoding,
                                   parse_chapter_range(args.chapters))
        if chapters:
            print("章节名: %s（%d 条）" % (scb_path, len(chapters)))

    for path in collect_asm(args.src):
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        stem = stem_of(path)
        items = scan_file(lines, enabled)
        entries = []
        for seq, it in enumerate(items, 1):
            if it["type"] != "TEXT" and not it["text"].strip():
                continue
            per_type[it["type"]] = per_type.get(it["type"], 0) + 1
            entries.append({
                "id": make_id(stem, seq),
                "pre_jp": it["text"],
                "message": it["text"],
            })
        if stem in chapters:
            idx, name = chapters[stem]
            entries.append({
                "id": "%s#CHAPTER%04d" % (stem, idx),
                "pre_jp": name,
                "message": name,
            })
            per_type["CHAPTER"] = per_type.get("CHAPTER", 0) + 1
        all_entries.extend(entries)
        total += len(entries)
        if not args.merged:
            if not entries and not args.keep_empty:
                continue
            out_path = os.path.join(args.out, stem + ".json")
            with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(entries, f, ensure_ascii=False, indent=2)
                f.write("\n")
            print("%s -> %s (%d)" % (os.path.basename(path), os.path.basename(out_path), len(entries)))
    if args.merged:
        out_path = os.path.join(args.out, "messages.json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(all_entries, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("merged -> %s (%d)" % (out_path, len(all_entries)))
    print("done: %d texts" % total)
    for k in sorted(per_type):
        print("  %-8s %d" % (k, per_type[k]))
    return 0


# ---------------------------------------------------------------------------
# inject
# ---------------------------------------------------------------------------
def find_json(json_dir, stem):
    p = os.path.join(json_dir, stem + ".json")
    return p if os.path.exists(p) else None


def cmd_inject(args):
    enabled = parse_types(args.types)
    if os.path.isfile(args.src):
        if is_scb_asm_text(open(args.src, encoding="utf-8").read()):
            return inject_scb(args.src, args, enabled)
    files = collect_asm(args.src)
    if not args.in_place:
        os.makedirs(args.out, exist_ok=True)
    changed_files = 0
    total = 0
    missing = 0

    merged_path = os.path.join(args.json, "messages.json")
    merged_by_id = None
    if os.path.exists(merged_path):
        data = json.load(open(merged_path, encoding="utf-8-sig"))
        if not isinstance(data, list):
            raise SystemExit("%s 不是 JSON 数组" % merged_path)
        merged_by_id = {e["id"]: e for e in data if isinstance(e, dict) and "id" in e}

    for path in files:
        raw = open(path, encoding="utf-8", newline="").read()
        lines = raw.splitlines(keepends=True)
        stem = stem_of(path)
        items = scan_file(lines, enabled)
        if merged_by_id is not None:
            prefix = stem + "#"
            by_id = {k: v for k, v in merged_by_id.items() if k.startswith(prefix)}
            jp = merged_path
        else:
            jp = find_json(args.json, stem)
            if not jp:
                if items:
                    missing += 1
                if not args.in_place:
                    open(os.path.join(args.out, os.path.basename(path)), "w",
                         encoding="utf-8", newline="").write(raw)
                continue
            data = json.load(open(jp, encoding="utf-8-sig"))
            if not isinstance(data, list):
                raise SystemExit("%s 不是 JSON 数组" % jp)
            by_id = {e["id"]: e for e in data if isinstance(e, dict) and "id" in e}

        replacements = []  # (start_line, end_line, new_lines)
        changed = False
        for seq, it in enumerate(items, 1):
            ent = by_id.get(make_id(stem, seq))
            if ent is None:
                continue
            new = ent.get("message")
            if not new:
                new = ent.get("pre_jp") or it["text"]
            if not isinstance(new, str):
                raise SystemExit("%s: %s 的 message 不是字符串" % (jp, ent.get("id")))
            if new == it["text"]:
                continue
            total += 1
            if it["type"] == "TEXT":
                body = new.lstrip("\u3000")
                if it["leading"]:
                    body = "\u3000" + body
                wrapped = wrap_text(body, args.width * 2)
                new_lines = []
                for k, seg in enumerate(wrapped):
                    suffix = it["marker"] if k == len(wrapped) - 1 else ""
                    new_lines.append('TEXT "%s%s"\n' % (escape_body(seg), ("/" + suffix) if suffix else ""))
                replacements.append((it["start_line"], it["end_line"], new_lines))
                changed = True
            else:
                line = lines[it["start_line"]]
                got = get_arg_text(line, it["arg_index"])
                if got is None:
                    continue
                s, e, _ = got
                lines[it["start_line"]] = line[:s] + escape_body(new) + line[e:]
                changed = True

        for start, end, new_lines in sorted(replacements, reverse=True):
            lines[start:end + 1] = new_lines

        if changed:
            changed_files += 1
        text = "".join(lines)
        if args.encoding:
            for i, line in enumerate(lines):
                b = line.rstrip("\r\n")
                m = ENC_RE.match(b)
                if m:
                    lines[i] = m.group(1) + args.encoding + line[len(b):]
                    break
            text = "".join(lines)

        if args.in_place:
            bak = path + ".bak"
            if not os.path.exists(bak):
                open(bak, "w", encoding="utf-8", newline="").write(raw)
            target = path
        else:
            target = os.path.join(args.out, os.path.basename(path))
        open(target, "w", encoding="utf-8", newline="").write(text)

    # 章节名：从 JSON 的 #CHAPTER 条目收集，写成 scb_tool 可用的标题表
    chapter_re = re.compile(r"#CHAPTER(\d+)$")
    chapter_updates = {}
    if merged_by_id is not None:
        sources = [merged_by_id]
    else:
        sources = []
        for name in os.listdir(args.json):
            if not name.endswith(".json"):
                continue
            try:
                d = json.load(open(os.path.join(args.json, name), encoding="utf-8-sig"))
            except Exception:
                continue
            if isinstance(d, list):
                sources.append({e["id"]: e for e in d if isinstance(e, dict) and "id" in e})
    for src in sources:
        for eid, ent in src.items():
            m = chapter_re.search(eid)
            if not m:
                continue
            new = ent.get("message") or ent.get("pre_jp")
            if isinstance(new, str) and new:
                chapter_updates[int(m.group(1))] = new

    if chapter_updates:
        if args.titles_out:
            titles_path = args.titles_out
        elif args.in_place:
            titles_path = os.path.join(os.path.dirname(files[0]), "titles.txt")
        else:
            titles_path = os.path.join(args.out, "titles.txt")
        enc = args.chapter_encoding or "gbk"
        with open(titles_path, "w", encoding=enc, errors="replace", newline="\n") as f:
            f.write("# encoding: %s\n" % enc)
            for idx in sorted(chapter_updates):
                f.write("%d\t%s\n" % (idx, chapter_updates[idx]))
        print("章节标题表: %s（%d 条，%s）" % (titles_path, len(chapter_updates), enc))

    if missing:
        print("警告: %d 个 asm 没有对应 JSON，已原样输出" % missing)
    print("done: %d files, %d texts changed" % (len(files), total))
    return 0


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="MIBOUJIN asm.txt <-> 翻译 JSON")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="asm.txt -> JSON")
    p.add_argument("-s", "--src", required=True, help="asm.txt 文件或目录")
    p.add_argument("-o", "--out", default="json_jp")
    p.add_argument("--types", default=None,
                   help="逗号分隔：TEXT,TITLE,ENDING,ANGLE,LABEL,SCENE（默认仅 TEXT）")
    p.add_argument("--merged", action="store_true", help="输出单个 messages.json")
    p.add_argument("--keep-empty", action="store_true", help="没有文本的 asm 也生成空 JSON")
    p.add_argument("--scb", help="SCB 路径（默认自动找 <目录名去_asm>.SCB）")
    p.add_argument("--scb-encoding", default="cp932", help="SCB 表项编码")
    p.add_argument("--chapters", default="58-99", help="要提取的章节表项序号，默认 58-99")
    p.add_argument("--no-chapters", action="store_true", help="不提取章节名")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="JSON -> asm.txt")
    p.add_argument("-s", "--src", required=True, help="原 asm.txt 文件或目录")
    p.add_argument("-j", "--json", required=True, help="译文 JSON 目录")
    p.add_argument("-o", "--out", default="asm_cn")
    p.add_argument("--in-place", action="store_true", help="覆盖源文件（先备份 .bak）")
    p.add_argument("--encoding", default=None, help="更新 asm 头部编码，如 gbk")
    p.add_argument("--width", type=int, default=25, help="每行全角字符数（默认 25）")
    p.add_argument("--types", default=None)
    p.add_argument("--titles-out", help="章节标题表输出路径（默认 <out>/titles.txt）")
    p.add_argument("--chapter-encoding", default="gbk", help="章节标题表编码，默认 gbk")
    p.set_defaults(func=cmd_inject)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
