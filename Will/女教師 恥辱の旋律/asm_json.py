#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""asm_json.py -- 本作 .scr 的语义汇编 (asm.txt) <-> 翻译 JSON

提取的文本类型
==============
* TEXT  0x41：旁白文本（第三个参数）
* SAY   0x42：人名 + 台词（第四个参数是人名，第五个是台词）
* OPT   0x02：选择肢文本（SELECT 块内 OPT 的第三个参数）
另外 SAY 的人名也会作为 name 字段一并提取、可翻译。

提取规则
========
* 文本中的换行转义 \\n 会被删掉，合成一行（pre_jp / message 都是单行）；
* {{XX}} 字节占位符原样保留；
* id = <文件名不含 .asm.txt>#<序号>，按 asm 中出现顺序编号。

注入规则
========
* message 为空或等于 pre_jp 时保留原行 -> 空注入时 asm 逐字节不变；
* 否则按每 23 个全角字符（=46 个半角宽度）补一个 \\n；
* {{XX}} 占位符不占宽度、不会被切开；
* 只替换对应参数，行内其它内容（opcode、数值参数、SELECT 结构）不动。

用法
====
    python asm_json.py extract -s asm -o json_jp
    python asm_json.py inject  -s asm -j json_cn -o asm_cn
    python asm_json.py inject  -s asm -j json_cn --in-place
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata

INSN_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s+)(.*)$")
PLACEHOLDER_RE = re.compile(r"\{\{[0-9A-Fa-f]{2}\}\}")

# 文本参数在参数列表中的下标
TEXT_ARG = {"TEXT": 2, "SAY": 4, "OPT": 2}
NAME_ARG = {"SAY": 3}


# ---------------------------------------------------------------------------
# 行解析
# ---------------------------------------------------------------------------
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


def split_args(s):
    """按逗号切分，忽略引号内部。返回 [(start, end), ...]。"""
    spans = []
    start = 0
    q = False
    i = 0
    while i < len(s):
        ch = s[i]
        if q:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                q = False
        else:
            if ch == '"':
                q = True
            elif ch == ",":
                j = i
                while j > start and s[j - 1] in " \t":
                    j -= 1
                spans.append((start, j))
                start = i + 1
                while start < len(s) and s[start] in " \t":
                    start += 1
        i += 1
    j = len(s)
    while j > start and s[j - 1] in " \t":
        j -= 1
    if j > start:
        spans.append((start, j))
    return spans


def unescape(body):
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "\\":
                out.append("\\")
            elif nxt == '"':
                out.append('"')
            else:
                out.append(ch)
                out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def escape(text):
    parts = re.split(r"(\{\{[0-9A-Fa-f]{2}\}\})", text)
    out = []
    for part in parts:
        if PLACEHOLDER_RE.fullmatch(part):
            out.append(part)
        else:
            out.append(part.replace("\\", "\\\\").replace('"', '\\"'))
    return "".join(out)


def arg_body(line, index):
    """返回 (start, end, text)；start/end 是字符串 body 在 line 中的区间。"""
    m = INSN_RE.match(line)
    if not m:
        return None
    off = m.start(4)
    spans = split_args(m.group(4))
    if index == -1:
        index = len(spans) - 1
    if index < 0 or index >= len(spans):
        return None
    a, b = spans[index]
    raw = m.group(4)[a:b]
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return None
    start = off + a + 1
    return start, start + len(raw) - 2, unescape(raw[1:-1])


# ---------------------------------------------------------------------------
# 扫描
# ---------------------------------------------------------------------------
def scan_lines(lines, enabled):
    """返回 [{'line','op','arg','start','end','text','name'}]，按出现顺序。"""
    items = []
    for i, raw in enumerate(lines):
        line = strip_comment(raw.rstrip("\r\n")).rstrip()
        m = INSN_RE.match(line)
        if not m:
            continue
        op = m.group(2)
        if op not in enabled or op not in TEXT_ARG:
            continue
        got = arg_body(line, TEXT_ARG[op])
        if got is None:
            continue
        item = {"line": i, "op": op, "arg": TEXT_ARG[op],
                "start": got[0], "end": got[1], "text": got[2],
                "name": None, "name_span": None}
        if op in NAME_ARG:
            ng = arg_body(line, NAME_ARG[op])
            if ng is not None:
                item["name"] = ng[2]
                item["name_span"] = (ng[0], ng[1])
        items.append(item)
    return items


# ---------------------------------------------------------------------------
# 换行
# ---------------------------------------------------------------------------
def char_width(ch):
    if ch == "\u3000":
        return 2
    if unicodedata.east_asian_width(ch) in ("W", "F", "A"):
        return 2
    return 1


def wrap_text(text, full_width=23):
    """每 full_width 个全角字符断一行；占位符不占宽度。"""
    limit = full_width * 2
    text = text.replace("\n", "").replace("\r", "")
    tokens = []
    pos = 0
    for m in PLACEHOLDER_RE.finditer(text):
        for ch in text[pos:m.start()]:
            tokens.append((ch, char_width(ch)))
        tokens.append((m.group(0), 0))
        pos = m.end()
    for ch in text[pos:]:
        tokens.append((ch, char_width(ch)))

    lines = []
    cur = []
    w = 0
    for tok, tw in tokens:
        if cur and w + tw > limit:
            lines.append("".join(cur))
            cur = []
            w = 0
        cur.append(tok)
        w += tw
    if cur or not lines:
        lines.append("".join(cur))
    return lines


def render_body(text, full_width=23):
    segs = wrap_text(text, full_width)
    return "\\n".join(escape(s) for s in segs)


# ---------------------------------------------------------------------------
# 文件
# ---------------------------------------------------------------------------
def stem_of(path):
    base = os.path.basename(path)
    if base.lower().endswith(".asm.txt"):
        return base[:-8]
    return os.path.splitext(base)[0]


def collect(src, suffix):
    if os.path.isdir(src):
        return [os.path.join(src, f) for f in sorted(os.listdir(src))
                if f.lower().endswith(suffix)]
    return [src]


def parse_types(s):
    if not s:
        return {"TEXT": True, "SAY": True, "OPT": True}
    out = {}
    for name in s.split(","):
        name = name.strip().upper()
        if name not in TEXT_ARG:
            raise SystemExit("未知类型: %s（可选 TEXT,SAY,OPT）" % name)
        out[name] = True
    return out


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------
def cmd_extract(args):
    files = collect(args.src, ".asm.txt")
    if not files:
        raise SystemExit("没有 .asm.txt: %s" % args.src)
    enabled = parse_types(args.types)
    os.makedirs(args.out, exist_ok=True)

    merged = []
    total = 0
    per_type = {}
    for path in files:
        stem = stem_of(path)
        lines = open(path, encoding="utf-8-sig").read().splitlines()
        items = scan_lines(lines, enabled)
        entries = []
        for seq, it in enumerate(items, 1):
            text = it["text"].replace("\n", "").replace("\r", "")
            ent = {
                "id": "%s#%04d" % (stem, seq),
                "type": it["op"],
            }
            if it["op"] == "SAY" and it["name"] is not None:
                ent["name"] = it["name"]
            ent["pre_jp"] = text
            ent["message"] = text
            entries.append(ent)
            per_type[it["op"]] = per_type.get(it["op"], 0) + 1
        total += len(entries)
        merged.extend(entries)
        if not args.merged:
            out_path = os.path.join(args.out, stem + ".json")
            with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(entries, f, ensure_ascii=False, indent=2)
                f.write("\n")
    if args.merged:
        out_path = os.path.join(args.out, "messages.json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(merged, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("merged -> %s" % out_path)

    print("提取完成: %d 个文件, %d 条文本 -> %s" % (len(files), total, args.out))
    for k in sorted(per_type):
        print("  %-4s %d" % (k, per_type[k]))
    return 0


# ---------------------------------------------------------------------------
# inject
# ---------------------------------------------------------------------------
def load_json_dir(path):
    """返回 {stem: {id: entry}}。"""
    data = {}
    if os.path.isfile(path):
        items = json.load(open(path, encoding="utf-8-sig"))
        for e in items:
            eid = e.get("id", "")
            stem = eid.split("#")[0]
            data.setdefault(stem, {})[eid] = e
        return data
    for fn in sorted(os.listdir(path)):
        if not fn.lower().endswith(".json"):
            continue
        fp = os.path.join(path, fn)
        try:
            items = json.load(open(fp, encoding="utf-8-sig"))
        except Exception as e:
            raise SystemExit("%s 读取失败: %s" % (fp, e))
        if not isinstance(items, list):
            raise SystemExit("%s 不是 JSON 数组" % fp)
        stem = fn[:-5]
        by_id = {}
        for e in items:
            if isinstance(e, dict) and "id" in e:
                by_id[e["id"]] = e
        data[stem] = by_id
    return data


def cmd_inject(args):
    files = collect(args.src, ".asm.txt")
    if not files:
        raise SystemExit("没有 .asm.txt: %s" % args.src)
    enabled = parse_types(args.types)
    jsons = load_json_dir(args.json)
    os.makedirs(args.out, exist_ok=True)

    changed_total = 0
    files_changed = 0
    for path in files:
        stem = stem_of(path)
        by_id = jsons.get(stem)
        raw = open(path, encoding="utf-8-sig", newline="").read()
        lines = raw.splitlines(keepends=True)
        if not by_id:
            target = path if args.in_place else os.path.join(args.out, os.path.basename(path))
            if not args.in_place:
                open(target, "w", encoding="utf-8", newline="").write(raw)
            if by_id is None:
                print("  [skip] %s: 没有对应 JSON" % os.path.basename(path))
            continue

        items = scan_lines([ln.rstrip("\r\n") for ln in lines], enabled)
        changed = 0
        for seq, it in enumerate(items, 1):
            ent = by_id.get("%s#%04d" % (stem, seq))
            if ent is None:
                continue
            new = ent.get("message")
            if not new:
                new = ent.get("pre_jp")
            if not isinstance(new, str):
                raise SystemExit("%s 的 message 不是字符串" % ent.get("id"))
            old = it["text"].replace("\n", "").replace("\r", "")
            if new.replace("\n", "") != old:
                line = lines[it["line"]]
                body = render_body(new, args.width)
                lines[it["line"]] = line[:it["start"]] + body + line[it["end"]:]
                changed += 1
            if it["op"] == "SAY" and it["name_span"] and isinstance(ent.get("name"), str):
                ns, ne = it["name_span"]
                if ent["name"] != it["name"]:
                    line = lines[it["line"]]
                    lines[it["line"]] = (line[:ns] + escape(ent["name"]) + line[ne:])
                    changed += 1

        total_changed = changed
        if total_changed:
            files_changed += 1
            changed_total += total_changed
        if args.encoding:
            for k, ln in enumerate(lines):
                s = ln.rstrip("\r\n")
                if s.startswith(".encoding"):
                    lines[k] = ".encoding %s%s" % (args.encoding, ln[len(s):])
                    break
        text = "".join(lines)
        target = path if args.in_place else os.path.join(args.out, os.path.basename(path))
        open(target, "w", encoding="utf-8", newline="").write(text)
        if total_changed:
            print("  %s: %d 处" % (os.path.basename(path), total_changed))

    print("注入完成: %d 个文件, %d 处文本被替换 -> %s"
          % (files_changed, changed_total, args.src if args.in_place else args.out))
    return 0


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="asm.txt <-> 翻译 JSON（TEXT/SAY/OPT）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="asm.txt -> JSON")
    p.add_argument("-s", "--src", required=True, help="asm.txt 文件或目录")
    p.add_argument("-o", "--out", default="json_jp")
    p.add_argument("--types", default=None, help="TEXT,SAY,OPT（默认全部）")
    p.add_argument("--merged", action="store_true", help="输出单个 messages.json")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="JSON -> asm.txt")
    p.add_argument("-s", "--src", required=True, help="原 asm.txt 文件或目录")
    p.add_argument("-j", "--json", required=True, help="译文 JSON 目录或文件")
    p.add_argument("-o", "--out", default="asm_cn")
    p.add_argument("--in-place", action="store_true", help="覆盖源文件")
    p.add_argument("--width", type=int, default=23, help="每行全角字符数（默认 23）")
    p.add_argument("--encoding", default=None,
                   help="同时把 .encoding 改成指定编码（如 gbk，配合中文译文）")
    p.add_argument("--types", default=None)
    p.set_defaults(func=cmd_inject)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
