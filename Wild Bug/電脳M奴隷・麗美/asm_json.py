#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
asm_json.py -- 在语义汇编 (asm.txt) 与翻译 JSON 之间双向转换。

一个脚本同时完成“提取”和“注入”，参照 魔法少女アイ 的 extract.py / inject.py，
但适配本引擎的 asm 语法（文本内联在 Text(0xNNNN) "..." 操作数里）。

提取的指令类型（可用 --types 覆盖）：

    MESSAGE       0x80  正文/旁白        文本在参数 0
    MENU_ENTRY    0x48  章节/菜单条目    文本在参数 0
    TEXT_SELECT   0x50  目录/选择项      文本在参数 0
    MESSAGE_WAVE  0x87  带语音的对话     文本在参数 1（参数 0 是语音文件名）

JSON 为数组，每条：

    {"id": "CPT_0101#0001", "pre_jp": "原文", "message": "译文"}

`pre_jp` 提取后不再改变；`message` 是翻译字段（提取时等于原文，注入为空则回退 pre_jp）。
同一个文本 id 被多处引用时只产生一条，注入时会同步更新所有引用。

用法：

    python asm_json.py extract -s scn_asm -o json_jp
    python asm_json.py inject  -s scn_asm -j json_cn -o scn_cn
    python asm_json.py inject  -s scn_asm -j json_cn --in-place --encoding gbk
    python asm_json.py extract -s scn_asm/CPT_0101.asm.txt -o json_jp

    -s/--src       asm.txt 文件或目录
    -o/--out       JSON 目录（extract）或 asm 输出目录（inject）
    -j/--json      inject 时的译文 JSON 目录
    --types        逗号分隔的指令类型，默认 MESSAGE,MESSAGE_WAVE,MENU_ENTRY,TEXT_SELECT
    --encoding     inject 时更新 asm 头部的 `; encoding:`（如 gbk）
    --in-place     直接覆盖源 asm（先备份 .bak）
"""
import argparse
import json
import os
import re
import sys

# 指令 -> 文本所在的参数下标
TEXT_OPS = {
    "MESSAGE": 0,
    "MENU_ENTRY": 0,
    "TEXT_SELECT": 0,
    "MESSAGE_WAVE": 1,
}

INSN_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s+)(.*)$")
TEXT_ARG_RE = re.compile(r'^Text\(0x([0-9A-Fa-f]+)\)(\s*)"((?:\\.|[^"\\])*)"$')
ENC_LINE_RE = re.compile(r"^(;\s*encoding:\s*)([A-Za-z0-9_\-]+)\s*$")


# ---------------------------------------------------------------------------
# 参数切分（逗号分隔，忽略引号和括号内部）
# ---------------------------------------------------------------------------
def split_args_spans(s):
    spans = []
    buf = []
    quote = False
    depth = 0
    start = 0
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
            while j > start and s[j - 1] in " \t":
                j -= 1
            spans.append((start, j))
            start = i + 1
            while start < n and s[start] in " \t":
                start += 1
        i += 1
    j = n
    while j > start and s[j - 1] in " \t":
        j -= 1
    if j > start:
        spans.append((start, j))
    return spans


def unescape_body(body):
    out = []
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch == "\\" and i + 1 < n and body[i + 1] in '\\"':
            out.append(body[i + 1])
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def escape_body(text):
    return text.replace("\\", "\\\\").replace('"', '\\"')


def is_encodable(text, enc):
    """{{XX}} 占位符代表原始字节，跳过它们再判断。"""
    plain = re.sub(r"\{\{[0-9A-Fa-f]{2}\}\}", "", text)
    try:
        plain.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def replace_bad_chars(text, enc):
    plain_parts = re.split(r"(\{\{[0-9A-Fa-f]{2}\}\})", text)
    out = []
    bad = []
    for part in plain_parts:
        if re.fullmatch(r"\{\{[0-9A-Fa-f]{2}\}\}", part):
            out.append(part)
            continue
        for ch in part:
            try:
                ch.encode(enc)
                out.append(ch)
            except UnicodeEncodeError:
                out.append("?")
                bad.append(ch)
    return "".join(out), "".join(bad)


# ---------------------------------------------------------------------------
# 扫描 asm
# ---------------------------------------------------------------------------
def scan_texts(lines, stem, types):
    """返回 [{id, line, arg_index, text_id, start, end, text}]（end/start 为行内 body 区间）。"""
    out = []
    seq = 0
    for li, line in enumerate(lines):
        body = line.rstrip("\r\n")
        m = INSN_RE.match(body)
        if not m or m.group(2) not in types:
            continue
        op = m.group(2)
        args_off = m.start(4)
        arg_text = m.group(4)
        spans = split_args_spans(arg_text)
        idx = types[op]
        if idx >= len(spans):
            continue
        a0, a1 = spans[idx]
        arg = arg_text[a0:a1]
        am = TEXT_ARG_RE.match(arg)
        if not am:
            continue
        seq += 1
        out.append({
            "id": "%s#%04d" % (stem, seq),
            "line": li,
            "op": op,
            "arg_index": idx,
            "text_id": am.group(1).upper(),
            "start": args_off + a0 + am.start(3),
            "end": args_off + a0 + am.end(3),
            "text": unescape_body(am.group(3)),
        })
    return out


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------
def collect_asm_files(src):
    if os.path.isdir(src):
        return [os.path.join(src, f) for f in sorted(os.listdir(src))
                if f.lower().endswith(".asm.txt")]
    return [src]


def stem_of(path):
    base = os.path.basename(path)
    return base[:-len(".asm.txt")] if base.lower().endswith(".asm.txt") else os.path.splitext(base)[0]


def cmd_extract(args):
    types = parse_types(args.types)
    os.makedirs(args.out, exist_ok=True)
    files = collect_asm_files(args.src)
    total = 0
    per_op = {}
    for path in files:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        stem = stem_of(path)
        texts = scan_texts(lines, stem, types)
        entries = []
        seen = {}
        for t in texts:
            key = t["text_id"]
            if key in seen:
                continue
            seen[key] = t
            per_op[t["op"]] = per_op.get(t["op"], 0) + 1
            entries.append({
                "id": t["id"],
                "pre_jp": t["text"],
                "message": t["text"],
            })
        out_path = os.path.join(args.out, stem + ".json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(entries, f, ensure_ascii=False, indent=2)
            f.write("\n")
        total += len(entries)
        if entries:
            print("%s -> %s  (%d)" % (os.path.basename(path), os.path.basename(out_path), len(entries)))
    print("done: %d files, %d texts" % (len(files), total))
    for op in sorted(per_op):
        print("  %-14s %d" % (op, per_op[op]))
    return 0


# ---------------------------------------------------------------------------
# inject
# ---------------------------------------------------------------------------
def cmd_inject(args):
    types = parse_types(args.types)
    files = collect_asm_files(args.src)
    if not args.in_place:
        os.makedirs(args.out, exist_ok=True)
    total = 0
    changed_files = 0
    warnings = []
    for path in files:
        raw = open(path, encoding="utf-8", newline="").read()
        lines = raw.splitlines(keepends=True)
        stem = stem_of(path)
        texts = scan_texts(lines, stem, types)
        if not texts:
            if not args.in_place:
                open(os.path.join(args.out, os.path.basename(path)), "w",
                     encoding="utf-8", newline="").write(raw)
            continue
        jp = find_json(args.json, stem)
        if not jp:
            print("[跳过] %s（没有 %s.json）" % (os.path.basename(path), stem))
            if not args.in_place:
                open(os.path.join(args.out, os.path.basename(path)), "w",
                     encoding="utf-8", newline="").write(raw)
            continue
        data = json.load(open(jp, encoding="utf-8-sig"))
        if not isinstance(data, list):
            raise SystemExit("%s 不是 JSON 数组" % jp)
        by_id = {}
        for ent in data:
            if "id" in ent:
                by_id[ent["id"]] = ent
        # 没有 id 的旧格式按顺序对齐
        if not by_id and len(data) == len(texts):
            for t, ent in zip(texts, data):
                by_id[t["id"]] = ent

        # 按行收集替换
        by_line = {}
        changed = False
        for t in texts:
            ent = by_id.get(t["id"])
            if ent is None:
                continue
            new = ent.get("message")
            if not new:
                new = ent.get("pre_jp") or t["text"]
            if not isinstance(new, str):
                raise SystemExit("%s: %s 的 message 不是字符串" % (jp, t["id"]))
            if new == t["text"]:
                continue
            if args.encoding and not is_encodable(new, args.encoding):
                new, bad = replace_bad_chars(new, args.encoding)
                warnings.append((os.path.basename(path), t["id"], bad))
            by_line.setdefault(t["line"], []).append((t["start"], t["end"], escape_body(new)))
            changed = True

        for li, repls in by_line.items():
            line = lines[li]
            for start, end, new_body in sorted(repls, reverse=True):
                line = line[:start] + new_body + line[end:]
            lines[li] = line

        if changed and args.encoding:
            for i, line in enumerate(lines):
                b = line.rstrip("\r\n")
                m = ENC_LINE_RE.match(b)
                if m:
                    lines[i] = m.group(1) + args.encoding + line[len(b):]
                    break

        if changed:
            changed_files += 1
        out_text = "".join(lines)
        if args.in_place:
            bak = path + ".bak"
            if not os.path.exists(bak):
                open(bak, "w", encoding="utf-8", newline="").write(raw)
            target = path
        else:
            target = os.path.join(args.out, os.path.basename(path))
        open(target, "w", encoding="utf-8", newline="").write(out_text)
        total += len(texts)

    if warnings:
        print("\n警告：%d 处字符无法用 %s 编码，已替换为 '?'" % (len(warnings), args.encoding))
        for fn, tid, bad in warnings[:20]:
            try:
                print("  %s %s: %s" % (fn, tid, bad))
            except UnicodeEncodeError:
                print("  %s %s: %s" % (fn, tid, bad.encode("unicode_escape").decode("ascii")))
    print("done: %d files, %d texts, %d files changed" % (len(files), total, changed_files))
    return 0


def find_json(json_dir, stem):
    for name in (stem + ".json", stem + ".TXT.json"):
        p = os.path.join(json_dir, name)
        if os.path.exists(p):
            return p
    return None


def parse_types(s):
    if not s:
        return dict(TEXT_OPS)
    out = {}
    for name in s.split(","):
        name = name.strip().upper()
        if name not in TEXT_OPS:
            raise SystemExit("未知指令类型: %s（可选: %s）" % (name, ", ".join(TEXT_OPS)))
        out[name] = TEXT_OPS[name]
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="asm.txt <-> 翻译 JSON")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="asm.txt -> JSON")
    p.add_argument("-s", "--src", required=True, help="asm.txt 文件或目录")
    p.add_argument("-o", "--out", default="json_jp", help="输出 JSON 目录（默认 json_jp）")
    p.add_argument("--types", default=None, help="逗号分隔的指令类型")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("inject", help="JSON -> asm.txt")
    p.add_argument("-s", "--src", required=True, help="原 asm.txt 文件或目录")
    p.add_argument("-j", "--json", required=True, help="译文 JSON 目录")
    p.add_argument("-o", "--out", default="asm_cn", help="输出目录（默认 asm_cn）")
    p.add_argument("--in-place", action="store_true", help="覆盖源文件（先备份 .bak）")
    p.add_argument("--encoding", default=None, help="更新 asm 头部编码，如 gbk")
    p.add_argument("--types", default=None, help="逗号分隔的指令类型")
    p.set_defaults(func=cmd_inject)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
