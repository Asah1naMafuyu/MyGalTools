#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inject.py -- 把 GalTransl 翻译好的 json_cn 注入回 0.txt

要求与行为：
  * 行数严格不变：每条 JSON 只替换原行中的文本片段，不增删行。
  * 0.txt 的代码行/注释/标签/空行原样保留（逐字节）。
  * json_cn 里出现的条目全部注入（即使文本和原文相同），统一按 GBK 写入。
  * 菜单/UI 文本从单独的 ZZ_menu.TXT.json 注入回各自原来的位置。
  * 代码行里的 CP932 【 】（81 79 / 81 7A）会转成 GBK，避免在 GBK 引擎里显示成「亂亃」。
  * 如果译文里有换行，会替换成空格（避免破坏行数），并给出警告。
  * 如果译文里有 GBK 不支持的字符，会替换成 '?' 并汇总警告。

用法：
  python inject.py --src 0.txt --json json_cn --out 0.cn.txt
  python inject.py --src 0.txt --json json_cn --out 0.cn.txt --in-place

默认读取 extract_manifest.json 来把段名映射到 JSON 文件名；
如果 JSON 文件名被改过，编辑 manifest 即可。
"""
import argparse
import json
import os
import re
import sys

from extract_nscript import (
    parse_dialogue,
    split_sections,
    extract_section,
    section_filename,
    menu_occurrences,
)


def gbk_encode(s, ctx, warnings, encoding="gbk"):
    """把译文编码为指定编码（默认 GBK）；不支持字符用 '?' 代替并记录。"""
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    try:
        return s.encode(encoding)
    except UnicodeEncodeError:
        out = bytearray()
        bad = []
        for ch in s:
            try:
                out += ch.encode(encoding)
            except UnicodeEncodeError:
                bad.append(ch)
                out += b"?"
        if bad:
            warnings.append((ctx, "".join(bad)))
        return bytes(out)


def build_dialogue_line(source_line, translated, ctx, warnings, enc):
    who, orig_msg, tail = parse_dialogue(source_line)
    orig_name, slash, suffix = who.partition("/")
    new_name = translated.get("name") or orig_name
    new_name = new_name.replace("/", "／")  # 防止破坏 name/sprite 分隔
    new_msg = translated["message"]
    # 只要在 json_cn 里，就一律按译文编码注入，不再保留未改动的 CP932 文本
    name_bytes = gbk_encode(new_name, ctx + " name", warnings, enc)
    msg_bytes = gbk_encode(new_msg, ctx + " message", warnings, enc)
    return (b"[" + name_bytes + (slash + suffix).encode("cp932")
            + b"]" + msg_bytes + tail.encode("cp932"))


def build_scene_line(source_line, translated, ctx, warnings, enc):
    msg = translated["message"]
    if len(msg) >= 2 and msg[0] == '"' and msg[-1] == '"':
        msg = msg[1:-1]
    msg = msg.replace('"', "”")
    return b'scene "' + gbk_encode(msg, ctx + " scene", warnings, enc) + b'"'


def build_narration_line(source_line, translated, ctx, warnings, enc):
    return gbk_encode(translated["message"], ctx + " message", warnings, enc)


def build_csel_line(source_line, messages, ctx, warnings, enc):
    """把同一个 csel 行的多条译文合并回一行，保留逗号和跳转标签。"""
    parts = []
    orig = []
    last = 0
    for m in re.finditer(r'"([^"]*)"', source_line):
        parts.append(source_line[last:m.start()])
        orig.append(m.group(1))
        last = m.end()
    parts.append(source_line[last:])
    if len(messages) != len(orig):
        raise SystemExit(
            f"{ctx}: csel 选项数 {len(messages)} != 原文 {len(orig)}")
    out = bytearray(parts[0].encode("cp932"))
    for i, msg in enumerate(messages):
        inner = gbk_encode(msg.replace('"', "”"), f"{ctx} choice{i+1}", warnings, enc)
        out += b'"' + inner + b'"' + parts[i + 1].encode("cp932")
    return bytes(out)


def build_menu_line(source_line, replacements, ctx, warnings, enc):
    """把菜单行里选中的引号字符串替换成译文，其余部分原样保留。

    replacements: {引号匹配的起始位置: 译文}
    """
    out = bytearray()
    last = 0
    n = 0
    for m in re.finditer(r'"([^"]*)"', source_line):
        if m.start() in replacements:
            out += source_line[last:m.start()].encode("cp932")
            text = replacements[m.start()].replace('"', "”")
            out += b'"' + gbk_encode(text, f"{ctx} menu{n+1}", warnings, enc) + b'"'
            last = m.end()
            n += 1
    out += source_line[last:].encode("cp932")
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description="把 json_cn 注入回 NScripter 0.txt（GBK 译文）")
    ap.add_argument("--src", default="0.txt")
    ap.add_argument("--json", default="json_cn")
    ap.add_argument("--out", default="0.cn.txt")
    ap.add_argument("--manifest", default="extract_manifest.json")
    ap.add_argument("--encoding", default="cp932")
    ap.add_argument("--text-encoding", default="gbk", help="译文编码，默认 gbk；测试可用 cp932")
    ap.add_argument("--in-place", action="store_true", help="直接覆盖 --src（会先写 .bak）")
    args = ap.parse_args()

    raw = open(args.src, "rb").read()
    text = raw.decode(args.encoding)
    lines = text.split("\n")
    raw_lines = raw.split(b"\n")
    if len(raw_lines) != len(lines):
        raise SystemExit("行数不一致，源文件可能不是纯 LF 换行")

    sections = split_sections(lines)

    manifest = {}
    menu_file = "ZZ_menu.TXT.json"
    if os.path.exists(args.manifest):
        m = json.load(open(args.manifest, encoding="utf-8"))
        for s in m.get("sections", []):
            manifest[s["name"]] = s["file"]
        menu_file = m.get("menu", {}).get("file", menu_file)

    warnings = []
    total = 0
    story_entry_idxs = set()
    modified_idxs = set()
    for name, begin, end in sections:
        entries = extract_section(lines, begin, end)
        filename = manifest.get(name) or section_filename(name)
        path = os.path.join(args.json, filename)
        if not os.path.exists(path):
            raise SystemExit(f"缺少翻译文件: {path}")
        data = json.load(open(path, encoding="utf-8-sig"))
        if not isinstance(data, list):
            raise SystemExit(f"{path} 不是 JSON 数组")
        if len(data) != len(entries):
            raise SystemExit(
                f"{path}: 条目数 {len(data)} != 原文可提取行数 {len(entries)}。"
                "请勿增删条目，或检查是否用错了翻译文件。")
        # 同一行可能有多个条目（csel 的每个选项一条），先按行分组
        groups = []
        for ent in entries:
            if (ent["kind"] == "csel" and groups
                    and groups[-1]["kind"] == "csel"
                    and groups[-1]["index"] == ent["index"]):
                groups[-1]["entries"].append(ent)
            else:
                groups.append({"kind": ent["kind"], "index": ent["index"], "entries": [ent]})

        di = 0
        for g in groups:
            n = len(g["entries"])
            trs = data[di:di + n]
            if len(trs) != n:
                raise SystemExit(f"{path}: 条目数不足（csel 需要 {n} 条）")
            for tr in trs:
                if "message" not in tr:
                    raise SystemExit(f"{path} 第 {di+1} 条缺少 message 字段")
            ctx = f"{filename}#{di+1}"
            idx = g["index"]
            story_entry_idxs.add(idx)
            modified_idxs.add(idx)
            if g["kind"] == "csel":
                raw_lines[idx] = build_csel_line(
                    lines[idx], [t["message"] for t in trs], ctx, warnings, args.text_encoding)
            elif g["kind"] == "dialogue":
                raw_lines[idx] = build_dialogue_line(lines[idx], trs[0], ctx, warnings, args.text_encoding)
            elif g["kind"] == "scene":
                raw_lines[idx] = build_scene_line(lines[idx], trs[0], ctx, warnings, args.text_encoding)
            else:
                raw_lines[idx] = build_narration_line(lines[idx], trs[0], ctx, warnings, args.text_encoding)
            total += n
            di += n

    # 菜单/UI 文本注入（单独一个 JSON）
    menu_occs = menu_occurrences(lines)
    menu_path = os.path.join(args.json, menu_file)
    menu_count = 0
    if not os.path.exists(menu_path):
        print(f"警告: 缺少菜单翻译文件 {menu_path}，跳过菜单注入。")
    else:
        menu_data = json.load(open(menu_path, encoding="utf-8-sig"))
        if not isinstance(menu_data, list):
            raise SystemExit(f"{menu_path} 不是 JSON 数组")
        if len(menu_data) != len(menu_occs):
            raise SystemExit(
                f"{menu_path}: 条目数 {len(menu_data)} != 原文菜单文本数 {len(menu_occs)}。"
                "请勿增删条目，或检查是否用错了翻译文件。")
        by_line = {}
        for i, (occ, tr) in enumerate(zip(menu_occs, menu_data)):
            if "message" not in tr:
                raise SystemExit(f"{menu_path} 第 {i+1} 条缺少 message 字段")
            if occ["index"] in story_entry_idxs:
                raise SystemExit(
                    f"{menu_path} 第 {i+1} 条与剧情文本行冲突（行 {occ['index']+1}）")
            by_line.setdefault(occ["index"], {})[occ["start"]] = tr["message"]
        for idx, repl in by_line.items():
            raw_lines[idx] = build_menu_line(
                lines[idx], repl, f"{menu_file}#line{idx+1}", warnings, args.text_encoding)
            modified_idxs.add(idx)
        menu_count = len(menu_data)

    # 0.txt 的代码行仍是 CP932；其中 【 】（CP932 81 79 / 81 7A）在 GBK 下会显示成「亂亃」。
    # 对没有被剧情/菜单注入过的行，把这两个 CP932 字节换成 GBK 的 【 】。
    fixed_brackets = 0
    if args.text_encoding.lower() in ("gbk", "gb2312", "gb18030", "cp936"):
        lb = "【".encode("gbk")
        rb = "】".encode("gbk")
        for i, line in enumerate(raw_lines):
            if i in modified_idxs:
                continue
            if b"\x81\x79" in line or b"\x81\x7a" in line:
                raw_lines[i] = line.replace(b"\x81\x79", lb).replace(b"\x81\x7a", rb)
                fixed_brackets += 1

    out = b"\n".join(raw_lines)
    if len(raw_lines) != len(lines):
        raise SystemExit("内部错误：注入后行数变化")

    if args.in_place:
        bak = args.src + ".bak"
        if not os.path.exists(bak):
            open(bak, "wb").write(raw)
        target = args.src
    else:
        target = args.out
    open(target, "wb").write(out)

    print(f"injected {total} story entries + {menu_count} menu entries -> {target}")
    if fixed_brackets:
        print(f"fixed CP932 brackets -> GBK in {fixed_brackets} untouched lines")
    print(f"lines: {len(lines)} (unchanged), bytes: {len(raw)} -> {len(out)}")

    if warnings:
        print(f"\n警告：{len(warnings)} 处 {args.text_encoding} 不支持的字符（已替换为 '?'）")
        seen = set()
        for ctx, bad in warnings:
            key = (ctx.split("#")[0], bad)
            if key in seen:
                continue
            seen.add(key)
            safe = bad.encode("unicode_escape").decode("ascii")
            print(f"  {ctx}: {safe}")
        print(f"建议在译文里把这些字符换成 {args.text_encoding} 可编码的近似字符。")


if __name__ == "__main__":
    main()
