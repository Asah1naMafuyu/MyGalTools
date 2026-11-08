#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract.py -- 把 NScripter 的 0.txt 提取成 GalTransl 用的 json_jp

只提取以下内容：
  1. 对话 / 内心独白   [名字/立绘]「...」  或  [名字/立绘]（...）
  2. 旁白              不以命令/注释开头的正文行
  3. 章节名            scene "序章" 这类字面量（空串和 $变量 不算）
  4. 选项              csel "选项1",*标签1,"选项2",*标签2...
  5. 菜单 / UI          单独输出到 ZZ_menu.TXT.json

不提取任何代码行（命令、标签、注释、变量赋值等）。

输出：
  json_jp/<编号>_<原名>.TXT.json   每个 ;$filebegin ... ;$fileend 段一个文件
  json_jp/ZZ_menu.TXT.json         菜单/UI 文本（yesnobox / stralias / spfont / insertmenu / ＜データ無し＞）
  extract_manifest.json            段名、文件名、行号、条目数的清单

JSON 格式与 GalTransl 的 json_jp 一致：
  [
    {"message": "「......」"},
    {"name": "美咲", "message": "「......」"},
    ...
  ]
"""
import argparse
import json
import os
import re

BEGIN_RE = re.compile(r"^\;\$filebegin\s+(.+?)\s*$")
END_RE = re.compile(r"^\;\$fileend\s+(.+?)\s*$")
SCENE_RE = re.compile(r'^scene\s+"(.*)"\s*$')
CMD_RE = re.compile(r"^[a-z_][a-z0-9_]*(\s|$)")
NUM_CMD_RE = re.compile(r"^%[a-z0-9_]+\s*=")
DLG_RE = re.compile(r"^\[([^\]]*)\](.*)$")
CSEL_RE = re.compile(r"^\s*csel\b")
QUOTED_RE = re.compile(r'"([^"]*)"')
OPEN_CLOSE = {"「": "」", "『": "』", "（": "）", "(": ")"}
ASCII_ONLY_RE = re.compile(r"^[\x00-\x7f]*$")


def extract_quoted(line):
    """取出命令里所有双引号内的字符串（用于 csel 选项）。"""
    return [m.group(1) for m in QUOTED_RE.finditer(line)]


# 菜单/UI 文本所在的命令；这些行里的双引号字符串会单独提取到 ZZ_menu.TXT.json
MENU_COMMANDS = ("yesnobox", "stralias", "spfont", "insertmenu")
# 这些 scene 的字面量也会显示在窗口上，放进菜单 JSON
MENU_SCENE_LITERALS = ("タイトル", "スタッフロール")
MENU_MARKER = "＜データ無し＞"


def menu_occurrences(lines):
    """按文件顺序返回菜单文本出现位置。

    每项: {index: 行号(0-based), start/end: 引号区间, text: 引号内文本}
    """
    occ = []
    for i, line in enumerate(lines):
        s = line.lstrip()
        sm = SCENE_RE.match(line)
        scene_ui = bool(sm and sm.group(1) in MENU_SCENE_LITERALS)
        matched = any(re.match(r"^" + cmd + r"\b", s) for cmd in MENU_COMMANDS) or scene_ui
        if not matched and MENU_MARKER not in line:
            continue
        for m in QUOTED_RE.finditer(line):
            text = m.group(1)
            if not matched and MENU_MARKER not in text:
                continue
            occ.append({"index": i, "start": m.start(), "end": m.end(), "text": text})
    return occ


def parse_dialogue(line):
    """返回 (who, message, tail) 或 None。message 含引号/括号。"""
    m = DLG_RE.match(line)
    if not m:
        return None
    who, rest = m.group(1), m.group(2)
    if not rest or rest[0] not in OPEN_CLOSE:
        return None
    close = OPEN_CLOSE[rest[0]]
    idx = rest.rfind(close)
    if idx < 0:
        return None
    return who, rest[: idx + 1], rest[idx + 1:]


def is_code_line(line):
    s = line.strip()
    if not s:
        return True
    if s.startswith(";") or s.startswith("*"):
        return True
    if CMD_RE.match(s) or NUM_CMD_RE.match(s):
        return True
    if s == "cl-1" or re.match(r"^cl-?\d+$", s):
        return True
    # 纯 ASCII 行基本是代码/控制行（正文里只有一行的全角英文不算）
    if ASCII_ONLY_RE.match(s):
        return True
    return False


def split_sections(lines):
    """按 ;$filebegin / ;$fileend 切段，返回 [(name, begin_idx, end_idx)]（0-based，不含标记行）。"""
    sections = []
    cur = None
    for i, line in enumerate(lines):
        m = BEGIN_RE.match(line)
        if m:
            cur = [m.group(1), i + 1, None]
            sections.append(cur)
            continue
        if END_RE.match(line):
            if cur is not None:
                cur[2] = i
            cur = None
    return [(n, b, e) for n, b, e in sections]


def section_filename(name):
    code, sep, rest = name.partition(")")
    if not sep:
        code, rest = "", name
    stem = rest
    if stem.lower().endswith(".txt"):
        stem = stem[:-4]
    stem = stem.replace(" ", "_")
    stem = re.sub(r'[\\/:*?"<>|]', "_", stem)
    return f"{code}_{stem}.TXT.json".lstrip("_")


def extract_section(lines, begin, end):
    """begin/end 为 0-based，end 不含。返回 entries 列表。"""
    entries = []
    for i in range(begin, end):
        line = lines[i]
        if not line.strip():
            continue
        if line.lstrip().startswith(";") or line.lstrip().startswith("*"):
            continue
        sm = SCENE_RE.match(line)
        if sm:
            name = sm.group(1)
            if name and "$" not in name:
                entries.append({"kind": "scene", "index": i, "name": None, "message": name, "tail": ""})
            continue
        p = parse_dialogue(line)
        if p:
            who, msg, tail = p
            name = who.split("/", 1)[0]
            entries.append({"kind": "dialogue", "index": i, "name": name, "message": msg, "tail": tail})
            continue
        if CSEL_RE.match(line):
            texts = extract_quoted(line)
            if texts:
                for pos, text in enumerate(texts):
                    entries.append({
                        "kind": "csel", "index": i, "name": None,
                        "message": text, "tail": "",
                        "choice_pos": pos, "choice_total": len(texts),
                    })
                continue
        if is_code_line(line):
            continue
        entries.append({"kind": "narration", "index": i, "name": None, "message": line, "tail": ""})
    return entries


def to_galtransl_entry(e):
    if e["kind"] == "dialogue":
        return {"name": e["name"], "message": e["message"]}
    return {"message": e["message"]}


def write_json(path, entries):
    text = json.dumps(entries, ensure_ascii=False, indent=2)
    # 与示例一致：UTF-8 BOM + CRLF
    with open(path, "w", encoding="utf-8-sig", newline="\r\n") as f:
        f.write(text)


def main():
    ap = argparse.ArgumentParser(description="提取 NScripter 0.txt 为 GalTransl json_jp")
    ap.add_argument("--src", default="0.txt", help="解包后的脚本（Shift-JIS/CP932），默认 0.txt")
    ap.add_argument("--out", default="json_jp", help="输出 JSON 目录，默认 json_jp")
    ap.add_argument("--manifest", default="extract_manifest.json", help="清单文件")
    ap.add_argument("--encoding", default="cp932", help="源脚本编码，默认 cp932")
    args = ap.parse_args()

    raw = open(args.src, "rb").read()
    text = raw.decode(args.encoding)
    lines = text.split("\n")
    sections = split_sections(lines)

    os.makedirs(args.out, exist_ok=True)
    manifest = {"source": args.src, "encoding": args.encoding, "sections": []}
    total = 0
    for name, begin, end in sections:
        if end is None:
            raise SystemExit(f"段 {name} 没有 ;$fileend")
        entries = extract_section(lines, begin, end)
        filename = section_filename(name)
        write_json(os.path.join(args.out, filename), [to_galtransl_entry(e) for e in entries])
        manifest["sections"].append({
            "name": name,
            "file": filename,
            "begin_line": begin + 1,
            "end_line": end + 1,
            "entries": len(entries),
        })
        total += len(entries)
        print(f"{name} -> {filename}  ({len(entries)} entries)")

    # 菜单/UI 文本单独一个 JSON
    menu = menu_occurrences(lines)
    menu_file = "ZZ_menu.TXT.json"
    write_json(os.path.join(args.out, menu_file), [{"message": o["text"]} for o in menu])
    manifest["menu"] = {"file": menu_file, "entries": len(menu)}

    with open(args.manifest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"menu -> {menu_file}  ({len(menu)} entries)")
    print(f"done: {len(sections)} script files, {total} story entries + {len(menu)} menu entries -> {args.out}/")


if __name__ == "__main__":
    main()
