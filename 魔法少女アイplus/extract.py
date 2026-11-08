#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extract.py — 从 dis/*.asm.txt 提取 GalTransl json_jp。

只提取：
  MESSAGE       "【秋俊】CR「...」"  -> name=秋俊, message=「...」
  MESSAGE_AUTO  同上（多一个参数）
  TITLE         "１３日目Ａ「...」"  -> message=全文
  CHOICE        每个选项一条 message

每个 .asm.txt 输出一个同名 JSON：00001.asm.txt -> 00001.TXT.json
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from opcodelist import unescape_text  # noqa: E402

ENTRY_RE = re.compile(r"^\s*(MESSAGE_AUTO|MESSAGE|TITLE|CHOICE)\b")
STR_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
# 一个或多个【名字】，可用全角＋连接，例如：
#   【秋俊】CR...
#   【愛（めぐ）】＋【愛】CR...
SPEAKER_RE = re.compile(r"^((?:【[^】]*】\s*＋\s*)*【[^】]*】)(CR)?(.*)$", re.S)


def speaker_groups(text):
    """返回开头连续的【...】名字组；没有则返回 []。"""
    m = SPEAKER_RE.match(text)
    if not m:
        return []
    return re.findall(r"【([^】]*)】", m.group(1))


def split_speaker(text):
    """【秋俊】CR「...」 -> (秋俊, CR, 「...」)；
    【愛（めぐ）】＋【愛】CR「...」 -> (愛（めぐ）＋愛, CR, 「...」)。
    """
    m = SPEAKER_RE.match(text)
    if not m or not m.group(1):
        return None, "", text
    raw = re.sub(r"[【】]", "", m.group(1))
    name = re.sub(r"\s*＋\s*", "＋", raw).strip()
    if not name:
        return None, "", text
    return name, (m.group(2) or ""), m.group(3)


def parse_entries(lines):
    """返回 [{kind, line, span, name, message}]，span 为该行第几个引号串。"""
    entries = []
    for li, line in enumerate(lines):
        m = ENTRY_RE.match(line)
        if not m:
            continue
        op = m.group(1)
        if op == "CHOICE":
            for si, sm in enumerate(STR_RE.finditer(line)):
                entries.append({
                    "kind": "choice", "line": li, "span": si,
                    "name": None, "message": unescape_text(sm.group(1)),
                })
            continue
        sm = STR_RE.search(line)
        if not sm:
            continue
        text = unescape_text(sm.group(1))
        if op == "TITLE":
            if text:
                entries.append({
                    "kind": "title", "line": li, "span": 0,
                    "name": None, "message": text,
                })
            continue
        name, _sep, msg = split_speaker(text)
        entries.append({
            "kind": "message", "line": li, "span": 0,
            "name": name, "message": msg,
        })
    return entries


def to_json(entries):
    out = []
    for e in entries:
        if e["name"]:
            out.append({"name": e["name"], "message": e["message"]})
        else:
            out.append({"message": e["message"]})
    return out


def main():
    ap = argparse.ArgumentParser(description="提取 dis/*.asm.txt 为 GalTransl json_jp")
    ap.add_argument("--src", default="dis", help="asm.txt 目录，默认 dis")
    ap.add_argument("--out", default="json_jp", help="输出目录，默认 json_jp")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    files = sorted(f for f in os.listdir(args.src) if f.endswith(".asm.txt"))
    total = 0
    for fn in files:
        path = os.path.join(args.src, fn)
        lines = open(path, encoding="utf-8").read().splitlines()
        entries = parse_entries(lines)
        stem = fn[:-len(".asm.txt")]
        out_name = stem + ".TXT.json"
        text = json.dumps(to_json(entries), ensure_ascii=False, indent=2)
        with open(os.path.join(args.out, out_name), "w",
                  encoding="utf-8-sig", newline="\r\n") as f:
            f.write(text)
        total += len(entries)
        if entries:
            print("%s -> %s  (%d)" % (fn, out_name, len(entries)))
    print("done: %d files, %d entries -> %s/" % (len(files), total, args.out))


if __name__ == "__main__":
    main()
