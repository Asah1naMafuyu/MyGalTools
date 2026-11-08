#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""inject.py — 把 GalTransl json_cn 注入回 dis/*.asm.txt。

只替换 MESSAGE / MESSAGE_AUTO / TITLE / CHOICE 的字符串字面量，
其余代码逐字节保留；不增删行。

  python inject.py --src dis --json json_cn --out dis_cn
  python inject.py --src dis --json json_cn --in-place
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from opcodelist import escape_text, unescape_text  # noqa: E402
from extract import STR_RE, parse_entries, split_speaker, speaker_groups  # noqa: E402

LINE_END_RE = re.compile(r"(\r\n|\n|\r)$")


def find_json(json_dir, stem):
    for name in (stem + ".TXT.json", stem + ".json"):
        p = os.path.join(json_dir, name)
        if os.path.exists(p):
            return p
    return None


def one_line(s):
    return s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "CR")


def fix_encoding(s, enc, ctx, warnings):
    """把 enc 不支持的字符替换成 '?' 并记录，避免汇编阶段直接失败。"""
    s = s.replace("・", "·")  # 日文中点 -> GBK 中点
    try:
        s.encode(enc)
        return s
    except UnicodeEncodeError:
        out = []
        bad = []
        for ch in s:
            try:
                ch.encode(enc)
                out.append(ch)
            except UnicodeEncodeError:
                out.append("?")
                bad.append(ch)
        warnings.append((ctx, "".join(bad)))
        return "".join(out)


def rebuild_message(orig_text, tr):
    groups = speaker_groups(orig_text)
    name0, sep0, _msg0 = split_speaker(orig_text)
    new_name = (tr.get("name") or name0 or "")
    new_name = new_name.replace("【", "［").replace("】", "］")
    new_msg = one_line(tr["message"])
    if not new_name:
        return new_msg
    # 原文是【A】＋【B】这种多名字格式时，按＋拆开分别补【】；
    # 原文只有一个【...】时，即使名字里有＋也整体补一个【】。
    if len(groups) > 1 and "＋" in new_name:
        parts = new_name.split("＋")
        if len(parts) == len(groups):
            prefix = "＋".join("【%s】" % p for p in parts)
        else:
            prefix = "【%s】" % new_name
    else:
        prefix = "【%s】" % new_name
    return prefix + sep0 + new_msg


def main():
    ap = argparse.ArgumentParser(description="把 json_cn 注入回 dis/*.asm.txt")
    ap.add_argument("--src", default="dis", help="原 asm.txt 目录，默认 dis")
    ap.add_argument("--json", default="json_cn", help="翻译 JSON 目录，默认 json_cn")
    ap.add_argument("--out", default="dis_cn", help="输出目录，默认 dis_cn")
    ap.add_argument("--in-place", action="store_true", help="直接覆盖 --src（先备份 .bak）")
    ap.add_argument("--text-encoding", default="gbk",
                    help="译文二进制编码，默认 gbk；有改动时同步更新 .encoding")
    args = ap.parse_args()

    if not args.in_place:
        os.makedirs(args.out, exist_ok=True)

    files = sorted(f for f in os.listdir(args.src) if f.endswith(".asm.txt"))
    total = 0
    warnings = []
    for fn in files:
        src_path = os.path.join(args.src, fn)
        raw = open(src_path, encoding="utf-8", newline="").read()
        lines = raw.splitlines(keepends=True)
        entries = parse_entries([LINE_END_RE.sub("", x) for x in lines])
        if not entries:
            if not args.in_place:
                open(os.path.join(args.out, fn), "w", encoding="utf-8",
                     newline="").write(raw)
            continue

        stem = fn[:-len(".asm.txt")]
        jp = find_json(args.json, stem)
        if not jp:
            print("[跳过] %s（没有对应翻译 JSON）" % fn)
            if not args.in_place:
                open(os.path.join(args.out, fn), "w", encoding="utf-8",
                     newline="").write(raw)
            continue
        data = json.load(open(jp, encoding="utf-8-sig"))
        if not isinstance(data, list):
            raise SystemExit("%s 不是 JSON 数组" % jp)
        if len(data) != len(entries):
            raise SystemExit("%s: 条目数 %d != 原文可提取数 %d"
                             % (jp, len(data), len(entries)))

        # 每行收集 (span_index, new_text)
        by_line = {}
        changed = False
        for ent, tr in zip(entries, data):
            if "message" not in tr:
                raise SystemExit("%s: 第 %d 条缺少 message" % (jp, total + 1))
            if ent["kind"] == "message":
                # 原文的完整字符串需要重新拆一次（包含 name/CR）
                sm = list(STR_RE.finditer(LINE_END_RE.sub("", lines[ent["line"]])))[ent["span"]]
                orig_full = unescape_text(sm.group(1))
                new_text = rebuild_message(orig_full, tr)
                if new_text != orig_full:
                    new_text = fix_encoding(new_text, args.text_encoding,
                                            "%s:%d" % (fn, ent["line"] + 1), warnings)
                    changed = True
            else:
                new_text = tr["message"]
                if ent["kind"] == "choice":
                    new_text = new_text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
                else:
                    new_text = new_text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
                if new_text != ent["message"]:
                    new_text = fix_encoding(new_text, args.text_encoding,
                                            "%s:%d" % (fn, ent["line"] + 1), warnings)
                    changed = True
            by_line.setdefault(ent["line"], []).append((ent["span"], new_text))
            total += 1

        for li, repls in by_line.items():
            body = LINE_END_RE.sub("", lines[li])
            ending = lines[li][len(body):]
            spans = [m.span(1) for m in STR_RE.finditer(body)]
            for span_i, new_text in sorted(repls, reverse=True):
                if span_i >= len(spans):
                    raise SystemExit("%s 行 %d: 引号串不足" % (fn, li + 1))
                start, end = spans[span_i]
                body = body[:start] + escape_text(new_text) + body[end:]
            lines[li] = body + ending

        if changed:
            for i, line in enumerate(lines):
                body = LINE_END_RE.sub("", line)
                if body.strip().lower().startswith(".encoding"):
                    lines[i] = ".encoding " + args.text_encoding + line[len(body):]
                    break

        out_text = "".join(lines)
        if args.in_place:
            bak = src_path + ".bak"
            if not os.path.exists(bak):
                open(bak, "w", encoding="utf-8", newline="").write(raw)
            target = src_path
        else:
            target = os.path.join(args.out, fn)
        open(target, "w", encoding="utf-8", newline="").write(out_text)
        print("%s -> %s" % (fn, target))

    if warnings:
        seen = set()
        print("\n警告：%d 处字符无法用 %s 编码（已替换为 '?'）"
              % (len(warnings), args.text_encoding))
        for ctx, bad in warnings:
            key = (ctx.split(":")[0], bad)
            if key in seen:
                continue
            seen.add(key)
            print("  %s: %s" % (ctx, bad.encode("unicode_escape").decode("ascii")))

    print("done: %d files, %d entries" % (len(files), total))


if __name__ == "__main__":
    main()
