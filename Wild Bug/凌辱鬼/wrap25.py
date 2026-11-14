#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wrap25.py -- 给翻译 JSON 的 message 每 25 个字补一个 {{0A}} 换行。

规则（与游戏原来的 25 字/行一致）：

1. 从上一个 {{0A}} 之后开始数，满 25 个字就在其后插入 {{0A}}；
   已有的 {{0A}} 既保留，也会把计数清零。
2. 行尾的 `\\`（JSON 里的 `\\\\`）是“接续下一句”的标记：
   它本身不占字数，且下一句会接着当前计数继续排，直到凑满 25 字。
   例如上一句排到 19 字并以 `\\` 结尾，下一句再排 4 个字就换行。
3. 其它 `{{XX}}` 占位符代表原始字节，不占字数，也不会在它中间断行。
4. 如果刚好在句尾满 25 字，不会补一个多余的换行。

用法：
    python wrap25.py                 # 就地处理 json_cn（备份 .bak）
    python wrap25.py -s json_cn -o json_cn_wrap
    python wrap25.py --width 25 --dry-run
"""
import argparse
import json
import os
import shutil
import sys

NL = "{{0A}}"


def wrap_text(text, count, pending, width):
    """处理一条 message。

    count   : 进入本条时已经排了多少字（上一句以 \\ 接续时非 0）
    pending : 上一句刚好排满 width，是否还欠一个换行
    返回 (新文本, 结束时的 count, 结束时的 pending)
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("{{", i):
            j = text.find("}}", i + 2)
            if j != -1 and j - i == 4:
                tok = text[i:j + 2]
                out.append(tok)
                if tok == NL:
                    count = 0
                    pending = False
                i = j + 2
                continue
        ch = text[i]
        if ch == "\\" and i == n - 1:
            # 行尾续行符：保留、不占字数
            out.append(ch)
            i += 1
            continue
        if pending:
            out.append(NL)
            count = 0
            pending = False
        out.append(ch)
        count += 1
        if count >= width:
            pending = True
        i += 1
    return "".join(out), count, pending


def process_file(path, out_path, width, dry_run=False):
    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise SystemExit("%s 不是 JSON 数组" % path)

    count = 0
    pending = False
    changed = 0
    for ent in data:
        msg = ent.get("message")
        if not isinstance(msg, str) or not msg:
            count = 0
            pending = False
            continue
        new, count, pending = wrap_text(msg, count, pending, width)
        carry = msg.endswith("\\") and len(msg) > 1
        if not carry:
            # 句子结束：丢掉未使用的 pending，下一句重新计数
            pending = False
            count = 0
        if new != msg:
            ent["message"] = new
            changed += 1

    if not dry_run:
        text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    return changed


def main(argv=None):
    ap = argparse.ArgumentParser(description="每 N 个字补一个 {{0A}}")
    ap.add_argument("-s", "--src", default="json_cn", help="JSON 目录，默认 json_cn")
    ap.add_argument("-o", "--out", default=None, help="输出目录（默认就地修改）")
    ap.add_argument("--width", type=int, default=25, help="每行字数，默认 25")
    ap.add_argument("--in-place", action="store_true", help="就地修改（默认行为）")
    ap.add_argument("--dry-run", action="store_true", help="只统计不写文件")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.src):
        raise SystemExit("找不到目录: %s" % args.src)
    out_dir = args.out
    in_place = out_dir is None
    if in_place:
        out_dir = args.src

    files = sorted(f for f in os.listdir(args.src) if f.endswith(".json"))
    total_changed = 0
    for fn in files:
        src = os.path.join(args.src, fn)
        dst = os.path.join(out_dir, fn)
        if in_place and not args.dry_run:
            bak = src + ".bak"
            if not os.path.exists(bak):
                shutil.copyfile(src, bak)
        n = process_file(src, dst, args.width, args.dry_run)
        total_changed += n
        if n:
            print("%s: %d 条补了换行" % (fn, n))
    print("done: %d files, %d messages changed%s"
          % (len(files), total_changed, " (dry-run)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
