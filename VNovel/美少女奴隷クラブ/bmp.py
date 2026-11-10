#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bmp.py — 还原游戏里的 BMP 图片
==============================

游戏的 `.BMP` 并不是标准文件：**文件头前两个字节被写反了**，
`BM` 变成了 `MB`（`42 4D` → `4D 42`），所以双击打不开、看图软件也不认。
把这两个字节换回来就是一张普通的 24 位 BMP，像素数据没有加密。

用法：

    python bmp.py 图片文件夹 -o 输出文件夹              :: 递归还原整棵目录
    python bmp.py 图片文件夹 -o 输出文件夹 --png        :: 顺便转成 PNG
    python bmp.py 单个图片.bmp -o 输出文件夹            :: 单个文件
    python bmp.py 图片文件夹 --check                    :: 只统计，不写文件
"""

import argparse
import os
import sys
from pathlib import Path

BMP_SUFFIX = ".bmp"
BAD_MAGIC = b"MB"
GOOD_MAGIC = b"BM"


def fix_bytes(raw: bytes) -> bytes:
    """把 MB 头换回 BM；已经是 BM 的原样返回。"""
    if raw[:2] == BAD_MAGIC:
        return GOOD_MAGIC + raw[2:]
    return raw


def is_fixed(raw: bytes) -> bool:
    return raw[:2] == GOOD_MAGIC


def iter_bmp(root: Path, recursive=False):
    if root.is_file():
        yield root
        return
    for cur, dirs, files in os.walk(root):
        if not recursive:
            dirs[:] = []
        for fn in sorted(files):
            if fn.lower().endswith(BMP_SUFFIX):
                yield Path(cur) / fn


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="bmp.py",
        description="还原游戏 BMP（文件头 MB -> BM），可选转 PNG",
        epilog="示例:\n"
               "  python bmp.py 图片文件夹 -o 输出文件夹\n"
               "  python bmp.py 图片文件夹 -o 输出文件夹 --png\n"
               "  python bmp.py 图片文件夹 --check",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="BMP 文件或文件夹")
    parser.add_argument("-o", "--out", default="bmp_out", help="输出目录（默认 bmp_out）")
    parser.add_argument("--png", action="store_true", help="转换成 PNG（需要 Pillow）")
    parser.add_argument("--no-recursive", action="store_true",
                        help="只处理当前目录（默认递归子目录）")
    parser.add_argument("--check", action="store_true", help="只统计，不写文件")
    args = parser.parse_args(argv)

    src = Path(args.input)
    if not src.exists():
        print("输入不存在: %s" % src, file=sys.stderr)
        return 2

    files = list(iter_bmp(src, not args.no_recursive))
    if not files:
        print("没有找到 .bmp 文件: %s" % src, file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    if not args.check:
        out_dir.mkdir(parents=True, exist_ok=True)

    fixed = bad = skipped = 0
    for f in files:
        raw = f.read_bytes()
        if is_fixed(raw):
            skipped += 1
        else:
            fixed += 1
        if args.check:
            continue

        data = fix_bytes(raw)
        rel = f.relative_to(src) if src.is_dir() else Path(f.name)
        if args.png:
            try:
                import io
                from PIL import Image
            except ImportError:
                print("需要 Pillow 才能转 PNG：pip install pillow", file=sys.stderr)
                return 3
            im = Image.open(io.BytesIO(data))
            dst = out_dir / rel.with_suffix(".png")
            dst.parent.mkdir(parents=True, exist_ok=True)
            im.save(dst)
        else:
            dst = out_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
        print("[OK] %s -> %s" % (f.name, dst))

    if args.check:
        print("检查：%d 个 BMP，%d 个需要修复，%d 个已是 BM" % (len(files), fixed, skipped))
    else:
        print("完成：%d 个 BMP -> %s/（修复 %d，原本正常 %d）"
              % (len(files), out_dir, fixed, skipped))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
