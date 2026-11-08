"""pict_bnd.py — pict.bnd 图片封包的解包 / 打包（直接处理 BMP）。

pict.bnd 与 scr.bnd 使用同一种 BND 容器和 LZSS 压缩；393 个条目全部是
标准 BMP（24bpp/32bpp，部分带尾部附加字节）。因此解包时直接写出原始
BMP 字节，不转 PNG；修图后用任意支持 BMP 的编辑器保存，再打包即可。

解包：
    python pict_bnd.py extract <pict.bnd> <输出目录>
    输出 00000.bmp ... 00392.bmp 和 manifest.json（原始哈希，用于复用
    未修改条目的压缩块）。

打包：
    python pict_bnd.py pack <输入目录> <输出.bnd> [--base <原pict.bnd>]
    - BMP 未修改：直接复用原 BND 压缩块，结果与原包逐字节一致；
    - BMP 修改过：按原样重新 LZSS 压缩（游戏解压器兼容）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

try:
    import bnd
except ImportError:
    import scr_bnd as bnd

MANIFEST = "manifest.json"

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
GAME_ROOT = os.path.dirname(WORK)
DEFAULT_BASE = os.path.join(GAME_ROOT, "pict.bnd")
if not os.path.exists(DEFAULT_BASE):
    DEFAULT_BASE = os.path.join(WORK, "pict.bnd")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract(bnd_path: str, out_dir: str) -> int:
    raw, entries = bnd.read_bnd(bnd_path)
    os.makedirs(out_dir, exist_ok=True)
    manifest = []
    for i, (off, usize, csize) in enumerate(entries):
        data = bnd.lzss_decompress(raw[off:off + csize], usize)
        if len(data) < 2 or data[:2] != b"BM":
            raise ValueError("条目 %05d 不是 BMP" % i)
        name = "%05d.bmp" % i
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(data)
        manifest.append({"name": name, "sha256": sha256(data)})
        if (i + 1) % 50 == 0:
            print("  已解包 %d/%d" % (i + 1, len(entries)))
    with open(os.path.join(out_dir, MANIFEST), "w", encoding="utf-8") as f:
        json.dump({"version": 1, "entries": manifest}, f, ensure_ascii=False, indent=1)
    print("解包完成：%d 个 BMP -> %s" % (len(entries), out_dir))
    return len(entries)


def load_manifest(in_dir: str):
    p = os.path.join(in_dir, MANIFEST)
    if not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)["entries"]


def pack(in_dir: str, out_path: str, base_path: str | None) -> int:
    manifest = load_manifest(in_dir)
    base_raw = None
    base_entries = []
    if base_path and os.path.exists(base_path):
        base_raw, base_entries = bnd.read_bnd(base_path)
    if manifest and base_raw is not None and len(manifest) != len(base_entries):
        raise ValueError("manifest 条目数 %d 与原 BND %d 不一致"
                         % (len(manifest), len(base_entries)))
    if manifest is None:
        files = sorted(f for f in os.listdir(in_dir) if f.lower().endswith(".bmp"))
    else:
        files = [m["name"] for m in manifest]

    blobs = []
    usizes = []
    changed = 0
    for i, name in enumerate(files):
        path = os.path.join(in_dir, name)
        if not os.path.exists(path):
            raise ValueError("缺少文件: %s" % path)
        data = open(path, "rb").read()
        if len(data) < 2 or data[:2] != b"BM":
            raise ValueError("%s 不是 BMP" % name)

        if (manifest and base_raw is not None and i < len(base_entries)
                and manifest[i]["sha256"] == sha256(data)):
            off, usize, csize = base_entries[i]
            blobs.append(base_raw[off:off + csize])
            usizes.append(usize)
            continue

        blobs.append(bnd.lzss_compress_literal(data))
        usizes.append(len(data))
        changed += 1
        if changed <= 20:
            print("  已修改 %s：%d 字节" % (name, len(data)))

    count = len(files)
    header_size = 4 + count * 12
    entries = []
    cur = header_size
    for u, blob in zip(usizes, blobs):
        entries.append((cur, u, len(blob)))
        cur += len(blob)

    with open(out_path, "wb") as f:
        f.write(struct.pack("<I", count))
        for e in entries:
            f.write(struct.pack("<III", *e))
        for blob in blobs:
            f.write(blob)
    print("打包完成：%d 个 BMP（修改 %d 个），%d 字节 -> %s"
          % (count, changed, cur, out_path))
    return changed


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="pict.bnd 图片封包工具（BMP）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="解包 pict.bnd 为 BMP")
    p.add_argument("bnd")
    p.add_argument("out_dir")

    p = sub.add_parser("pack", help="把 BMP 打包回 pict.bnd")
    p.add_argument("in_dir")
    p.add_argument("out_bnd")
    p.add_argument("--base", default=None,
                   help="原始 pict.bnd（复用未修改条目；默认自动查找）")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "extract":
            extract(args.bnd, args.out_dir)
        else:
            base = args.base or DEFAULT_BASE
            if not os.path.exists(base):
                print("[提示] 找不到原始 BND，将全量重新压缩：%s" % base,
                      file=sys.stderr)
                base = None
            pack(args.in_dir, args.out_bnd, base)
        return 0
    except Exception as e:
        print("[失败] %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
