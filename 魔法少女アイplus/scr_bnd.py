"""scr_bnd.py — 读写 scr.bnd（BND 归档）与 LZSS 解压/压缩。

BND 结构：
    u32 count
    count * { u32 offset; u32 decomprlen; u32 size; }
    data[offset .. offset+size] 为 LZSS 压缩块

LZSS 参数（与 aiplusdvd.exe 一致）：
    4KB 环形窗口，初始填充 0，初始写入位置 0xFEE；
    控制字节 bit=1 表示 1 字节字面量，bit=0 表示 2 字节匹配：
        offset = ((hi & 0xF0) << 4) | lo
        length = 3 + (hi & 0x0F)

用法：
    python bnd.py list   <scr.bnd>
    python bnd.py extract <scr.bnd> <输出目录>
    python bnd.py pack   <输入目录> <scr.bnd> [--base 原始.bnd]
    python bnd.py verify <scr.bnd> <目录>
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

FRAME_SIZE = 0x1000
FRAME_MASK = FRAME_SIZE - 1
FRAME_INIT = 0xFEE


def lzss_decompress(data: bytes, expected: int | None = None) -> bytes:
    frame = bytearray(FRAME_SIZE)
    frame_pos = FRAME_INIT
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        ctrl = data[i]
        i += 1
        bit = 1
        while bit != 0x100 and i < n:
            if ctrl & bit:
                b = data[i]
                i += 1
                frame[frame_pos & FRAME_MASK] = b
                frame_pos += 1
                out.append(b)
            else:
                if i + 1 >= n:
                    break
                lo = data[i]
                hi = data[i + 1]
                i += 2
                off = ((hi & 0xF0) << 4) | lo
                cnt = 3 + (hi & 0x0F)
                for _ in range(cnt):
                    v = frame[off & FRAME_MASK]
                    off += 1
                    frame[frame_pos & FRAME_MASK] = v
                    frame_pos += 1
                    out.append(v)
            bit <<= 1
    if expected is not None and len(out) != expected:
        raise ValueError(f"LZSS 解压长度不符：期望 {expected}，实际 {len(out)}")
    return bytes(out)


def lzss_compress_literal(data: bytes) -> bytes:
    """以“全字面量”方式编码；游戏解压器完全兼容，零风险。"""
    out = bytearray()
    for i in range(0, len(data), 8):
        out.append(0xFF)
        out += data[i:i + 8]
    return bytes(out)


def read_bnd(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < 4:
        raise ValueError("不是有效的 BND 文件")
    count = struct.unpack_from("<I", raw, 0)[0]
    if count > 0x100000 or 4 + count * 12 > len(raw):
        raise ValueError(f"BND 条目数异常: {count}")
    entries = []
    for i in range(count):
        off, usize, csize = struct.unpack_from("<III", raw, 4 + i * 12)
        entries.append((off, usize, csize))
    return raw, entries


def extract(path: str, out_dir: str, quiet: bool = False) -> int:
    raw, entries = read_bnd(path)
    os.makedirs(out_dir, exist_ok=True)
    for i, (off, usize, csize) in enumerate(entries):
        blob = raw[off:off + csize]
        if len(blob) != csize:
            raise ValueError(f"条目 {i} 的压缩数据越界")
        data = lzss_decompress(blob, usize)
        name = "%05d" % i
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(data)
        if not quiet and (i + 1) % 50 == 0:
            print("  已解包 %d/%d" % (i + 1, len(entries)))
    if not quiet:
        print("解包完成：%d 个文件 -> %s" % (len(entries), out_dir))
    return len(entries)


def pack(in_dir: str, out_path: str, base: str | None = None,
         quiet: bool = False) -> int:
    files = []
    for fn in sorted(os.listdir(in_dir)):
        p = os.path.join(in_dir, fn)
        if os.path.isfile(p) and not fn.startswith("."):
            files.append(p)
    if not files:
        raise ValueError("输入目录为空")

    # 读取 base 归档，未修改的文件可以直接复用原压缩块
    base_blobs: dict[int, bytes] = {}
    base_hashes: dict[int, bytes] = {}
    if base:
        raw, entries = read_bnd(base)
        for i, (off, usize, csize) in enumerate(entries):
            blob = raw[off:off + csize]
            base_blobs[i] = blob
            try:
                base_hashes[i] = lzss_decompress(blob, usize)
            except ValueError:
                pass

    blobs = []
    for i, p in enumerate(files):
        data = open(p, "rb").read()
        if base_hashes.get(i) == data:
            blobs.append(base_blobs[i])
        else:
            blobs.append(lzss_compress_literal(data))

    count = len(files)
    header_size = 4 + count * 12
    entries = []
    off = header_size
    for p, blob in zip(files, blobs):
        usize = os.path.getsize(p)
        entries.append((off, usize, len(blob)))
        off += len(blob)

    with open(out_path, "wb") as f:
        f.write(struct.pack("<I", count))
        for e in entries:
            f.write(struct.pack("<III", *e))
        for blob in blobs:
            f.write(blob)
    if not quiet:
        print("封包完成：%d 个文件，%d 字节 -> %s" % (count, off, out_path))
    return count


def verify(path: str, ref_dir: str) -> int:
    raw, entries = read_bnd(path)
    errors = 0
    for i, (off, usize, csize) in enumerate(entries):
        data = lzss_decompress(raw[off:off + csize], usize)
        ref_path = os.path.join(ref_dir, "%05d" % i)
        if not os.path.exists(ref_path):
            print("缺少参考文件 %s" % ref_path)
            errors += 1
            continue
        ref = open(ref_path, "rb").read()
        if data != ref:
            print("条目 %05d 不一致" % i)
            errors += 1
    print("校验完成：%d 个条目，%d 个不一致" % (len(entries), errors))
    return errors


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="BND 归档工具（scr.bnd）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("list")
    p.add_argument("bnd")
    p = sub.add_parser("extract")
    p.add_argument("bnd")
    p.add_argument("out_dir")
    p = sub.add_parser("pack")
    p.add_argument("in_dir")
    p.add_argument("bnd")
    p.add_argument("--base", help="原始 BND，用于复用未修改条目的压缩块")
    p = sub.add_parser("verify")
    p.add_argument("bnd")
    p.add_argument("dir")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "list":
            raw, entries = read_bnd(args.bnd)
            print("条目数", len(entries))
            for i, (off, usize, csize) in enumerate(entries[:20]):
                print("  %05d offset=%d decompr=%d size=%d" % (i, off, usize, csize))
            if len(entries) > 20:
                print("  ...")
            return 0
        if args.cmd == "extract":
            extract(args.bnd, args.out_dir)
            return 0
        if args.cmd == "pack":
            pack(args.in_dir, args.bnd, args.base)
            return 0
        if args.cmd == "verify":
            return verify(args.bnd, args.dir)
    except Exception as e:
        print("[失败] %s" % e, file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
