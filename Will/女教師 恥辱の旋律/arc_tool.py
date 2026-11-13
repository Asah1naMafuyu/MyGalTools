#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""arc_tool.py - Will Co. (WARC) / Rio.arc 封包解包工具 (Chijyoku.exe 实测格式)

=====================================================================
格式说明 (依据 Chijyoku.exe 0x0042C1A0 读取函数与 0x00404DE0 脚本加载器)
=====================================================================

Rio.arc 没有文件魔数, 结构为:

    u32  dir_count                       目录(子封包)数量, Rio.arc = 1
    dir  [dir_count]                     每个目录 12 字节:
            char name[4]                 ASCII, 最多 3 字符 + NUL ("SCR\\0")
            u32  entry_count             该目录下的文件数
            u32  table_offset            该目录条目表在文件中的绝对偏移

    条目表 (17 字节/条, 按名字升序排列, 引擎用二分查找):
            char name[9]                 ASCII, 最多 8 字符 + NUL
            u32  size                    数据长度
            u32  offset                  数据在文件中的绝对偏移

    数据区: 各条目数据紧跟在所有条目表之后, 无对齐填充.

加密:
    目录名为 "SCR" (脚本) 的数据在写入前做了逐字节循环右移 2 位 (ROR 2)。
    引擎读取后 (0x00404F25) 调用 sub_42C820(..., 2) 做 ROR 2 还原, 因此:
        解包: plain = ROR2(stored)
        封包: stored = ROL2(plain)
    OGG/WIP/MSK/ANM/TBL 等目录的数据是明文 (实测 OggS / WIPF 魔数可读).

压缩:
    本作 Rio.arc 的 122 个脚本熵值 2.2~5.9, 且解密后可直接读出日文与 ASCII
    标识符, 没有压缩层。工具仍保留 zlib 自动检测: 解密后若数据以合法 zlib
    头开始且能完整 inflate, 则解包阶段解压并在清单中记录, 封包阶段重新压缩。

=====================================================================
用法
=====================================================================
    python arc_tool.py list   Rio.arc
    python arc_tool.py unpack Rio.arc -o Rio_unpacked
    python arc_tool.py pack   Rio_unpacked -o Rio_new.arc
    python arc_tool.py verify Rio.arc

解包输出: <outdir>/<目录名>/<条目名><扩展名>, 以及 _arc_manifest.json
(记录目录名/编码方式/压缩方式, 供 pack 精确还原)。
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib

MANIFEST = "_arc_manifest.json"

# 目录 -> (解包扩展名, 是否做 ROR2)
DIR_INFO = {
    "SCR": (".scr", True),
    "OGG": (".ogg", False),
    "WIP": (".wip", False),
    "MSK": (".msk", False),
    "ANM": (".anm", False),
    "TBL": (".tbl", False),
}

ZLIB_HEADS = {b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"}

DIR_HDR = 12          # sizeof dir entry
ENT_HDR = 17          # sizeof file entry


class ArcError(Exception):
    pass


# --------------------------------------------------------------------------
# 编解码
# --------------------------------------------------------------------------
def ror2(data: bytes) -> bytes:
    """解密: 逐字节循环右移 2 位。"""
    return bytes(((b >> 2) | ((b << 6) & 0xFF)) for b in data)


def rol2(data: bytes) -> bytes:
    """加密: 逐字节循环左移 2 位 (ror2 的逆)。"""
    return bytes((((b << 2) & 0xFF) | (b >> 6)) for b in data)


def try_inflate(data: bytes):
    """若 data 是完整 zlib 流则返回解压结果, 否则 None。"""
    if len(data) < 16 or data[:2] not in ZLIB_HEADS:
        return None
    try:
        out = zlib.decompress(data)
    except zlib.error:
        return None
    if len(out) <= len(data):
        return None
    return out


def codec_for_dir(name: str, mode: str) -> str:
    """返回 'rot2' 或 'none'。"""
    if mode == "rot2":
        return "rot2"
    if mode == "none":
        return "none"
    # auto
    return "rot2" if name.upper() in ("SCR",) else "none"


# --------------------------------------------------------------------------
# 读
# --------------------------------------------------------------------------
def _name(raw: bytes, field: int) -> str:
    z = raw.find(b"\x00")
    if z < 0:
        raise ArcError("名称字段缺少 NUL 终止符: %r" % raw)
    try:
        s = raw[:z].decode("ascii")
    except UnicodeDecodeError:
        raise ArcError("非 ASCII 名称: %r" % raw)
    if not s:
        raise ArcError("空名称 (偏移数据损坏?)")
    if not s.isprintable():
        raise ArcError("名称含不可打印字符: %r" % s)
    return s


def parse_archive(path: str, codec_mode: str = "auto", inflate: bool = True):
    """解析封包, 返回 (dirs, meta)。

    dirs: list[dict(name, codec, entries=[dict(name,size,offset,data,comp)])]
    """
    with open(path, "rb") as f:
        buf = f.read()
    if len(buf) < 4 + DIR_HDR:
        raise ArcError("文件过小, 不是有效的 arc 封包")

    dir_count = struct.unpack_from("<I", buf, 0)[0]
    if not (1 <= dir_count <= 64):
        raise ArcError("dir_count=%d 不合理, 不是 Will Co. WARC arc 封包" % dir_count)
    if 4 + DIR_HDR * dir_count > len(buf):
        raise ArcError("目录表越界")

    dirs = []
    p = 4
    for _ in range(dir_count):
        raw_name = buf[p:p + 4]
        name = _name(raw_name, 4)
        count, table_off = struct.unpack_from("<II", buf, p + 4)
        p += DIR_HDR
        if count > 0x100000:
            raise ArcError("目录 %s 条目数异常: %d" % (name, count))
        if table_off + count * ENT_HDR > len(buf):
            raise ArcError("目录 %s 条目表越界 (off=0x%X, n=%d)" % (name, table_off, count))
        codec = codec_for_dir(name, codec_mode)
        entries = []
        for i in range(count):
            q = table_off + i * ENT_HDR
            ename = _name(buf[q:q + 9], 9)
            size, off = struct.unpack_from("<II", buf, q + 9)
            if off + size > len(buf):
                raise ArcError("条目 %s 数据越界 (off=0x%X, size=0x%X)" % (ename, off, size))
            raw = buf[off:off + size]
            plain = ror2(raw) if codec == "rot2" else raw
            comp = "none"
            if inflate:
                d = try_inflate(plain)
                if d is not None:
                    plain = d
                    comp = "zlib"
            entries.append({"name": ename, "size": size, "offset": off,
                            "data": plain, "comp": comp})
        dirs.append({"name": name, "codec": codec, "entries": entries})
    return dirs, {"path": path, "size": len(buf)}


# --------------------------------------------------------------------------
# 写
# --------------------------------------------------------------------------
def _fixed(s: str, field: int, what: str) -> bytes:
    try:
        b = s.encode("ascii")
    except UnicodeEncodeError:
        raise ArcError("%s 名称必须是 ASCII: %r" % (what, s))
    if b"\x00" in b:
        raise ArcError("%s 名称不能含 NUL: %r" % (what, s))
    if len(b) > field - 1:
        raise ArcError("%s 名称过长 (最多 %d 字符): %r" % (what, field - 1, s))
    return b + b"\x00" * (field - len(b))


def serialize_archive(dirs):
    """把 dirs 组装成字节串。返回 (bytes, layout)。"""
    if not dirs:
        raise ArcError("没有可封装的目录")
    if len(dirs) > 64:
        raise ArcError("目录过多")

    # 计算目录表位置
    table_start = 4 + DIR_HDR * len(dirs)
    table_offs = []
    cur = table_start
    for d in dirs:
        table_offs.append(cur)
        cur += ENT_HDR * len(d["entries"])
    data_start = cur

    # 先编码所有数据, 得到最终大小
    blobs = []
    for d in dirs:
        blist = []
        for e in d["entries"]:
            data = e["data"]
            if e.get("comp", "none") == "zlib":
                data = zlib.compress(data, 9)
            if d["codec"] == "rot2":
                data = rol2(data)
            blist.append(data)
        blobs.append(blist)

    out = bytearray(struct.pack("<I", len(dirs)))
    for d, toff in zip(dirs, table_offs):
        out += _fixed(d["name"], 4, "目录")
        out += struct.pack("<II", len(d["entries"]), toff)

    layout = []
    off = data_start
    for d, blist in zip(dirs, blobs):
        for e, blob in zip(d["entries"], blist):
            out += _fixed(e["name"], 9, "条目")
            out += struct.pack("<II", len(blob), off)
            layout.append((d["name"], e["name"], off, len(blob)))
            off += len(blob)
    for blist in blobs:
        for blob in blist:
            out += blob
    return bytes(out), layout


# --------------------------------------------------------------------------
# 命令
# --------------------------------------------------------------------------
def cmd_list(args):
    dirs, meta = parse_archive(args.archive, args.codec, inflate=False)
    total = 0
    print("封包: %s (%d 字节)" % (meta["path"], meta["size"]))
    for d in dirs:
        print("  目录 %-4s  条目 %4d  编码 %s" % (d["name"], len(d["entries"]), d["codec"]))
        for e in d["entries"]:
            total += 1
            print("    %-9s size=0x%06X off=0x%06X" % (e["name"], e["size"], e["offset"]))
    print("合计 %d 个条目" % total)


def cmd_unpack(args):
    dirs, meta = parse_archive(args.archive, args.codec, inflate=(args.compress != "none"))
    outdir = args.out or os.path.splitext(args.archive)[0] + "_unpacked"
    if os.path.exists(outdir) and not args.force:
        raise ArcError("输出目录已存在: %s (用 --force 覆盖)" % outdir)
    os.makedirs(outdir, exist_ok=True)

    manifest = {"tool": "arc_tool.py", "source": os.path.abspath(args.archive),
                "format": "Will Co. WARC arc (dir table + 17-byte entries)", "dirs": []}
    nfiles = 0
    nbytes = 0
    nzlib = 0
    for d in dirs:
        sub = os.path.join(outdir, d["name"])
        os.makedirs(sub, exist_ok=True)
        ext = DIR_INFO.get(d["name"].upper(), ("", False))[0]
        md = {"name": d["name"], "codec": d["codec"], "entries": []}
        for e in d["entries"]:
            fn = e["name"] + ext
            with open(os.path.join(sub, fn), "wb") as f:
                f.write(e["data"])
            nfiles += 1
            nbytes += len(e["data"])
            if e["comp"] == "zlib":
                nzlib += 1
            md["entries"].append({"name": e["name"], "file": "%s/%s" % (d["name"], fn),
                                  "size": len(e["data"]), "compression": e["comp"]})
        manifest["dirs"].append(md)

    with open(os.path.join(outdir, MANIFEST), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print("解包完成: %s" % outdir)
    print("  条目 %d 个, 解出 %d 字节" % (nfiles, nbytes))
    if nzlib:
        print("  zlib 压缩条目: %d 个 (已自动解压)" % nzlib)
    else:
        print("  压缩: 未检测到 (全部原样保存)")
    # 自检: 内存中重组, 与源文件逐字节比较
    try:
        rebuilt, _ = serialize_archive(dirs)
        with open(args.archive, "rb") as f:
            src = f.read()
        if rebuilt == src:
            print("  自检: 重组结果与源封包逐字节一致 (sha256=%s)"
                  % hashlib.sha256(src).hexdigest()[:16])
        else:
            print("  自检: 警告! 重组结果与源封包不一致 (压缩层无法保证位级还原)")
    except ArcError as e:
        print("  自检跳过: %s" % e)


def _load_manifest(indir):
    p = os.path.join(indir, MANIFEST)
    if not os.path.isfile(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_pack(args):
    indir = args.source
    if not os.path.isdir(indir):
        raise ArcError("输入不是目录: %s" % indir)
    manifest = _load_manifest(indir)
    dirs = []
    if manifest:
        for md in manifest["dirs"]:
            entries = []
            for me in md["entries"]:
                fp = os.path.join(indir, me["file"].replace("/", os.sep))
                if not os.path.isfile(fp):
                    raise ArcError("缺少文件: %s" % fp)
                with open(fp, "rb") as f:
                    data = f.read()
                entries.append({"name": me["name"], "data": data,
                                "comp": me.get("compression", "none")})
            entries.sort(key=lambda x: x["name"].upper())
            dirs.append({"name": md["name"], "codec": md.get("codec", "auto"), "entries": entries})
    else:
        # 从目录结构推断；也支持“平铺目录 + --dir”的情况（如 assembler.py 直接产出的 *.scr）
        subs = [x for x in sorted(os.listdir(indir))
                if os.path.isdir(os.path.join(indir, x))]
        flat = not subs
        if flat:
            subs = [args.dir]
        for dn in subs:
            sub = os.path.join(indir, dn)
            is_flat = flat or not os.path.isdir(sub)
            if is_flat:
                sub = indir
            entries = []
            for fn in sorted(os.listdir(sub), key=str.upper):
                fp = os.path.join(sub, fn)
                if not os.path.isfile(fp):
                    continue
                if is_flat and not fn.lower().endswith(".scr"):
                    continue
                stem, ext = os.path.splitext(fn)
                name = stem if ext else fn
                with open(fp, "rb") as f:
                    entries.append({"name": name, "data": f.read(), "comp": "none"})
            entries.sort(key=lambda x: x["name"].upper())
            dirs.append({"name": dn, "codec": codec_for_dir(dn, args.codec), "entries": entries})

    # 校验名称长度/重复
    for d in dirs:
        if len(d["entries"]) == 0:
            raise ArcError("目录 %s 没有文件" % d["name"])
        names = [e["name"].upper() for e in d["entries"]]
        if len(set(names)) != len(names):
            raise ArcError("目录 %s 存在重名条目" % d["name"])
        _fixed(d["name"], 4, "目录")
        for e in d["entries"]:
            _fixed(e["name"], 9, "条目")

    blob, layout = serialize_archive(dirs)
    outp = args.out or (os.path.basename(os.path.normpath(indir)) + ".arc")
    if os.path.exists(outp) and not args.force:
        raise ArcError("输出已存在: %s (用 --force 覆盖)" % outp)
    with open(outp, "wb") as f:
        f.write(blob)
    print("封包完成: %s (%d 字节)" % (outp, len(blob)))
    for dn, en, off, sz in layout:
        print("  %-4s %-9s off=0x%06X size=0x%06X" % (dn, en, off, sz))
    print("  sha256=%s" % hashlib.sha256(blob).hexdigest())


def cmd_verify(args):
    dirs, meta = parse_archive(args.archive, args.codec)
    blob, _ = serialize_archive(dirs)
    with open(args.archive, "rb") as f:
        src = f.read()
    ok = blob == src
    print("源封包   sha256=%s" % hashlib.sha256(src).hexdigest())
    print("重组封包 sha256=%s" % hashlib.sha256(blob).hexdigest())
    print("结果: %s" % ("逐字节一致" if ok else "不一致!"))
    if not ok:
        for i, (a, b) in enumerate(zip(src, blob)):
            if a != b:
                print("  首个差异偏移: 0x%X (源 0x%02X, 重组 0x%02X)" % (i, a, b))
                break
        sys.exit(1)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Will Co. (WARC) / Rio.arc 封包解包工具 (自动解密 ROR2, 可选 zlib 自动解压)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="列出封包内容")
    p.add_argument("archive")
    p.add_argument("--codec", choices=["auto", "rot2", "none"], default="auto")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("unpack", help="解包")
    p.add_argument("archive")
    p.add_argument("-o", "--out")
    p.add_argument("--codec", choices=["auto", "rot2", "none"], default="auto")
    p.add_argument("--compress", choices=["auto", "none"], default="auto",
                   help="auto: 检测 zlib 并解压; none: 原样保存")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("pack", help="封包")
    p.add_argument("source")
    p.add_argument("-o", "--out")
    p.add_argument("--codec", choices=["auto", "rot2", "none"], default="auto")
    p.add_argument("--dir", default="SCR", help="无子目录时的默认目录名")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("verify", help="解包->重组并逐字节校验")
    p.add_argument("archive")
    p.add_argument("--codec", choices=["auto", "rot2", "none"], default="auto")
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    try:
        args.func(args)
    except ArcError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
