#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_event_names.py - 同步 MIBOUJIN.EXE 内置的 13 条章节名（「イベント」/回想界面用）

为什么需要：
  EXE 的 .data 里硬编码了 13 条章节名（对应 .table 第 58-99 项中的 13 条），
  回想界面用它判断每个回想项是否可用：
      0x406F58  遍历这 13 条
        -> 0x416FBC(name)  调 0x416F64：在 SCB 字符串表里按名字逐字节查找
           -> 返回 block 索引，找不到返回 -1
           -> 找到后查 obj+0xA654[index] 的解锁标志
        -> 找不到就把菜单项 [item+0x44E] 置 0（禁用，鼠标无反应）
  所以只要改了 .table 的章节名，就必须把 EXE 里这 13 条改成同样的字节。

用法：
    python patch_event_names.py <EXE> --scb <新 MIBOUJIN.SCB> --jp <原版 MIBOUJIN.SCB.JP>
                                  [--out <输出 EXE>] [--dry-run]

行为：
  - 按 .table 索引一一对应（第 i 项对第 i 项），要求新旧 SCB 的块数量与顺序一致；
  - 优先原地替换（新串不长于原串时，不移动任何数据，diff 最小）；
  - 若个别新串更长，则把 13 条整体重新紧凑排布在原区域内，并更新指针表
    （区域总长度够即可）；总长度不够则报错退出，不写文件；
  - 默认原地修改，先备份 <EXE>.bak；--out 写到副本；
  - 已经是新名字时直接返回 0（可反复执行）。

限制：
  - 只适用于同一版本 EXE（该 13 条字符串与指针表必须还能被定位到）；
  - SCB 必须保持 100 个块、索引顺序不变；
  - 若新名字长到 13 条合计超过原区域 453 字节，本脚本不处理。
"""

import argparse
import shutil
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scb_format


def pe_image(data: bytes):
    """返回 (image_base, [(rva, vsize, raw_ptr, raw_size)])。"""
    if data[:2] != b"MZ":
        raise SystemExit("不是 PE 文件")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("不是 PE 文件")
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    sec = opt + opt_size
    sections = []
    for i in range(nsec):
        off = sec + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<4I", data, off + 8)
        sections.append((vaddr, vsize, rawptr, rawsize))
    return image_base, sections


def off_to_va(image_base, sections, off):
    for rva, vsize, ptr, size in sections:
        if ptr <= off < ptr + size:
            return image_base + rva + (off - ptr)
    raise SystemExit("偏移 0x%X 不在任何节内" % off)


def table_names(scb_path: Path):
    scb = scb_format.ScbFile(scb_path.read_bytes(), "cp932")
    return [scb_format.decode_text(e["payload"], "cp932") for e in scb.entries]


def find_cstr(data: bytes, text: bytes):
    """所有「前面是 0x00（或文件头）、内容等于 text、后面是 0x00」的位置。"""
    out = []
    start = 0
    while True:
        i = data.find(text, start)
        if i < 0:
            break
        end = i + len(text)
        if (i == 0 or data[i - 1] == 0) and (end == len(data) or data[end] == 0):
            out.append(i)
        start = i + 1
    return out


def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description="同步 EXE 内置的 13 条章节名")
    ap.add_argument("exe")
    ap.add_argument("--scb", required=True, help="新的 MIBOUJIN.SCB（中文）")
    ap.add_argument("--jp", required=True, help="原版 MIBOUJIN.SCB.JP")
    ap.add_argument("--out", help="输出 EXE（默认原地修改，先备份 .bak）")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    exe = Path(args.exe)
    data = bytearray(exe.read_bytes())
    image_base, sections = pe_image(bytes(data))
    jp = table_names(Path(args.jp))
    cn = table_names(Path(args.scb))
    if len(jp) != len(cn):
        raise SystemExit("SCB 条目数不一致：%d vs %d" % (len(jp), len(cn)))

    def collect(names):
        got = []
        for i in range(58, 100):
            for off in find_cstr(bytes(data), names[i].encode("cp932")):
                got.append((off, i))
        got.sort()
        return got

    hits = collect(jp)
    if not hits:
        if len(collect(cn)) == 13:
            print("这 13 条已经是新名字，无需修改")
            return 0
        raise SystemExit("EXE 里没有找到内置章节名，版本不符或已被改坏")
    print("定位到 %d 条内置章节名" % len(hits))

    # 指针表：连续 13 个 dword，正好指向这 13 条
    first_va = off_to_va(image_base, sections, hits[0][0])
    needle = struct.pack("<I", first_va)
    want = [off_to_va(image_base, sections, off) for off, _ in hits]
    ptbl = None
    start = 0
    while True:
        p = data.find(needle, start)
        if p < 0:
            break
        if p + 4 * len(hits) <= len(data):
            vals = list(struct.unpack_from("<%dI" % len(hits), data, p))
            if vals == want:
                ptbl = p
                break
        start = p + 1
    if ptbl is None:
        raise SystemExit("没找到 13 条的指针表，无法安全改写（版本不符？）")
    print("指针表 @0x%X" % ptbl)

    olds = [bytes(data[off:data.index(0, off)]) for off, _ in hits]
    news = [cn[i].encode("cp932") for _, i in hits]
    bounds = [off for off, _ in hits] + [hits[-1][0] + len(olds[-1]) + 1]
    slots = [bounds[k + 1] - bounds[k] - 1 for k in range(len(hits))]  # 不含结尾 0x00
    region_start, region_end = bounds[0], bounds[-1]
    need = sum(len(n) + 1 for n in news)
    capacity = region_end - region_start
    print("新串合计 %d 字节，原区域 %d 字节" % (need, capacity))
    if need > capacity:
        raise SystemExit("新名字太长，区域放不下（%d > %d），需要改指针到别处，本脚本不处理"
                         % (need, capacity))

    changed = []
    if all(len(n) <= s for n, s in zip(news, slots)):
        for k, ((off, idx), old, new) in enumerate(zip(hits, olds, news)):
            if new == old:
                continue
            data[off:off + slots[k] + 1] = new + b"\x00" * (slots[k] + 1 - len(new))
            changed.append((idx, off, old, new))
    else:
        print("有串变长，改为整体重排 + 更新指针表")
        pos = region_start
        for k, ((off, idx), new) in enumerate(zip(hits, news)):
            data[pos:pos + len(new)] = new
            data[pos + len(new)] = 0
            struct.pack_into("<I", data, ptbl + 4 * k, off_to_va(image_base, sections, pos))
            if new != olds[k]:
                changed.append((idx, pos, olds[k], new))
            pos += len(new) + 1
        data[pos:region_end] = b"\x00" * (region_end - pos)

    for idx, off, old, new in changed:
        print("%02d @0x%X %s -> %s" % (idx, off,
                                       old.decode("cp932", "backslashreplace"),
                                       new.decode("cp932", "backslashreplace")))
    print("改动 %d 条" % len(changed))

    if args.dry_run or not changed:
        return 0
    if args.out:
        Path(args.out).write_bytes(bytes(data))
        print("写入 %s" % args.out)
    else:
        bak = exe.with_name(exe.name + ".bak")
        if not bak.exists():
            shutil.copy2(exe, bak)
            print("备份 %s" % bak)
        exe.write_bytes(bytes(data))
        print("写入 %s" % exe)
    return 0


if __name__ == "__main__":
    sys.exit(main())
