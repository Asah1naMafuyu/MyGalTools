#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GBK.py - 把 女教師・恥辱の旋律 (Chijyoku.exe) 改成 GBK(CP936) 编码版本。

解决的问题
==========
1. 字体创建 (sub_42C660 -> CreateFontIndirectA)
   原代码把 lfCharSet 设为 0x80 (SHIFTJIS_CHARSET)，GDI 因此按 CP932 解释
   文本字节。改成 0x86 (GB2312_CHARSET) 后，GDI 按 CP936/GBK 解释。

2. 字体枚举 (sub_42C990 -> EnumFontFamiliesExA)
   同样把 lfCharSet 从 0x80 改成 0x86，设置界面的字体列表才会列出中文字体。

3. 字体枚举回调 (Proc, 0x42C940)
   原逻辑只接受“固定宽度 (lfPitchAndFamily & 1) + TrueType”的字体；
   宋体/黑体等中文字体是变宽字体，会被过滤掉。补丁去掉固定宽度过滤，
   保留 TrueType 过滤。

补丁点（均为 VA，镜像基址 0x400000，.text 段 RVA==文件偏移）
============================================================
  0x0042C6AC  81 E2 80 00 00 00   and edx,80h
              -> BA 86 00 00 00 90  mov edx,86h ; nop
  0x0042C9CC  25 80 00 00 00      and eax,80h
              -> B8 86 00 00 00     mov eax,86h
  0x0042C948  74 2F               jz  (跳过非固定宽度字体)
              -> 90 90              nop nop

注意
====
* 补丁后的 exe 适用于把脚本编码换成 GBK/CP936 的中文版。
* 多字节字符判定使用 CRT 的 _ismbclegal/_ismbblead，其代码页来自
  GetACP()；在简体中文 Windows 上为 936，与 GBK 文本一致。
  若用日文区域模拟(Locale Emulator)运行，则需要保持系统代码页为 936。
* 建议在游戏设置里把字体选为“宋体/黑体/微软雅黑”等中文字体。

用法
====
    python GBK.py                      # 默认处理 exe\\Chijyoku.exe
    python GBK.py -i Chijyoku.exe -o Chijyoku.gbk.exe
"""

import argparse
import os
import struct
import sys

IMAGE_BASE = 0x400000

# (VA, 原始字节, 新字节, 说明)
PATCHES = [
    (0x0042C6AC, bytes.fromhex("81 E2 80 00 00 00"),
     bytes.fromhex("BA 86 00 00 00 90"),
     "CreateFontIndirectA: lfCharSet 0x80 -> 0x86 (GB2312)"),
    (0x0042C9CC, bytes.fromhex("25 80 00 00 00"),
     bytes.fromhex("B8 86 00 00 00"),
     "EnumFontFamiliesExA: lfCharSet 0x80 -> 0x86 (GB2312)"),
    (0x0042C948, bytes.fromhex("74 2F"),
     bytes.fromhex("90 90"),
     "字体枚举: 允许变宽 TrueType 字体 (宋体/黑体等)"),
]


class PeInfo:
    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("不是 PE 文件")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("PE 头损坏")
        self.nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt = e_lfanew + 24
        self.base = struct.unpack_from("<I", data, opt + 28)[0]
        sec = opt + struct.unpack_from("<H", data, e_lfanew + 20)[0]
        self.sections = []
        for _ in range(self.nsec):
            name = data[sec:sec + 8].rstrip(b"\x00").decode("latin1")
            vsize, va, rsize, roff = struct.unpack_from("<IIII", data, sec + 8)
            self.sections.append((name, va, vsize, roff, rsize))
            sec += 40

    def off(self, va):
        rva = va - self.base
        for _name, sva, vsize, roff, rsize in self.sections:
            if sva <= rva < sva + max(vsize, rsize):
                return roff + (rva - sva)
        raise ValueError("地址 0x%X 不在任何区段内" % va)


def apply_patches(data, patches, pe):
    buf = bytearray(data)
    for va, old, new, desc in patches:
        off = pe.off(va)
        if buf[off:off + len(old)] != old:
            raise ValueError("0x%08X 处字节不匹配 (期望 %s, 实际 %s)；"
                             "可能不是同一版本 exe"
                             % (va, old.hex(" "), buf[off:off + len(old)].hex(" ")))
        buf[off:off + len(new)] = new
        print("  [OK] 0x%08X  %s" % (va, desc))
    return bytes(buf)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Chijyoku.exe GBK 编码补丁")
    ap.add_argument("-i", "--input", default=None, help="原 exe")
    ap.add_argument("-o", "--out", default=None, help="输出 exe")
    args = ap.parse_args(argv)

    src = args.input
    if src is None:
        for cand in (os.path.join("exe", "Chijyoku.exe"), "Chijyoku.exe"):
            if os.path.isfile(cand):
                src = cand
                break
    if not src or not os.path.isfile(src):
        print("找不到输入 exe，请用 -i 指定", file=sys.stderr)
        return 1
    out = args.out or os.path.splitext(src)[0] + ".gbk.exe"

    data = open(src, "rb").read()
    pe = PeInfo(data)
    print("输入: %s (%d 字节, 基址 0x%X)" % (src, len(data), pe.base))
    try:
        patched = apply_patches(data, PATCHES, pe)
    except ValueError as e:
        print("错误: %s" % e, file=sys.stderr)
        return 1
    open(out, "wb").write(patched)
    print("输出: %s (%d 字节)" % (out, len(patched)))
    print("完成。请把游戏字体设为中文字体（宋体/黑体/微软雅黑），并用 GBK 编码的脚本。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
