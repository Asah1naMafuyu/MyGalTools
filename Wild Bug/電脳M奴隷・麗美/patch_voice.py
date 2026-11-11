#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_voice.py -- 翻页不打断语音；只有“下一句语音开始时”才打断旧语音。

原理（来自 exe 伪代码）：

    sub_41A0F3  MESSAGE_WAVE 0x87 处理器
      └─ sub_410634(hWnd, 频道, 类型, 语音文件, 文本)
           ├─ sub_40CFCA / sub_40CEEB   开始播放语音（类型 3 / 类型 2）
           ├─ sub_4104FA                显示文本，等玩家点击翻页
           └─ sub_40CF6A / sub_40CE8B   文本读完 → 停止语音   ← 翻页就掐断

补丁做两件事：

1. 把“文本读完就停语音”的两处 call 改成 NOP —— 翻页不再打断语音；
2. 把“开始播放语音”的两处 call 重定向到 .text 末尾空白处的两段小代码，
   先调用 sub_40C243(类型) 停掉同类型的旧语音，再跳回原播放函数 ——
   这样只有下一条语音开始播放时，才会打断上一条。

类型 2 / 类型 3 分别处理，不会误停 BGM（BGM 是类型 1）。

改动点（共 5 处）：
    0x410708  call sub_40CE8B  -> NOP*5
    0x410713  call sub_40CF6A  -> NOP*5
    0x4106BE  call sub_40CFCA  -> call stub_type3(0x449380)
    0x4106D8  call sub_40CEEB  -> call stub_type2(0x449390)
    0x449380  .text 末尾 align 填充区 -> 两段 15 字节 stub

用法：
    python patch_voice.py            # 打补丁
    python patch_voice.py --check    # 检查
    python patch_voice.py --restore  # 还原
"""
import os
import struct
import sys

DEFAULT_EXE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exe", "REIMI.EXE")

VA_DELTA = 0x400A00          # 文件偏移 = VA - 0x400A00


def va2off(va):
    return va - VA_DELTA


VBASE = 0x400000
STOP_ALL = 0x40C243          # sub_40C243(type) 停止某一类型的全部声道
PLAY_T3 = 0x40CFCA           # sub_40CFCA(hWnd, name, 0) 播放类型 3
PLAY_T2 = 0x40CEEB           # sub_40CEEB(hWnd, name, 0) 播放类型 2
CALL_STOP_T2 = 0x410708      # call sub_40CE8B  停 type2
CALL_STOP_T3 = 0x410713      # call sub_40CF6A  停 type3
CALL_PLAY_T3 = 0x4106BE      # call sub_40CFCA
CALL_PLAY_T2 = 0x4106D8      # call sub_40CEEB
STUB3_VA = 0x449380          # .text 末尾 align 100h 的零填充区
STUB2_VA = 0x449390


def make_stub(stub_va, type_id, play_va):
    """push type; call stop_all; add esp,4; jmp play"""
    code = bytearray([0x6A, type_id])
    rel = STOP_ALL - (stub_va + len(code) + 5)
    code += b"\xE8" + struct.pack("<i", rel)
    code += b"\x83\xC4\x04"
    rel = play_va - (stub_va + len(code) + 5)
    code += b"\xE9" + struct.pack("<i", rel)
    assert len(code) == 15, len(code)
    return bytes(code)


def call_bytes(call_va, target_va):
    return b"\xE8" + struct.pack("<i", target_va - (call_va + 5))


STUB3 = make_stub(STUB3_VA, 3, PLAY_T3)
STUB2 = make_stub(STUB2_VA, 2, PLAY_T2)
CAVE = STUB3 + b"\x90" + STUB2 + b"\x90"          # 32 字节

NOP5 = b"\x90" * 5

# (名称, 文件偏移, 原始字节, 补丁后字节, 说明)
PATCHES = [
    ("stop.t2",   va2off(CALL_STOP_T2), b"\xE8\x7E\xC7\xFF\xFF", NOP5,
     "文本读完不再停 type2"),
    ("stop.t3",   va2off(CALL_STOP_T3), b"\xE8\x52\xC8\xFF\xFF", NOP5,
     "文本读完不再停 type3"),
    ("play.t3",   va2off(CALL_PLAY_T3), b"\xE8\x07\xC9\xFF\xFF",
     call_bytes(CALL_PLAY_T3, STUB3_VA), "播放 type3 前先停旧的 type3"),
    ("play.t2",   va2off(CALL_PLAY_T2), b"\xE8\x0E\xC8\xFF\xFF",
     call_bytes(CALL_PLAY_T2, STUB2_VA), "播放 type2 前先停旧的 type2"),
    ("stub.cave", va2off(STUB3_VA), b"\x00" * 32, CAVE,
     "在 .text 末尾空白处放置两段 stub"),
]

# 上下文校验（跳过被改写的 call 字节）
CONTEXT_SEGMENTS = [
    (0xFD05, bytes.fromhex("ff 75 fc")),          # push [ebp-4]
    (0xFD0D, bytes.fromhex("59 eb 09 ff 75 fc")),  # pop ecx ; jmp ; push [ebp-4]
    (0xFD18, bytes.fromhex("59")),                 # pop ecx
    (0xFCB6, bytes.fromhex("6a 00 ff 75 14 ff 75 08")),  # push 0 / push name / push hWnd
    (0xFCD0, bytes.fromhex("6a 00 ff 75 14 ff 75 08")),
    (va2off(STUB3_VA) + 32, bytes.fromhex("00" * 16)),   # 空白区后面的填充仍是 0
]


def check_context(d):
    for off, want in CONTEXT_SEGMENTS:
        if d[off:off + len(want)] != want:
            return False, off, d[off:off + len(want)]
    return True, 0, b""


def main(argv):
    exe = DEFAULT_EXE
    args = [a for a in argv if not a.startswith("--")]
    if args:
        exe = args[0]
    do_restore = "--restore" in argv
    do_check = "--check" in argv

    if not os.path.exists(exe):
        print("找不到:", exe)
        return 1
    d = bytearray(open(exe, "rb").read())
    if d[:2] != b"MZ":
        print("不是 PE 文件:", exe)
        return 1

    ok, bad_off, bad = check_context(d)
    if not ok:
        print("!! 上下文不匹配，可能不是这个版本（0x%X: %s）" % (bad_off, bad.hex(" ")))
        return 1

    if do_check:
        n = 0
        for name, off, orig, new, _desc in PATCHES:
            cur = d[off:off + len(orig)]
            if cur == new:
                print("%-10s @0x%X  patched" % (name, off))
                n += 1
            elif cur == orig:
                print("%-10s @0x%X  original" % (name, off))
            else:
                print("%-10s @0x%X  unknown (%s)" % (name, off, cur.hex(" ")))
        print("%d/%d patched" % (n, len(PATCHES)))
        return 0

    changed = 0
    for name, off, orig, new, desc in PATCHES:
        cur = d[off:off + len(orig)]
        if do_restore:
            if cur == orig:
                continue
            if cur != new:
                print("!! %s 处字节异常: %s" % (name, cur.hex(" ")))
                return 1
            d[off:off + len(orig)] = orig
            print("%-10s 还原 @0x%X" % (name, off))
        else:
            if cur == new:
                continue
            if cur != orig:
                print("!! %s 处字节异常: %s" % (name, cur.hex(" ")))
                return 1
            d[off:off + len(orig)] = new
            print("%-10s -> @0x%X  %s" % (name, off, desc))
        changed += 1

    if not changed:
        print("无需修改。")
        return 0
    open(exe, "wb").write(d)
    print("\n完成：%s" % ("已还原" if do_restore else "翻页不再打断语音，下一条语音开始时才打断"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
