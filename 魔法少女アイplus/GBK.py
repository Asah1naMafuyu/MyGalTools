"""GBK.py — 让游戏用「黑体 + GBK 字符集」渲染文本（只改 exe）。

用法：
    python GBK.py --exe <aiplusdvd.exe 路径>
    python GBK.py --exe <路径> --restore

修改内容：
  1. CreateFontA 的 charset：0x80 (SHIFTJIS) -> 0x86 (GB2312)；
  2. exe 内默认字体名「ＭＳ ゴシック」(CP932) -> 「黑体」(GBK) + 00 填充；
  3. 字体选择对话框的 LOGFONT.lfCharSet：0x80 -> 0x86，字符集下拉
     默认变成「中文」；
  4. 退出确认「アプリケーションを終了します、宜しいですか？」-> 
     「确定要退出游戏吗？」(GBK)，多余字节补 00；
  5. 启动时把活动字体指向 exe 内默认字体（黑体），不再被 system.dat
     里的「ＭＳ ゴシック」覆盖；字体对话框里选择的字体在当前运行中
     仍然生效，重启后回到黑体默认值。

不修改 system.dat。首次运行会自动备份为 <exe>.bak。
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys

# CreateFontA 的 charset 立即数（文件偏移；0x16766 是 push 0x80 的 0x68 前缀）
CHARSET_OFF = 0x16767
OLD_CHARSET = 0x80
NEW_CHARSET = 0x86

# 默认字体名「ＭＳ ゴシック」的 CP932 字节
FONT_OLD = bytes.fromhex("82 6C 82 72 20 83 53 83 56 83 62 83 4E")
# 「黑体」的 GBK 字节 + 00 填充（与原字段等长，12 字节）
FONT_NEW = "黑体".encode("gbk") + b"\x00" * (len(FONT_OLD) - len("黑体".encode("gbk")))

# 字体选择对话框：mov byte ptr [esp+0x57], 0x80
CHOOSE_OLD = bytes.fromhex("C6 44 24 57 80")
CHOOSE_NEW = bytes.fromhex("C6 44 24 57 86")

# 退出确认（CP932）
EXIT_OLD = "アプリケーションを終了します、宜しいですか？".encode("cp932")
EXIT_NEW = "确定要退出游戏吗？".encode("gbk")

# 启动时把活动字体缓冲区 0x92BC38 的来源从 system.dat 的字体名
# (0x44C161) 改成 exe 内默认字体名 (0x43C644)，默认即黑体。
FONT_SRC_OLD = bytes.fromhex("8A 88 61 C1 44 00")
FONT_SRC_NEW = bytes.fromhex("8A 88 44 C6 43 00")


def backup(path: str) -> str:
    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
        print("已备份：%s" % bak)
    return bak


def patch_exe(path: str) -> int:
    data = bytearray(open(path, "rb").read())
    changed = []

    # 1. CreateFontA charset
    if data[CHARSET_OFF] == NEW_CHARSET:
        print("  [跳过] CreateFontA charset 已是 0x86")
    elif data[CHARSET_OFF] == OLD_CHARSET:
        data[CHARSET_OFF] = NEW_CHARSET
        changed.append("CreateFontA charset 0x80 -> 0x86")
    else:
        raise ValueError("0x%X 处不是 0x80/0x86（实际 0x%02X）"
                         % (CHARSET_OFF, data[CHARSET_OFF]))

    # 2. 默认字体名
    i = data.find(FONT_OLD)
    if i >= 0:
        data[i:i + len(FONT_OLD)] = FONT_NEW
        changed.append("默认字体 ＭＳ ゴシック -> 黑体")
    elif data.find(FONT_NEW) >= 0:
        print("  [跳过] 默认字体已是黑体")
    else:
        raise ValueError("找不到默认字体字符串 ＭＳ ゴシック")

    # 3. 字体选择对话框 charset
    i = data.find(CHOOSE_OLD)
    if i >= 0:
        data[i:i + len(CHOOSE_OLD)] = CHOOSE_NEW
        changed.append("字体对话框 charset 0x80 -> 0x86")
    elif data.find(CHOOSE_NEW) >= 0:
        print("  [跳过] 字体对话框 charset 已是 0x86")
    else:
        raise ValueError("找不到字体对话框 charset 初始化代码")

    # 4. 退出确认文本
    i = data.find(EXIT_OLD)
    if i >= 0:
        data[i:i + len(EXIT_OLD)] = EXIT_NEW + b"\x00" * (len(EXIT_OLD) - len(EXIT_NEW))
        changed.append("退出确认文本 -> 确定要退出游戏吗？")
    elif data.find(EXIT_NEW) >= 0:
        print("  [跳过] 退出确认文本已是中文")
    else:
        raise ValueError("找不到退出确认文本")

    # 5. 启动时活动字体来源：system.dat 字体名 -> exe 默认字体名
    i = data.find(FONT_SRC_OLD)
    if i >= 0:
        data[i:i + len(FONT_SRC_OLD)] = FONT_SRC_NEW
        changed.append("启动字体来源 system.dat -> exe 默认黑体")
    elif data.find(FONT_SRC_NEW) >= 0:
        print("  [跳过] 启动字体来源已是 exe 默认黑体")
    else:
        raise ValueError("找不到启动字体复制代码")

    if not changed:
        print("所有补丁均已存在，无需修改：%s" % path)
        return 0

    open(path, "wb").write(data)
    print("已修改 %s：" % path)
    for c in changed:
        print("  - " + c)
    return len(changed)


def restore(path: str) -> int:
    bak = path + ".bak"
    if not os.path.exists(bak):
        print("找不到备份：%s" % bak, file=sys.stderr)
        return 2
    shutil.copy2(bak, path)
    print("已还原：%s" % path)
    return 0


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="黑体 + GBK 字体补丁（只改 exe）")
    ap.add_argument("--exe", required=True, help="要修改的 aiplusdvd.exe 路径")
    ap.add_argument("--restore", action="store_true", help="从 .bak 还原")
    args = ap.parse_args(argv)

    if not os.path.exists(args.exe):
        print("找不到 exe：%s" % args.exe, file=sys.stderr)
        return 2
    if args.restore:
        return restore(args.exe)
    backup(args.exe)
    try:
        patch_exe(args.exe)
    except ValueError as e:
        print("[失败] %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
