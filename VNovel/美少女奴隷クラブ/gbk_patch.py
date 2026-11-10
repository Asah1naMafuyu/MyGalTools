#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
D_Club.exe 简体中文（GBK）补丁
==============================

把引擎的 GDI 字符集从 DEFAULT_CHARSET(1) 改成 GB2312_CHARSET(134 = 0x86)，
把默认字体从「ＭＳ 明朝」改成「黑体 / SimHei」，
把文本控制符号（● ▲ ■、全角空格）的硬编码 CP932 字节改成 GBK，
并把 exe 里的菜单/提示文本、鉴赏列表（.def）换成简体中文。

改动：

    1. 4 个 LOGFONT 初始化点（lfCharSet）
    2. 全局字体名字符串 ".data:0x456FC8"（4 处 CreateFont 共用同一个名字）
    3. 4 个文本控制符号常量：● ▲ ■ 与全角空格（引擎用 strcmp 判断它们，
       不改成 GBK 的话符号会被当成普通文字画出来，且不再停顿/清屏）
    4. 91 条菜单/提示文本（UI_TEXT 表），原位替换 + 00 填充
    5. --defs 时同步汉化 Bgm.def / Cg.def / Event.def 的显示名

语音不打断的补丁在 patch_voice.py，与本脚本独立。

用法：

    python gbk_patch.py D_Club.exe            # 生成同目录的 D_Club_GBK.exe
    python gbk_patch.py D_Club.exe --defs D_Club   # 同时汉化鉴赏列表
    python gbk_patch.py D_Club.exe --font 黑体 --charset 134
    python gbk_patch.py D_Club.exe --dry-run  # 只看会改哪些字节
    python gbk_patch.py D_Club.exe --check    # 检查是否已打补丁

说明：
* 86 与 134 是同一个值（0x86），Windows 头文件里叫 GB2312_CHARSET。
* 字体名默认写 ASCII "SimHei"（即黑体的英文名）：CreateFontIndirectA 按系统
  ANSI 代码页解释字节，ASCII 名字在任何代码页下都不会被误解；也可以写
  `--font 黑体`，脚本会按 GBK 编码写入（要求系统代码页是 936）。
* 字体名字段只有 9 字节可用，超长会拒绝。
* 默认输出新文件，不改原 exe；需要就地改请加 --inplace（会自动备份 .bak）。
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

VERSION = "1.0"

# ---------------------------------------------------------------------------
# 补丁点（文件偏移，已用反汇编逐条核对）
# ---------------------------------------------------------------------------

# `mov byte ptr [esp+XXh+lf.lfCharSet], 1` -> 改写立即数（每处都紧跟
# 11 字节后的 `mov [esp+..+lf.lfHeight], -26`，因此可交叉校验）
CHARSET_SITES = [
    (0x089B8, b"\xC6\x44\x24\x53\x01"),   # sub_409540  VA 0x4095B8
    (0x0AFC1, b"\xC6\x44\x24\x43\x01"),   # sub_40AB20  VA 0x40ABC1
    (0x0B283, b"\xC6\x44\x24\x43\x01"),   # sub_40AE00  VA 0x40AE83
    (0x0C587, b"\xC6\x44\x24\x4B\x01"),   # sub_40C140  VA 0x40C187
]

# 字体名："ＭＳ 明朝"(CP932) + NUL，后接两个 0 字节，再后面是别的数据
FONT_SITE = 0x0555C8
FONT_MAXLEN = 9          # 原有 9 字节，再加 3 字节的余量到下一个非零数据

# 文本控制符号：引擎用 `strcmp(当前字符, 常量)` 判断 ● ▲ ■ 和全角空格，
# 常量是 CP932 两字节。脚本改成 GBK 后字节不同，必须一起改，否则：
#   * ● ▲ ■ 被当普通文字画出来，且不再停顿 / 清屏（表现为文字一路播下去）
#   * 引擎补的全角空格缩进也会变成乱码
# 偏移为文件偏移，每处 2 字节（后跟 2 字节 0 填充）。
SYMBOL_SITES = [
    (0x0554AC, "\u3000"),   # 全角空格  sub_409D60 里用于缩进/替换
    (0x0555E0, "\u25a0"),   # ■  清屏 + 等待
    (0x055990, "\u25cf"),   # ●  停顿（不清屏）
    (0x055994, "\u25b2"),   # ▲  等待翻页
]

# 名称 -> 值
CHARSET_NAMES = {
    "ansi": 0,
    "default": 1,
    "shiftjis": 128,
    "sjis": 128,
    "86": 134,          # 0x86 的十进制写法，等同 gb2312
    "gb2312": 134,
    "gbk": 134,
    "gb18030": 134,
    "big5": 136,
}

CURRENT_FONT = "ＭＳ 明朝"

# ---------------------------------------------------------------------------
# exe 内的菜单 / 提示文本：CP932 -> 简体中文（GBK）
# 原位替换，剩余字节用 00 填充；译文长度必须放得下（脚本会校验）。
# ---------------------------------------------------------------------------

UI_TEXT = [
    # 标题菜单
    ("ゲームを始める", "开始游戏"),
    ("ロードする", "读取进度"),
    ("セーブする", "保存进度"),
    ("回想モード", "回想模式"),
    ("ゲームを終了する", "退出游戏"),
    ("ゲームを終了します", "正在退出游戏"),
    # 游戏内菜单
    ("文字を消す", "隐藏文字"),
    ("スキップ", "跳过"),
    ("環境設定", "环境设置"),
    ("タイトルに戻る", "返回标题"),
    ("タイトルに戻ります", "返回标题画面"),
    # 环境设置
    ("＜環境設定＞", "＜环境设置＞"),
    ("設定する項目を選択してください", "请选择要设置的项目"),
    ("テキスト表示スピード", "文字显示速度"),
    ("＜テキスト表示スピード＞", "＜文字显示速度＞"),
    ("テキスト表示のスピードを選択してください", "请选择文字显示速度"),
    ("１(低速)", "１(低速)"),
    ("３(中速)", "３(中速)"),
    ("５(高速)", "５(高速)"),
    ("音声", "语音"),
    ("＜音声＞", "＜语音＞"),
    ("音声のボリュームを選択してください", "请选择语音音量"),
    ("効果音", "音效"),
    ("＜効果音＞", "＜音效＞"),
    ("効果音のボリュームを選択してください", "请选择音效音量"),
    ("BGMのボリュームを選択してください", "请选择BGM音量"),
    ("＜BGM＞", "＜BGM＞"),
    # 只有空白/符号的行，内容不变，但必须换成 GBK 字节
    ("　" * 8, "　" * 8),        # 空标签占位（8 个全角空格）
    ("　" * 7, "　" * 7),        # 空标签占位（7 个全角空格）
    ("ＮＯ", "ＮＯ"),
    ("ＯＫ", "ＯＫ"),
    ("０(無音)", "０(静音)"),
    # 音量档位：原文带行尾全角空格，长度与 GBK 一致，只换编码
    ("５(大)　", "５(大)　"),
    ("３(中)　", "３(中)　"),
    ("１(小)　", "１(小)　"),
    # 文字速度档位：2、4 没有文字标签，只有数字+空白
    ("２ 　　 ", "２ 　　 "),
    ("４ 　　 ", "４ 　　 "),
    # 存档列表的日期格式：・ 在 GBK 里不存在，换成 ·（A1A4）
    ("%02d・----／--／--[--:--]", "%02d·----／--／--[--:--]"),
    ("%02d・%4d／%02d／%02d[%02d:%02d]", "%02d·%4d／%02d／%02d[%02d:%02d]"),
    # 读取 / 保存
    ("＜ロード＞", "＜读取＞"),
    ("＜セーブ＞", "＜保存＞"),
    ("データファイルを選択してください", "请选择存档文件"),
    ("以下のデータファイルをロードします", "将读取以下存档"),
    ("以下のデータファイルにセーブします", "将保存到以下存档"),
    ("以下のデータファイルに上書きセーブします", "将覆盖保存到以下存档"),
    # 回想 / 鉴赏
    ("＜回想モード＞", "＜回想模式＞"),
    ("CG鑑賞モード", "CG鉴赏模式"),
    ("BGM鑑賞モード", "BGM鉴赏模式"),
    ("イベント鑑賞モード", "事件鉴赏模式"),
    ("＜CG鑑賞モード＞", "＜CG鉴赏模式＞"),
    ("＜BGM鑑賞モード＞", "＜BGM鉴赏模式＞"),
    ("＜イベント鑑賞モード＞", "＜事件鉴赏模式＞"),
    ("キャラクターを選択してください", "请选择角色"),
    ("BGMを選択してください", "请选择BGM"),
    ("シチュエーションを選択してください", "请选择场景"),
    # 名字输入
    ("＜名前の入力＞", "＜名字输入＞"),
    ("名前を入力してください", "请输入名字"),
    ("＜名前の確認＞", "＜名字确认＞"),
    ("よろしいですか？", "可以吗？"),
    ("[カタカナ]", "[片假名]"),
    ("[ひらがな]", "[平假名]"),
    ("[キー入力]", "[键盘输入]"),
    ("[大隅□□□□□□]", "[大隅□□□□□□]"),
    ("[レイジ□□□□□]", "[雷吉□□□□□]"),
    ("レイジ・大隅", "雷吉·大隅"),
    # 错误提示
    ("シナリオが開けません", "无法打开剧本"),
    ("シナリオが指定されていません", "未指定剧本"),
    ("画面の設定をTrue Color(24ビット)以上に設定してください", "请将画面设置为真彩色(24位)以上"),
    ("画面がTrue Color(24ビット)以上に設定されていないとグラフィックが正しく表示されません。\nよろしいですか？",
     "画面未设置为真彩色(24位)以上时，图像将无法正确显示。\n可以吗？"),
    ("CD-ROMドライブにCDを入れてください", "请将CD放入CD-ROM光驱"),
    ("プライマリ・バッファのフォーマット設定に失敗", "主缓冲区格式设置失败"),
    ("ゲームデータのロードに失敗しました", "游戏数据读取失败"),
    ("ゲームデータのセーブに失敗しました", "游戏数据保存失败"),
    ("がローカル変数として宣言されました", "被声明为局部变量"),
    ("#IFの後にGO,THEN,JUMPがありません", "#IF 后缺少 GO,THEN,JUMP"),
    ("#SELECTの後にGO,THEN,JUMPがありません", "#SELECT 后缺少 GO,THEN,JUMP"),
    ("変数名がありません。", "缺少变量名。"),
    ("#GOの指定に誤りがあります", "#GO 指定有误"),
    ("文法エラー：#LET 変数名 = 数式", "语法错误：#LET 变量名 = 表达式"),
    ("文法エラー：条件式", "语法错误：条件式"),
    ("閉じ括弧がありません", "缺少右括号"),
    ("ラベルが見つかりません", "找不到标签"),
]

# 存档槽 01-09 的预置空日期串（"01・----／--／--[--:--]"），只需把 ・ 换成 ·
UI_TEXT += [("%02d・----／--／--[--:--]" % i, "%02d·----／--／--[--:--]" % i)
            for i in range(1, 10)]

# 鉴赏列表（Bgm.def / Cg.def / Event.def）里的显示名
DEF_TEXT = {
    "北上結也": "北上结也",
    "白川紗英": "白川纱英",
    "永井直見": "永井直见",
    "猛毒": "猛毒",
    "カジノバー": "赌场酒吧",
    "悲壮": "悲壮",
    "媚香": "媚香",
    "抱擁": "拥抱",
    "美少女奴隷クラブ": "美少女奴隶俱乐部",
    "背景": "背景",
    "毒島猛": "毒岛猛",
    "スマックス隊員": "斯玛克斯队员",
    "江里子": "江里子",
    "舐め犬": "舔犬",
    "町田": "町田",
    "話": "话",          # Event.def 的「第一話」等
    "節": "节",          # Event.def 的「第一節」等（本作实际用的是「節」）
}

DEF_FILES = ("Bgm.def", "Cg.def", "Event.def")


class PatchError(Exception):
    pass


# ---------------------------------------------------------------------------
# PE 工具（只用于校验与报告）
# ---------------------------------------------------------------------------

def pe_info(data):
    if data[:2] != b"MZ":
        raise PatchError("不是 MZ/PE 文件")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise PatchError("PE 头无效")
    machine, nsec = struct.unpack_from("<HH", data, pe + 4)
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    imagebase = struct.unpack_from("<I", data, opt + 28)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    sec = opt + optsz
    sections = []
    for i in range(nsec):
        o = sec + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin-1")
        vs, va, rs, ro = struct.unpack_from("<IIII", data, o + 8)
        sections.append((name, va, vs, ro, rs))
    return {
        "machine": machine, "nsections": nsec, "magic": magic,
        "imagebase": imagebase, "entry": entry, "sections": sections,
    }


def rva_to_off(info, rva):
    for _name, va, vs, ro, rs in info["sections"]:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None


# ---------------------------------------------------------------------------
# 补丁
# ---------------------------------------------------------------------------

def parse_charset(value):
    v = str(value).strip().lower()
    if v in CHARSET_NAMES:
        return CHARSET_NAMES[v]
    try:
        n = int(v, 0)
    except ValueError:
        raise PatchError("无法识别的字符集: %s" % value)
    if not 0 <= n <= 255:
        raise PatchError("字符集必须是 0-255: %s" % value)
    return n


def encode_font(name):
    """字体名编码：ASCII 原样，否则按 GBK。"""
    if all(ord(c) < 128 for c in name):
        return name.encode("ascii"), "ascii"
    try:
        return name.encode("gbk"), "gbk"
    except UnicodeEncodeError as e:
        raise PatchError("字体名无法用 GBK 编码: %s (%s)" % (name, e.reason))


def patch_ui(data, force=False):
    """把 exe 内的菜单/提示文本换成 GBK 中文（原位，剩余字节填 00）。"""
    out = bytearray(data)
    changes = []
    # 长串优先：避免「よろしいですか？」之类先吃掉长消息的尾巴
    for jp, zh in sorted(UI_TEXT, key=lambda kv: len(kv[0]), reverse=True):
        jb = jp.encode("cp932")
        zb = zh.encode("gbk")
        pat = jb + b"\x00"
        idx = 0
        found = 0
        while True:
            i = out.find(pat, idx)
            if i < 0:
                break
            found += 1
            z = 0
            k = i + len(jb)
            while k < len(out) and out[k] == 0 and z < 64:
                z += 1
                k += 1
            room = len(jb) + z
            if len(zb) + 1 > room:
                raise PatchError("译文过长: %r -> %r（需要 %d 字节，只有 %d）"
                                 % (jp, zh, len(zb) + 1, room))
            old = bytes(out[i:i + len(jb)])
            out[i:i + room] = zb + b"\x00" * (room - len(zb))
            changes.append((i, old, zb, "text %r" % jp))
            idx = i + room
        if not found and not force:
            raise PatchError("找不到字符串: %r（exe 版本不符？用 --force 跳过）" % jp)
    return bytes(out), changes


def patch_defs(folder, dry_run=False):
    """把 Bgm.def / Cg.def / Event.def 的显示名换成 GBK 中文，并重新 xor 0x44。"""
    folder = Path(folder)
    reports = []
    keys = sorted(DEF_TEXT, key=len, reverse=True)
    for name in DEF_FILES:
        p = folder / name
        if not p.is_file():
            reports.append((name, "跳过（文件不存在）"))
            continue
        raw = p.read_bytes()
        cipher_xor = raw[:1] != b";"
        plain = bytes(x ^ 0x44 for x in raw) if cipher_xor else raw
        try:
            text = plain.decode("cp932")
        except UnicodeDecodeError:
            reports.append((name, "不是 CP932 文本，跳过"))
            continue
        new = text
        count = 0
        for k in keys:
            c = new.count(k)
            if c:
                new = new.replace(k, DEF_TEXT[k])
                count += c
        if new == text:
            reports.append((name, "无需修改"))
            continue
        data = new.encode("gbk")
        if cipher_xor:
            data = bytes(x ^ 0x44 for x in data)
        if not dry_run:
            bak = p.with_name(p.name + ".bak")
            if not bak.exists():
                bak.write_bytes(raw)
            p.write_bytes(data)
        reports.append((name, "%d 处替换%s" % (count, "（dry-run）" if dry_run else "")))
    return reports


def patch_state(data, charset):
    """返回 [(项目, 当前状态)]，状态: 'patched' / 'original' / 'unknown'。"""
    rows = []
    for off, expect in CHARSET_SITES:
        got = data[off + 4]
        if got == charset:
            rows.append(("lfCharSet@0x%06X" % (off + 4), "patched"))
        elif got == expect[4]:
            rows.append(("lfCharSet@0x%06X" % (off + 4), "original"))
        else:
            rows.append(("lfCharSet@0x%06X" % (off + 4), "unknown(0x%02X)" % got))

    old = data[FONT_SITE:FONT_SITE + FONT_MAXLEN + 1]
    if old.startswith(CURRENT_FONT.encode("cp932") + b"\0"):
        rows.append(("lfFaceName@0x%06X" % FONT_SITE, "original"))
    else:
        name = old.split(b"\0", 1)[0]
        try:
            shown = name.decode("gbk")
        except UnicodeDecodeError:
            shown = name.hex()
        rows.append(("lfFaceName@0x%06X (%s)" % (FONT_SITE, shown), "patched"))

    for off, ch in SYMBOL_SITES:
        got = data[off:off + 2]
        if got == ch.encode("gbk"):
            rows.append(("symbol %r@0x%06X" % (ch, off), "patched"))
        elif got == ch.encode("cp932"):
            rows.append(("symbol %r@0x%06X" % (ch, off), "original"))
        else:
            rows.append(("symbol %r@0x%06X" % (ch, off), "unknown(%s)" % got.hex()))
    return rows


def build(data, charset, font_name, force=False):
    info = pe_info(data)
    if info["machine"] != 0x14C:
        raise PatchError("不是 32 位 PE（machine=0x%04X）" % info["machine"])

    font_bytes, font_enc = encode_font(font_name)
    if len(font_bytes) > FONT_MAXLEN:
        raise PatchError("字体名最多 %d 字节，%r 需要 %d 字节"
                         % (FONT_MAXLEN, font_name, len(font_bytes)))

    out = bytearray(data)
    changes = []

    for off, expect in CHARSET_SITES:
        got = bytes(out[off:off + len(expect)])
        if got == expect:
            pass
        elif got[:-1] == expect[:-1] and got[-1] == charset:
            print("[跳过] 0x%06X 已经是字符集 %d" % (off, charset))
            continue
        elif got[:-1] == expect[:-1] and not force:
            raise PatchError("0x%06X 内容异常: %s（用 --force 强制）" % (off, got.hex()))
        # 交叉校验：紧随其后（5..20 字节内）必有 `mov [esp+..+lf.lfHeight], -26`，
        # 且 lfFaceName 的偏移满足 lfHeight_disp - 0x17 == lfCharSet_disp
        want = b"\xC7\x44\x24" + bytes([expect[3] - 0x17]) + b"\xE6\xFF\xFF\xFF"
        if want not in bytes(out[off + 5:off + 20]):
            raise PatchError("0x%06X 附近不像 LOGFONT 初始化（lfHeight 校验失败）" % off)
        out[off + 4] = charset
        changes.append((off + 4, got[4], charset, "lfCharSet"))

    # 字体名
    old = bytes(out[FONT_SITE:FONT_SITE + FONT_MAXLEN + 1])
    orig = CURRENT_FONT.encode("cp932") + b"\0"
    new = font_bytes + b"\0" * (FONT_MAXLEN + 1 - len(font_bytes))
    if old == new:
        print("[跳过] 0x%06X 字体名已经是 %r" % (FONT_SITE, font_name))
    elif old.startswith(orig) or force:
        out[FONT_SITE:FONT_SITE + FONT_MAXLEN + 1] = new
        changes.append((FONT_SITE, old, new, "lfFaceName"))
    else:
        raise PatchError("字体字符串不符合预期: %r（用 --force 强制）" % old)

    # 文本控制符号（● ▲ ■ 与全角空格）：CP932 两字节 -> GBK 两字节
    for off, ch in SYMBOL_SITES:
        sjis = ch.encode("cp932")
        gbk = ch.encode("gbk")
        got = bytes(out[off:off + 2])
        if got == gbk:
            print("[跳过] 0x%06X 符号 %r 已是 GBK" % (off, ch))
            continue
        if got != sjis and not force:
            raise PatchError("0x%06X 符号 %r 内容异常: %s（用 --force 强制）"
                             % (off, ch, got.hex()))
        out[off:off + 2] = gbk
        changes.append((off, got, gbk, "symbol %r" % ch))

    # 菜单 / 提示文本
    out, ui_changes = patch_ui(bytes(out), force)
    changes.extend(ui_changes)

    return out, changes, font_enc


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="gbk_patch.py",
        description="D_Club.exe 简体中文补丁：GDI 字符集改 GB2312(0x86/134)，默认字体改黑体",
        epilog="示例:\n"
               "  python gbk_patch.py D_Club.exe\n"
               "  python gbk_patch.py D_Club.exe --font 黑体 --charset 134\n"
               "  python gbk_patch.py D_Club.exe --dry-run",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exe", nargs="?", help="原版 D_Club.exe 路径")
    parser.add_argument("--out", help="输出文件名（默认 <原名>_GBK.exe）")
    parser.add_argument("--charset", default="134",
                        help="字符集：134 / 0x86 / gb2312 等价（默认 134）")
    parser.add_argument("--font", default="SimHei",
                        help="默认字体名（默认 SimHei；写中文名会按 GBK 编码）")
    parser.add_argument("--inplace", action="store_true", help="就地修改（先备份 .bak）")
    parser.add_argument("--force", action="store_true", help="跳过原始字节校验")
    parser.add_argument("--dry-run", action="store_true", help="只报告要改的字节，不写文件")
    parser.add_argument("--check", action="store_true",
                        help="检查指定 exe 是否已打补丁（不写文件）")
    parser.add_argument("--defs", metavar="DIR",
                        help="同时汉化该目录下的 Bgm.def / Cg.def / Event.def（会先备份 .bak）")
    args = parser.parse_args(argv)

    if not args.exe:
        parser.print_help()
        return 1

    src = Path(args.exe)
    if not src.is_file():
        print("找不到文件: %s" % src, file=sys.stderr)
        return 2

    data = src.read_bytes()

    if args.check:
        charset = parse_charset(args.charset)
        print("检查: %s (%d 字节, sha256=%s)"
              % (src, len(data), hashlib.sha256(data).hexdigest()[:16]))
        rows = patch_state(data, charset)
        for name, state in rows:
            print("  %-24s %s" % (name, state))
        todo = [n for n, s in rows if s != "patched"]
        left = sum(1 for jp, _ in UI_TEXT if (jp.encode("cp932") + b"\x00") in data)
        print("  菜单/提示文本            %d/%d 已汉化" % (len(UI_TEXT) - left, len(UI_TEXT)))
        if todo or left:
            print("结论: 未打补丁（%d 处结构项、%d 条文本待修改）" % (len(todo), left))
            return 1
        print("结论: 已全部打补丁")
        return 0
    charset = parse_charset(args.charset)

    try:
        patched, changes, font_enc = build(data, charset, args.font, args.force)
    except PatchError as e:
        print("[错误] %s" % e, file=sys.stderr)
        return 1

    info = pe_info(data)
    print("源文件   : %s" % src)
    print("大小     : %d 字节  sha256=%s" % (len(data), hashlib.sha256(data).hexdigest()[:16]))
    print("PE       : machine=0x%04X imagebase=0x%08X entry=0x%08X sections=%d"
          % (info["machine"], info["imagebase"], info["entry"], info["nsections"]))
    print("字符集   : %d (0x%02X)" % (charset, charset))
    print("字体     : %r (%s, %d 字节)" % (args.font, font_enc, len(args.font.encode('gbk', 'replace'))))
    print("")

    struct_changes = [c for c in changes if not c[3].startswith("text ")]
    text_changes = [c for c in changes if c[3].startswith("text ")]

    if struct_changes:
        for off, old, new, what in struct_changes:
            if isinstance(old, int):
                print("  0x%06X  %-10s %02X -> %02X" % (off, what, old, new))
            else:
                print("  0x%06X  %-10s %s -> %s" % (off, what, old.hex(), bytes(new).hex()))
    if text_changes:
        print("  菜单/提示文本  %d 条已替换为 GBK 中文" % len(text_changes))
    if not changes:
        print("exe 无需修改（可能已经打过补丁）")

    if args.dry_run:
        print("\n(dry-run，未写文件)")
        if args.defs:
            for name, rep in patch_defs(args.defs, dry_run=True):
                print("  %-10s %s" % (name, rep))
        return 0

    if changes:
        if args.inplace:
            dst = src
            bak = src.with_name(src.name + ".bak")
            if not bak.exists():
                bak.write_bytes(data)
                print("\n已备份原文件 -> %s" % bak)
        else:
            dst = Path(args.out) if args.out else src.with_name(src.stem + "_GBK" + src.suffix)
        dst.write_bytes(patched)
        print("\n输出     : %s (%d 字节)" % (dst, len(patched)))

    if args.defs:
        print("\n鉴赏列表:")
        for name, rep in patch_defs(args.defs):
            print("  %-10s %s" % (name, rep))

    print("提示     : 系统区域设置需为中文(936)，否则 TextOutA 仍会按日文代码页解释字节")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
