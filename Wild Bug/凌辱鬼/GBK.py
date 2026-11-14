#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GBK.py -- 把 Wild Bug 引擎的 exe 改成 GBK(CP936) 文本引擎，并汉化菜单/对话框。

用法：
    python GBK.py [exe]                # 打补丁（自动备份为 <exe>.bak）
    python GBK.py [exe] --restore      # 从备份还原
    python GBK.py [exe] --check        # 只检查当前 exe 的补丁状态
    python GBK.py --list               # 列出支持的 exe 版本

支持版本（按 exe 大小自动识别，补丁点由逆向逐个核对）：

    REIMI.EXE     349,696  《電脳M奴隷・麗美》 2000-06
    RYOJKUKI.EXE  350,720  《凌辱鬼》          2000-09

补丁内容（全部来自 exe 静态逆向）：

1. 字符切分：把写死的 Shift-JIS 前导字节范围 0x81..0x9F 放宽到 0x81..0xFE
   （8 处 cmp ...,9Fh：正文、标题/菜单、文本量测各有一套），尾字节上限
   0xFC 同步放宽到 0xFE（8 处）；GBK 的双字节范围正好是 0x81..0xFE。
2. 字形缓存索引：sub_4251D2 用 189*(lead-0x81|0xC1)+(trail-0x40) 的 SJIS 公式，
   改成 GBK 公式 190*(lead-0x81)+(trail-0x40)，并把缓存表从 11340 项扩到
   24000 项（0xB130 -> 0x17700 字节，0x2C4C -> 0x5DC0 项）。
3. 字体：两处 LOGFONTA.lfCharSet = SHIFTJIS_CHARSET(0x80) 改成
   GB2312_CHARSET(0x86)；字体枚举回调只接受 tmCharSet==0x80 的比较同样改成 0x86，
   这样"Text Config"里会列出宋体/黑体等中文字体。
4. 游戏内菜单文本：.data 里 20/18 字节的定宽菜单项（ＳＡＶＥ／ＬＯＡＤ／
   グラフィックを見る／回想に戻る／ゲームに戻る／タイトルに戻る 等）按 GBK 改写，
   并用 0x20 与全角空格 U+3000 重新左右对称居中，字段长度不变。
5. 退出提示："終了しますか？" -> "要退出游戏吗？"、"終了の確認" -> "退出确认"。
6. 对话框文本：.rsrc 里的 UTF-16 对话框文本按等字符数改写（不足补空格），
   保证模板长度/NUL 位置完全不变。

窗口上方菜单栏（&Application／&Config／&Text Setting ... 等）**不做修改**，
保留原文交给使用者自行处理。

注意：引擎用 GDI 的 ANSI 接口(TextOutA)绘制文字，字节由系统 ANSI 代码页解释。
因此打完补丁后需要在 **中文区域设置（CP936）** 下运行（可用 LocaleEmulator 选
zh-CN），否则 GBK 字节仍会按日文代码页解释。
"""
import hashlib
import os
import shutil
import struct
import sys

DEFAULT_EXE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exe", "REIMI.EXE")
DEFAULT_EXE_RYO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exe", "RYOJKUKI.EXE")

# ---------------------------------------------------------------------------
# 二进制补丁：(名称, 原始字节, 新字节)
# 文件内偏移随 exe 版本不同，放在 PROFILES[..]["offsets"] 里
# ---------------------------------------------------------------------------
PATCHES = [
    # --- 字体字符集 0x80 -> 0x86 (GB2312_CHARSET) ---
    ("font.charset.1", b"\x80", b"\x86"),      # mov byte [esi+17h],80h
    ("font.charset.2", b"\x80", b"\x86"),      # mov byte [edi+17h],80h
    ("font.enum",      b"\x80", b"\x86"),      # cmp byte [eax+34h],80h

    # --- Shift-JIS 前导字节范围 0x9F -> 0xFE ---
    ("split.1", b"\x9F", b"\xFE"),
    ("split.2", b"\x9F", b"\xFE"),
    ("split.3", b"\x9F", b"\xFE"),
    ("split.4", b"\x9F", b"\xFE"),

    # --- 其它文本渲染/量测函数里的同一范围判断（标题、菜单、选字等） ---
    ("split.5", b"\x9F", b"\xFE"),
    ("split.6", b"\x9F", b"\xFE"),
    ("split.7", b"\x9F", b"\xFE"),
    ("split.8", b"\x9F", b"\xFE"),

    # --- 尾字节上限 0xFC -> 0xFE（GBK 尾字节到 0xFE） ---
    ("trail.1", b"\xFC", b"\xFE"),
    ("trail.2", b"\xFC", b"\xFE"),
    ("trail.3", b"\xFC", b"\xFE"),
    ("trail.4", b"\xFC", b"\xFE"),
    ("trail.5", b"\xFC", b"\xFE"),
    ("trail.6", b"\xFC", b"\xFE"),
    ("trail.7", b"\xFC", b"\xFE"),
    ("trail.8", b"\xFC", b"\xFE"),

    # --- 字形缓存索引（189 -> 190，范围判定放宽） ---
    ("glyph.trail",  b"\xFC\x00\x00\x00", b"\xFE\x00\x00\x00"),
    ("glyph.trail2", b"\xFC\x00\x00\x00", b"\xFE\x00\x00\x00"),
    ("glyph.lead",   b"\x9F\x00\x00\x00", b"\xFE\x00\x00\x00"),
    ("glyph.jump",   b"\x14", b"\x36"),                    # jg -> 零分支
    ("glyph.mul",    b"\xBD\x00\x00\x00", b"\xBE\x00\x00\x00"),

    # --- 双字节字形缓存容量 11340 -> 24000 ---
    ("cache.alloc.1", b"\x30\xB1\x00\x00", b"\x00\x77\x01\x00"),  # push 0B130h
    ("cache.alloc.2", b"\x30\xB1\x00\x00", b"\x00\x77\x01\x00"),
    ("cache.alloc.3", b"\x30\xB1\x00\x00", b"\x00\x77\x01\x00"),
    ("cache.loop.1",  b"\x4C\x2C\x00\x00", b"\xC0\x5D\x00\x00"),  # cmp edx,2C4Ch
    ("cache.loop.2",  b"\x4C\x2C\x00\x00", b"\xC0\x5D\x00\x00"),
    ("cache.loop.3",  b"\x4C\x2C\x00\x00", b"\xC0\x5D\x00\x00"),
    ("cache.size.1",  b"\x4C\x2C\x00\x00", b"\xC0\x5D\x00\x00"),  # imul ..,2C4Ch
    ("cache.size.2",  b"\x4C\x2C\x00\x00", b"\xC0\x5D\x00\x00"),
]

# 每个版本的补丁点文件偏移（VA - 0x400A00，.text 段布局两者相同）
_REIMI_OFFSETS = {
    "font.charset.1": 0x0062EE, "font.charset.2": 0x006346, "font.enum": 0x001E7E,
    "split.1": 0x00CF3B, "split.2": 0x00CFC6, "split.3": 0x00D050, "split.4": 0x025A78,
    "split.5": 0x024BA2, "split.6": 0x024F73, "split.7": 0x025346, "split.8": 0x025625,
    "trail.1": 0x00CF45, "trail.2": 0x00CFD0, "trail.3": 0x00D05A, "trail.4": 0x024BB0,
    "trail.5": 0x024F87, "trail.6": 0x025350, "trail.7": 0x025639, "trail.8": 0x025A8C,
    "glyph.trail": 0x024838, "glyph.trail2": 0x02486C, "glyph.lead": 0x02484A,
    "glyph.jump": 0x02484F, "glyph.mul": 0x024857,
    "cache.alloc.1": 0x02427B, "cache.alloc.2": 0x024356, "cache.alloc.3": 0x0245B4,
    "cache.loop.1": 0x024380, "cache.loop.2": 0x0245DB, "cache.loop.3": 0x024756,
    "cache.size.1": 0x02457E, "cache.size.2": 0x0245E4,
}

_RYO_OFFSETS = {
    "font.charset.1": 0x0065A4, "font.charset.2": 0x0065FC, "font.enum": 0x001E88,
    "split.1": 0x00D446, "split.2": 0x00D4D1, "split.3": 0x00D55B, "split.4": 0x0266CC,
    "split.5": 0x0257F6, "split.6": 0x025BC7, "split.7": 0x025F9A, "split.8": 0x026279,
    "trail.1": 0x00D450, "trail.2": 0x00D4DB, "trail.3": 0x00D565, "trail.4": 0x025804,
    "trail.5": 0x025BDB, "trail.6": 0x025FA4, "trail.7": 0x02628D, "trail.8": 0x0266E0,
    "glyph.trail": 0x02548C, "glyph.trail2": 0x0254C0, "glyph.lead": 0x02549E,
    "glyph.jump": 0x0254A3, "glyph.mul": 0x0254AB,
    "cache.alloc.1": 0x024ECF, "cache.alloc.2": 0x024FAA, "cache.alloc.3": 0x025208,
    "cache.loop.1": 0x024FD4, "cache.loop.2": 0x02522F, "cache.loop.3": 0x0253AA,
    "cache.size.1": 0x0251D2, "cache.size.2": 0x025238,
}

PROFILES = [
    {
        "label": "REIMI.EXE  (Denno M dorei Reimi, 2000-06)",
        "size": 349696,
        "sha256": "3ccbf9c78992f71dd9813488a0d4a67f03927fecc229371d5925353262dd3246",
        "offsets": _REIMI_OFFSETS,
    },
    {
        "label": "RYOJKUKI.EXE  (Ryoujokuki, 2000-09)",
        "size": 350720,
        "sha256": "89497b85b038b0629436263e1d2b6f33414fd049a5cd0491a4d2629be05b932c",
        "offsets": _RYO_OFFSETS,
    },
]

# ---------------------------------------------------------------------------
# .data 里的游戏内菜单文本（原样保留 20/18 字节的定宽字段，居中重新填充）
#
# 原字段用 0x20（半角空格）和 U+3000（全角空格，GBK A1A1）左右对称填充，
# 例如 "　　　ＬＯＡＤ　　　"。这里按同样的规则重新居中，保证字段长度不变。
# ---------------------------------------------------------------------------
MENU_TEXT = [
    (" グラフィックを見る ", "查看图片"),
    ("　　 回想に戻る　　 ", "返回回想"),
    ("　　　ＳＡＶＥ　　　", "保存"),
    ("　　　ＬＯＡＤ　　　", "读取"),
    ("　　ゲームに戻る　　", "返回游戏"),
    (" 　タイトルに戻る　 ", "返回标题"),
    ("     前回の続き     ", "继续上次"),
    (" ＬＯＡＤ ＤＡＴＡ", "读取数据"),
    (" ＳＡＶＥ ＤＡＴＡ", "保存数据"),
]

# 普通 NUL 结尾的提示文本（不做居中，只补空格到原长度）
PLAIN_TEXT = [
    ("終了しますか？", "要退出游戏吗？"),
    ("終了の確認", "退出确认"),
]

# 窗口上方菜单栏文本（&Application/&Config/...）不做修改，由用户自行处理。

# ---------------------------------------------------------------------------
# UTF-16 (.rsrc) 对话框文本：原文 -> 译文（字符数必须 <= 原文，不足补空格）
# ---------------------------------------------------------------------------
UTF16_TEXT = {
    "Text Config":            "文本设置",
    "背景輝度":                "背景亮度",
    "暗":                     "暗",
    "明":                     "亮",
    "OK":                     "确定",
    "CANCEL":                 "取消",
    "初期化":                  "初始化",
    "フォント":                "字体",
    "全てのフォント":           "所有字体",
    "デフォルト文字色":         "默认文字颜色",
    "Volume":                 "音量设置",
    "出力デバイス":             "输出设备",
    "大":                     "大",
    "小":                     "小",
    "ﾏｽﾀｰ":                  "主音量",
    "Version info":           "版本信息",
    "Debug":                  "调试",
}


# ---------------------------------------------------------------------------
# PE 解析：从 section 表取 .text / .data / .rsrc 的实际文件区间
# ---------------------------------------------------------------------------
def pe_sections(d):
    if d[:2] != b"MZ":
        raise SystemExit("不是 PE 文件")
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe + 4] != b"PE\x00\x00":
        raise SystemExit("不是 PE 文件")
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    base = struct.unpack_from("<I", d, pe + 24 + 28)[0]
    off = pe + 24 + optsz
    secs = {}
    for i in range(nsec):
        o = off + i * 40
        name = d[o:o + 8].rstrip(b"\x00").decode("latin1")
        vsize, va, rsize, raw = struct.unpack_from("<IIII", d, o + 8)
        secs[name] = {"va": va, "vsize": vsize, "raw": raw, "size": rsize}
    return base, secs


def pick_profile(d):
    for p in PROFILES:
        if len(d) != p["size"]:
            continue
        # 用补丁点的原始字节再确认一次，防止同尺寸的其它版本误伤
        ok = 0
        for name, old, new in PATCHES:
            off = p["offsets"].get(name)
            if off is None:
                continue
            cur = d[off:off + len(old)]
            if cur in (old, new):
                ok += 1
        if ok >= len(PATCHES) - 1:
            return p
    return None


class Target:
    """一个已识别的 exe：文件内容 + 版本信息 + 各段区间。"""

    def __init__(self, path, data):
        self.path = path
        self.d = data
        prof = pick_profile(data)
        if prof is None:
            sizes = ", ".join("%d" % p["size"] for p in PROFILES)
            raise SystemExit(
                "!! 不支持的 exe（%d 字节）。本脚本适配：\n%s\n"
                "如需新版本，请按 vm_analysis.md 的方法重新定位补丁点。"
                % (len(data), "\n".join("   %-46s %d 字节  sha256 %s…"
                                        % (p["label"], p["size"], p["sha256"][:12])
                                        for p in PROFILES)))
        self.profile = prof
        self.base, self.secs = pe_sections(data)
        if ".data" not in self.secs or ".rsrc" not in self.secs:
            raise SystemExit("!! exe 缺少 .data / .rsrc 段")

    def off(self, name):
        o = self.profile["offsets"].get(name)
        if o is None:
            raise SystemExit("!! 版本 %s 没有补丁点 %s" % (self.profile["label"], name))
        return o

    @property
    def data_range(self):
        s = self.secs[".data"]
        return s["raw"], s["raw"] + s["size"]

    @property
    def rsrc_range(self):
        s = self.secs[".rsrc"]
        return s["raw"], s["raw"] + s["size"]


def patch_binary(t, report):
    d = t.d
    for name, old, new in PATCHES:
        off = t.off(name)
        cur = d[off:off + len(old)]
        if cur == new:
            report.append("  %-16s already patched" % name)
            continue
        if cur != old:
            raise SystemExit("!! %s: unexpected bytes at 0x%X: %s" % (name, off, cur.hex()))
        d[off:off + len(new)] = new
        report.append("  %-16s patched @0x%X" % (name, off))


def _pad_side(n, outer_left=True):
    """生成 n 字节的填充：全角空格 U+3000(A1A1) 为主，奇数补一个 0x20。"""
    if n <= 0:
        return b""
    b = b"\xA1\xA1" * (n // 2)
    if n % 2:
        b = (b"\x20" + b) if outer_left else (b + b"\x20")
    return b


def center_field(rep, width):
    """把 GBK 字节 rep 在 width 字节内左右对称居中。"""
    pad = width - len(rep)
    if pad < 0:
        raise SystemExit("!! 译文过长: %r (%d > %d 字节)" % (rep, len(rep), width))
    left = pad // 2
    right = pad - left
    return _pad_side(left, True) + rep + _pad_side(right, False)


def patch_menu(t, report):
    d = t.d
    lo, hi = t.data_range
    for src, dst in MENU_TEXT:
        raw = src.encode("cp932")
        if len(raw) not in (18, 20):
            raise SystemExit("!! 菜单字段长度异常: %r (%d)" % (src, len(raw)))
        payload = center_field(dst.encode("gbk"), len(raw))
        n = 0
        start = lo
        while True:
            j = d.find(raw, start, hi)
            if j < 0:
                break
            d[j:j + len(raw)] = payload
            n += 1
            start = j + 1
        if n:
            report.append("  menu  %-22r -> %-12r x%d (居中 %d 字节)" % (src, dst, n, len(raw)))
        elif payload in d:
            report.append("  menu  %-22r -> %-12r already patched" % (src, dst))
        else:
            report.append("  menu  %-22r 未找到" % src)


def patch_plain(t, report):
    d = t.d
    lo, hi = t.data_range
    for src, dst in PLAIN_TEXT:
        raw = src.encode("cp932")
        rep = dst.encode("gbk")
        if len(rep) > len(raw):
            raise SystemExit("!! 译文过长: %r -> %r (%d > %d 字节)" % (src, dst, len(rep), len(raw)))
        payload = rep + b" " * (len(raw) - len(rep))
        n = 0
        start = lo
        while True:
            needle = raw + b"\x00"
            j = d.find(needle, start, hi)
            if j < 0:
                break
            d[j:j + len(raw)] = payload
            n += 1
            start = j + 1
        report.append("  text  %-22r -> %-12r x%d" % (src, dst, n))
        if n == 0 and payload in d:
            report[-1] = "  text  %-22r -> %-12r already patched" % (src, dst)


def patch_utf16(t, report):
    d = t.d
    lo, hi = t.rsrc_range
    # 长串优先："フォント" 是 "全てのフォント" 的子串，先处理短串会把长串改坏
    for src, dst in sorted(UTF16_TEXT.items(), key=lambda kv: -len(kv[0])):
        raw = src.encode("utf-16le")
        rep = dst.encode("utf-16le")
        if len(dst) > len(src):
            raise SystemExit("!! 译文过长: %r -> %r (%d > %d 字符)" % (src, dst, len(dst), len(src)))
        payload = rep + (" " * (len(src) - len(dst))).encode("utf-16le")
        n = 0
        start = lo
        while True:
            j = d.find(raw, start, hi)
            if j < 0:
                break
            d[j:j + len(raw)] = payload
            n += 1
            start = j + 1
        if n:
            report.append("  dlg   %-24r -> %-16r x%d" % (src, dst, n))


def find_default_exe():
    for p in (DEFAULT_EXE, DEFAULT_EXE_RYO):
        if os.path.exists(p):
            return p
    return DEFAULT_EXE


def main(argv):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    exe = find_default_exe()
    args = [a for a in argv if not a.startswith("--")]
    if args:
        exe = args[0]
    do_restore = "--restore" in argv
    do_check = "--check" in argv

    if "--list" in argv:
        print("支持的 exe 版本：")
        for p in PROFILES:
            print("  %-46s %7d 字节  sha256 %s…" % (p["label"], p["size"], p["sha256"][:12]))
        return 0

    if not os.path.exists(exe):
        print("找不到:", exe)
        return 1
    data = bytearray(open(exe, "rb").read())
    try:
        t = Target(exe, data)
    except SystemExit as exc:
        print(exc)
        return 1
    print("目标: %s  [%s]" % (os.path.basename(exe), t.profile["label"]))

    bak = exe + ".bak"
    if do_restore:
        if not os.path.exists(bak):
            print("没有备份文件:", bak)
            return 1
        shutil.copyfile(bak, exe)
        print("已还原:", exe)
        return 0

    if do_check:
        ok = 0
        for name, old, new in PATCHES:
            off = t.off(name)
            cur = data[off:off + len(new)]
            state = "patched" if cur == new else (
                "original" if cur == old else "unknown")
            ok += state == "patched"
            print("%-16s 0x%06X  %s" % (name, off, state))
        print("%d/%d patched" % (ok, len(PATCHES)))
        return 0

    if not os.path.exists(bak):
        shutil.copyfile(exe, bak)
        print("已备份 ->", bak)

    report = []
    patch_binary(t, report)
    patch_menu(t, report)
    patch_plain(t, report)
    patch_utf16(t, report)
    open(exe, "wb").write(data)
    print("补丁完成:", exe)
    for line in report:
        try:
            print(line)
        except UnicodeEncodeError:
            print(line.encode("ascii", "backslashreplace").decode("ascii"))
    print("\n提示：请在中文区域设置(CP936)下运行游戏；可用 LocaleEmulator 选择 zh-CN。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
