"""opcodelist.py — 魔法少女アイ plus DVD (scr.bnd) 脚本字节码定义。

本模块是 disassembler.py / assembler.py 的唯一格式真值源。

二进制格式（逆向结论，详见 vm_analysis.md）
--------------------------------------------------
每个脚本是 4 字节对齐的 dword 流。每条指令的首 dword 为：

    bits 31..24 : opcode
    bits 23..8  : 保留（样本中恒为 0）
    bits 7..0   : 编译器写入的辅助字节（样本中每个 opcode 恒定，运行时被调度器忽略）

    header = (opcode << 24) | b0

文本以「单元数（units）」计量，1 unit = 4 字节：

    text_blob = encoded_text + b"\x00\x00" + 零填充
    units     = len(text_blob) // 4        （所有样本均取最小值）

跳转类操作数是 **dword 下标**（PC index），不是字节偏移：

    dword_index = byte_offset // 4

因此文本长度改变后，其后的 JUMP / CHOICE 目标以及同文件内的所有 PC 下标
必须由汇编器重新计算。disassembler 会把它们输出为 loc_XXXXXXXX 标签。

官方命名不可得；mnemonic 依据 0x412d50 处 VM 调度器与各 handler 的
实际行为命名（见 vm_analysis.md 的“证据”列）。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

VERSION = "1.0"
DEFAULT_ENCODING = "cp932"

# ---------------------------------------------------------------------------
# 操作码表
# ---------------------------------------------------------------------------
# kind:
#   fixed   — 固定数量的 u32 操作数
#   text    — units + 文本（0x21 TITLE / 0x22 LABEL）
#   message — 1 个 u32 + units + 文本（0x05）
#   message2— 2 个 u32 + units + 文本（0x06）
#   choice  — count + count*(units + 文本 + target)
#   list    — n + n 个 u32（0x09）
#   jump    — 1 个 u32，语义为 PC 下标
#   call    — 2 个 u32：目标脚本编号 + 目标脚本内的入口 PC 下标
#
# confidence: confirmed = 已由 handler 代码/大量样本确认
#             inferred  = 由上下文推断
OPCODES: Dict[int, dict] = {
    0x01: dict(mnemonic="PLAY_BGM", b0=1, kind="fixed", argc=1,
               desc="播放 BGM；特殊值 0x3E8/0x3E9/0x3EA 走音量/停止分支",
               confidence="inferred"),
    0x02: dict(mnemonic="PLAY_SE", b0=1, kind="fixed", argc=1,
               desc="播放音效；同样支持 0x3E8/0x3E9/0x3EA 特殊分支",
               confidence="inferred"),
    0x03: dict(mnemonic="PLAY_SOUND", b0=3, kind="fixed", argc=3,
               desc="(id, channel, loop) 写入 3 个声道槽并播放",
               confidence="confirmed"),
    0x04: dict(mnemonic="SCREEN_EFFECT", b0=1, kind="fixed", argc=1,
               desc="屏幕/窗口绘制或淡入淡出效果（handler 0x403210）",
               confidence="inferred"),
    0x05: dict(mnemonic="MESSAGE", b0=1, kind="message", argc=1,
               desc="(voice_id) + 文本；普通对白",
               confidence="confirmed"),
    0x06: dict(mnemonic="MESSAGE_AUTO", b0=2, kind="message2", argc=2,
               desc="(voice_id, param) + 文本；自动/特殊模式对白（样本仅 6 条）",
               confidence="confirmed"),
    0x07: dict(mnemonic="CHOICE", b0=1, kind="choice",
               desc="选项菜单：count + count*(units, 文本, PC 目标)",
               confidence="confirmed"),
    0x08: dict(mnemonic="SET_VAR", b0=2, kind="fixed", argc=2,
               desc="(变量号, 字节值) 设置标志变量",
               confidence="confirmed"),
    0x09: dict(mnemonic="SET_VARS", b0=2, kind="list",
               desc="n + n 个 u32，按 (变量号, 值) 成对批量设置（n 恒为偶数）",
               confidence="confirmed"),
    0x0A: dict(mnemonic="BRANCH_0A", b0=3, kind="fixed", argc=3,
               desc="条件分支（本作样本未使用，条件未确认）",
               confidence="inferred"),
    0x0B: dict(mnemonic="INC_COUNTER", b0=1, kind="fixed", argc=1,
               desc="计数器/变量数组 [arg] += 1",
               confidence="confirmed"),
    0x0C: dict(mnemonic="DEC_COUNTER", b0=1, kind="fixed", argc=1,
               desc="计数器/变量数组 [arg] -= 1",
               confidence="confirmed"),
    0x0D: dict(mnemonic="BRANCH_0D", b0=3, kind="fixed", argc=3,
               desc="条件分支（未使用）", confidence="inferred"),
    0x0E: dict(mnemonic="BRANCH_0E", b0=3, kind="fixed", argc=3,
               desc="条件分支（未使用）", confidence="inferred"),
    0x0F: dict(mnemonic="BRANCH_0F", b0=3, kind="fixed", argc=3,
               desc="条件分支（未使用）", confidence="inferred"),
    0x10: dict(mnemonic="BRANCH_10", b0=3, kind="fixed", argc=3,
               desc="条件分支（未使用）", confidence="inferred"),
    0x11: dict(mnemonic="JUMP", b0=1, kind="jump", argc=1,
               desc="无条件跳转，操作数为 dword 下标",
               confidence="confirmed"),
    0x12: dict(mnemonic="CALL_SCRIPT", b0=3, kind="call", argc=2,
               desc="(脚本编号, 目标脚本内入口 PC 下标) 压栈并切换脚本；返回后继续",
               confidence="confirmed"),
    0x13: dict(mnemonic="RETURN", b0=1, kind="fixed", argc=0,
               desc="从 CALL_SCRIPT 返回；调用栈为空时弹出 RET-STACK-ERROR",
               confidence="confirmed"),
    0x14: dict(mnemonic="LOAD_BG", b0=2, kind="fixed", argc=2,
               desc="(资源号, 模式) 加载背景层",
               confidence="confirmed"),
    0x15: dict(mnemonic="CLEAR_BG", b0=0, kind="fixed", argc=0,
               desc="释放背景层", confidence="confirmed"),
    0x16: dict(mnemonic="LOAD_CHAR", b0=2, kind="fixed", argc=2,
               desc="(资源号, 模式) 加载角色立绘层",
               confidence="confirmed"),
    0x17: dict(mnemonic="CLEAR_CHAR", b0=0, kind="fixed", argc=0,
               desc="释放角色立绘层", confidence="confirmed"),
    0x18: dict(mnemonic="LOAD_FG", b0=2, kind="fixed", argc=2,
               desc="(资源号, 模式) 加载前景/特效层",
               confidence="confirmed"),
    0x19: dict(mnemonic="CLEAR_FG", b0=1, kind="fixed", argc=1,
               desc="释放前景层（带一个参数）", confidence="confirmed"),
    0x1A: dict(mnemonic="SKIP2", b0=2, kind="fixed", argc=2,
               desc="跳过 2 个 dword（占位/未使用）", confidence="confirmed"),
    0x1B: dict(mnemonic="NOP", b0=0, kind="fixed", argc=0,
               desc="空操作（调度器直接返回）", confidence="confirmed"),
    0x1C: dict(mnemonic="WAIT", b0=0, kind="fixed", argc=1,
               desc="等待指定毫秒数（GetTickCount）", confidence="confirmed"),
    0x1D: dict(mnemonic="WAIT_STATE", b0=0, kind="fixed", argc=0,
               desc="等待状态 0x0B（未使用）", confidence="confirmed"),
    0x1E: dict(mnemonic="QUIT", b0=0, kind="fixed", argc=0,
               desc="设置退出标志并进入状态 0x13（调试菜单的“終了”）",
               confidence="confirmed"),
    0x1F: dict(mnemonic="RANDOM", b0=2, kind="fixed", argc=2,
               desc="(计数器槽, 范围) 取随机数（未使用）", confidence="confirmed"),
    0x20: dict(mnemonic="SET_MODE", b0=1, kind="fixed", argc=1,
               desc="设置模式字节（未使用）", confidence="inferred"),
    0x21: dict(mnemonic="TITLE", b0=1, kind="text",
               desc="章节标题文本（复制到标题缓冲区，不进入对白窗口）",
               confidence="confirmed"),
    0x22: dict(mnemonic="LABEL", b0=1, kind="text",
               desc="命名标签（运行时直接跳过文本，供 CHOICE/CALL 定位）",
               confidence="confirmed"),
    0x23: dict(mnemonic="END", b0=0, kind="fixed", argc=0,
               desc="脚本终止哨兵；直接执行会弹出“到达脚本终点”消息框",
               confidence="confirmed"),
}

TEXT_KINDS = {"text", "message", "message2", "choice"}
JUMP_OPS = {0x11}
CHOICE_OPS = {0x07}
CALL_OPS = {0x12}


class ScriptError(Exception):
    """脚本格式错误。"""


@dataclass
class Record:
    offset: int                 # 字节偏移
    op: int
    b0: int
    args: List[int] = field(default_factory=list)
    texts: List[bytes] = field(default_factory=list)
    entries: List[Tuple[bytes, int]] = field(default_factory=list)  # (text, target_pc)
    size: int = 0

    @property
    def index(self) -> int:
        return self.offset // 4

    @property
    def mnemonic(self) -> str:
        return OPCODES[self.op]["mnemonic"]


def opcode_info(op: int) -> dict:
    try:
        return OPCODES[op]
    except KeyError:
        raise ScriptError(f"未知操作码 0x{op:02X}") from None


def _u32(data: bytes, pos: int) -> int:
    if pos + 4 > len(data):
        raise ScriptError(f"在 0x{pos:X} 处读取 u32 越界（文件长度 0x{len(data):X}）")
    return struct.unpack_from("<I", data, pos)[0]


def text_units(nbytes: int) -> int:
    """文本（含 2 字节终止符）占用的 4 字节单元数。"""
    return (nbytes + 2 + 3) // 4


def parse_record(data: bytes, pos: int) -> Record:
    """解析 pos 处的一条指令，返回 Record；不做跨记录校验。"""
    if pos % 4:
        raise ScriptError(f"指令地址 0x{pos:X} 未按 4 字节对齐")
    word = _u32(data, pos)
    if word & 0x00FFFF00:
        raise ScriptError(f"0x{pos:X}: 指令头保留位非零（0x{word:08X}）")
    op = (word >> 24) & 0xFF
    b0 = word & 0xFF
    info = opcode_info(op)
    p = pos + 4
    rec = Record(offset=pos, op=op, b0=b0)

    kind = info["kind"]
    if kind == "fixed":
        for _ in range(info["argc"]):
            rec.args.append(_u32(data, p))
            p += 4
    elif kind == "text":
        units = _u32(data, p)
        p += 4
        rec.texts.append(data[p:p + units * 4])
        p += units * 4
    elif kind == "message":
        rec.args.append(_u32(data, p))
        p += 4
        units = _u32(data, p)
        p += 4
        rec.texts.append(data[p:p + units * 4])
        p += units * 4
    elif kind == "message2":
        rec.args.append(_u32(data, p)); p += 4
        rec.args.append(_u32(data, p)); p += 4
        units = _u32(data, p); p += 4
        rec.texts.append(data[p:p + units * 4])
        p += units * 4
    elif kind == "choice":
        count = _u32(data, p)
        p += 4
        rec.args.append(count)
        if count > 0x1000:
            raise ScriptError(f"0x{pos:X}: CHOICE 选项数异常 ({count})")
        for _ in range(count):
            units = _u32(data, p)
            p += 4
            blob = data[p:p + units * 4]
            p += units * 4
            target = _u32(data, p)
            p += 4
            rec.entries.append((blob, target))
    elif kind == "list":
        n = _u32(data, p)
        p += 4
        rec.args.append(n)
        if n > 0x1000:
            raise ScriptError(f"0x{pos:X}: SET_VARS 数量异常 ({n})")
        for _ in range(n):
            rec.args.append(_u32(data, p))
            p += 4
    elif kind == "jump":
        rec.args.append(_u32(data, p))
        p += 4
    elif kind == "call":
        rec.args.append(_u32(data, p)); p += 4
        rec.args.append(_u32(data, p)); p += 4
    else:
        raise ScriptError(f"0x{pos:X}: 未实现的 kind={kind}")

    if p > len(data):
        raise ScriptError(f"0x{pos:X}: 指令越过文件末尾")
    rec.size = p - pos
    return rec


def iter_records(data: bytes):
    """从头到尾解析，保证无空隙、无越界。"""
    pos = 0
    n = len(data)
    if n % 4:
        raise ScriptError(f"文件长度 {n} 不是 4 的倍数")
    while pos < n:
        rec = parse_record(data, pos)
        # 文本块尾部必须是 0x00 0x00 + 零填充
        for blob in rec.texts:
            _check_text_blob(blob, pos)
        for blob, _ in rec.entries:
            _check_text_blob(blob, pos)
        yield rec
        pos += rec.size
    if pos != n:
        raise ScriptError(f"解析结束于 0x{pos:X}，文件长度 0x{n:X}")


def _check_text_blob(blob: bytes, rec_off: int) -> None:
    if not blob:
        raise ScriptError(f"0x{rec_off:X}: 文本单元为 0")
    body = blob.rstrip(b"\x00")
    if len(body) + 2 > len(blob):
        raise ScriptError(f"0x{rec_off:X}: 文本缺少 2 字节终止符")
    if b"\x00" in body:
        raise ScriptError(f"0x{rec_off:X}: 文本中间出现 NUL")
    for b in blob[len(body) + 2:]:
        if b != 0:
            raise ScriptError(f"0x{rec_off:X}: 文本填充非零")


# ---------------------------------------------------------------------------
# 文本编码 / 转义
# ---------------------------------------------------------------------------

def decode_text(blob: bytes, encoding: str = DEFAULT_ENCODING) -> str:
    """把文本单元解码成 Python 字符串（不处理转义）。"""
    body = blob.rstrip(b"\x00")
    if len(body) + 2 > len(blob):
        raise ScriptError("文本缺少终止符")
    text = body.decode(encoding, errors="surrogateescape")
    out = []
    for ch in text:
        code = ord(ch)
        if 0xDC80 <= code <= 0xDCFF:
            out.append("{{%02X}}" % (code - 0xDC00))
        else:
            out.append(ch)
    return "".join(out)


def encode_text(text: str, encoding: str = DEFAULT_ENCODING) -> bytes:
    """把语义文本编码成字节；{{XX}} 占位符表示单字节。"""
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            if i + 1 < len(text) and text[i + 1] in ('\\', '"'):
                out += text[i + 1].encode(encoding)
                i += 2
                continue
            raise ScriptError("非法转义：反斜杠后只能是 \\ 或 \"")
        if ch == '"':
            raise ScriptError("字符串中出现未转义的双引号")
        if ch == "{" and i + 3 < len(text) and text[i + 1] == "{":
            j = text.find("}}", i + 2)
            if j == -1:
                raise ScriptError("占位符缺少 }}")
            body = text[i + 2:j]
            if len(body) == 2:
                try:
                    out.append(int(body, 16))
                except ValueError:
                    raise ScriptError("非法占位符 {{" + body + "}}") from None
                i = j + 2
                continue
            raise ScriptError("无法识别的占位符 {{" + body + "}}")
        try:
            out += ch.encode(encoding)
        except UnicodeEncodeError:
            raise ScriptError(
                "文本中的字符 %r 无法用 %s 编码（请改用全角字符或翻译成中文）"
                % (ch, encoding)) from None
        i += 1
    return bytes(out)


def escape_text(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "{":
            out.append("{{7B}}")
        elif ch == "}":
            out.append("{{7D}}")
        elif o < 0x20 or o == 0x7F:
            out.append("{{%02X}}" % o)
        else:
            out.append(ch)
    return "".join(out)


def unescape_text(s: str) -> str:
    """把 asm 中的转义写法还原为 Python 字符串（占位符保留为 \\xNN 字符）。"""
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in ('\\', '"'):
            out.append(s[i + 1])
            i += 2
            continue
        if s[i] == "{" and s.startswith("{{", i):
            j = s.find("}}", i + 2)
            if j != -1:
                body = s[i + 2:j]
                if len(body) == 2:
                    try:
                        out.append(chr(int(body, 16)))
                        i = j + 2
                        continue
                    except ValueError:
                        pass
        out.append(s[i])
        i += 1
    return "".join(out)


def format_value(v: int) -> str:
    return "0x%X" % v
