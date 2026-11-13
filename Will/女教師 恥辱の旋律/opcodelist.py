# -*- coding: utf-8 -*-
"""opcodelist.py - Will Co. WARC (.scr) 字节码指令集定义。

完整 VM 分析（执行模型、边界规则、文本/跳转策略、跨版本复用注意事项）见
`vm_analysis.md`；本文件是它的可执行版本，二者必须同步修改。

指令集由 Chijyoku.exe 的脚本 VM（sub_405160, 0x00405160）静态逆向得到：
每个 opcode 的指针推进量、操作数位置均取自该函数的 switch 分支。

字段类型:
    u8 / u16 / u32 : 小端整数
    str            : NUL 结尾的字符串（按 .encoding 编码）
    rel32          : 4 字节有符号偏移，目标 = 指令末地址 + 值
    abs32          : 4 字节绝对偏移（相对脚本起点），目标 = 值
    select         : 0x02 专属的多行选择块，单独处理

本表覆盖从 122 个脚本中实际出现的全部 opcode（89 个）。
未出现在样本中的字节在反汇编时会报错，而不会静默跳过。
"""

# 仅占位、语义未完全确认的 opcode 使用 raw 字段，按字节原样保留。
def raw(n):
    return [("b%d" % (i + 1), "u8") for i in range(n)]


OPCODES = {
    # ---- 控制流 ----
    0x00: {"name": "NOP",    "fields": []},
    0x01: {"name": "IF",     "fields": [("flags", "u8"), ("lhs", "u16"),
                                        ("rhs", "u16"), ("target", "rel32"),
                                        ("pad", "u8")]},
    0x02: {"name": "SELECT", "fields": [("b1", "u8"), ("count", "u8")],
           "special": "select"},
    0x03: {"name": "VAR",    "fields": [("sub", "u8"), ("lhs", "u16"),
                                        ("flags", "u8"), ("rhs", "u16"),
                                        ("pad", "u8")]},
    0x04: {"name": "EXIT",   "fields": []},
    0x05: {"name": "WAIT",   "fields": [("id", "u8")]},
    0x06: {"name": "GOTO",   "fields": [("target", "abs32")]},
    0x07: {"name": "CHANGE", "fields": [("script", "str")]},
    0x08: {"name": "SET08",  "fields": [("v", "u8"), ("pad", "u8")]},
    0x09: {"name": "CALL",   "fields": [("script", "str")]},
    0x0A: {"name": "RET",    "fields": []},
    0x0B: {"name": "DELAY",  "fields": [("tick", "u8"), ("pad", "u8")]},
    0x0C: {"name": "CMPVAR", "fields": [("var", "u16"), ("pad", "u8")]},

    # ---- 消息 / 语音 / 画面 ----
    0x21: {"name": "MSG21",  "fields": [("a", "u8"), ("b", "u8"),
                                        ("c", "u8"), ("text", "str")]},
    0x22: {"name": "CMD22",  "fields": [("a", "u32")]},
    0x23: {"name": "VOICE",  "fields": [("flags", "u8"), ("a", "u16"),
                                        ("b", "u16"), ("c", "u16"),
                                        ("file", "str")]},
    0x24: {"name": "CMD24",  "fields": [("a", "u8")]},
    0x25: {"name": "PLAYSE", "fields": [("a", "u8"), ("b", "u8"),
                                        ("c", "u8"), ("d", "u8"),
                                        ("file", "str")]},
    0x26: {"name": "CMD26",  "fields": [("a", "u16")]},
    0x41: {"name": "TEXT",   "fields": [("voice", "u16"), ("flag", "u8"),
                                        ("text", "str")]},
    0x42: {"name": "SAY",    "fields": [("msgid", "u16"), ("b", "u8"),
                                        ("c", "u8"), ("name", "str"),
                                        ("text", "str")]},
    0x43: {"name": "CHAR",   "fields": [("layer", "u8"), ("x", "u16"),
                                        ("y", "u16"), ("flags", "u8"),
                                        ("file", "str")]},
    0x44: {"name": "LAYER44", "fields": raw(4)},
    0x45: {"name": "CMD45",  "fields": [("a", "u32")]},
    0x46: {"name": "BG",     "fields": [("a", "u8"), ("b", "u16"),
                                        ("c", "u16"), ("d", "u16"),
                                        ("e", "u16"), ("file", "str")]},
    0x47: {"name": "CMD47",  "fields": [("a", "u16")]},
    0x48: {"name": "BG48",   "fields": [("a", "u8"), ("b", "u16"),
                                        ("c", "u16"), ("d", "u16"),
                                        ("e", "u16"), ("f", "u8"),
                                        ("file", "str")]},
    0x49: {"name": "FLAG49", "fields": raw(3)},
    0x4A: {"name": "CMD4A",  "fields": [("a", "u32")]},
    0x4B: {"name": "CMD4B",  "fields": raw(10)},
    0x4C: {"name": "CMD4C",  "fields": [("a", "u8")]},
    0x4D: {"name": "CMD4D",  "fields": raw(5)},
    0x4E: {"name": "CMD4E",  "fields": raw(3)},
    0x4F: {"name": "LAYER4F", "fields": raw(4)},
    0x50: {"name": "RES50",  "fields": [("file", "str")]},
    0x51: {"name": "CMD51",  "fields": [("a", "u16"), ("b", "u16"),
                                        ("c", "u8")]},
    0x52: {"name": "CMD52",  "fields": [("a", "u16")]},
    0x53: {"name": "RES53",  "fields": [("a", "u8"), ("b", "u16"),
                                        ("c", "u16"), ("file", "str")]},
    0x54: {"name": "MASK54", "fields": [("file", "str")]},
    0x55: {"name": "CMD55",  "fields": [("a", "u8")]},
    0x56: {"name": "CMD56",  "fields": [("a", "u8")]},
    0x57: {"name": "CMD57",  "fields": raw(9)},
    0x58: {"name": "CMD58",  "fields": raw(8)},
    0x59: {"name": "RES59",  "fields": [("file", "str")]},
    0x60: {"name": "CMD60",  "fields": [("a", "u8")]},
    0x61: {"name": "RES61",  "fields": [("a", "u8"), ("file", "str")]},
    0x62: {"name": "CMD62",  "fields": [("a", "u8")]},
    0x63: {"name": "CMD63",  "fields": raw(3)},
    0x64: {"name": "CMD64",  "fields": raw(4)},
    0x65: {"name": "CMD65",  "fields": raw(5)},
    0x66: {"name": "CMD66",  "fields": raw(8)},
    0x67: {"name": "CMD67",  "fields": [("a", "u8")]},
    0x68: {"name": "CMD68",  "fields": raw(7)},
    0x69: {"name": "CMD69",  "fields": raw(2)},
    0x70: {"name": "CMD70",  "fields": [("a", "u8")]},
    0x71: {"name": "RES71",  "fields": [("file", "str")]},
    0x72: {"name": "CMD72",  "fields": [("a", "u8")]},
    0x73: {"name": "RES73",  "fields": [("a", "u8"), ("b", "u16"),
                                        ("c", "u16"), ("d", "u16"),
                                        ("e", "u16"), ("file", "str")]},
    0x74: {"name": "CMD74",  "fields": raw(2)},
    0x75: {"name": "CMD75",  "fields": raw(9)},
    0x76: {"name": "CMD76",  "fields": raw(9)},
    0x77: {"name": "CMD77",  "fields": raw(9)},
    0x78: {"name": "CMD78",  "fields": raw(8)},
    0x79: {"name": "CMD79",  "fields": [("a", "u8")]},
    0x81: {"name": "CMD81",  "fields": raw(2)},
    0x82: {"name": "CMD82",  "fields": [("a", "u8")]},
    0x83: {"name": "CMD83",  "fields": [("a", "u8")]},
    0x84: {"name": "CMD84",  "fields": [("a", "u8")]},
    0x85: {"name": "CMD85",  "fields": raw(2)},
    0x86: {"name": "CMD86",  "fields": raw(2)},
    0x87: {"name": "CMD87",  "fields": raw(3)},
    0x88: {"name": "CMD88",  "fields": raw(2)},
    0x89: {"name": "CMD89",  "fields": [("a", "u8")]},
    0x8A: {"name": "CMD8A",  "fields": [("a", "u16")]},
    0x8B: {"name": "CMD8B",  "fields": [("a", "u8")]},
    0x8C: {"name": "CMD8C",  "fields": raw(3)},
    0x8D: {"name": "CMD8D",  "fields": [("a", "u8")]},
    0x8E: {"name": "CMD8E",  "fields": [("a", "u8")]},
    0xB1: {"name": "CMDB1",  "fields": [("a", "u16"), ("b", "u16"),
                                        ("c", "u8")]},
    0xB2: {"name": "RESB2",  "fields": [("a", "u8"), ("b", "u8"),
                                        ("file", "str")]},
    0xB3: {"name": "CMDB3",  "fields": [("a", "u16")]},
    0xB4: {"name": "CMDB4",  "fields": raw(12)},
    0xB5: {"name": "CMDB5",  "fields": raw(2)},
    0xB6: {"name": "RESB6",  "fields": [("a", "u8"), ("b", "u8"),
                                        ("file", "str")]},
    0xE0: {"name": "RESE0",  "fields": [("file", "str")]},
    0xE1: {"name": "CMDE1",  "fields": [("a", "u8")]},
    0xE2: {"name": "CMDE2",  "fields": [("a", "u8")]},
    0xE3: {"name": "CMDE3",  "fields": [("a", "u8")]},
    0xE4: {"name": "CMDE4",  "fields": raw(2)},
    0xE5: {"name": "CMDE5",  "fields": [("a", "u8")]},
    0xFF: {"name": "END",    "fields": []},
}

# 0x02 选择块中每个选项的类型
SELECT_TYPES = {
    3: "条件选项",
    6: "延时选项",
    7: "跳转选项",
}


def instruction_length(op, data, pos, decode_str):
    """返回该指令的字节长度。decode_str(bytes)->str 用于取字符串长度。

    解析失败时抛 ValueError（包含 opcode 与偏移）。
    """
    info = OPCODES.get(op)
    if info is None:
        raise ValueError("未知 opcode 0x%02X @ 0x%X" % (op, pos))
    if info.get("special") == "select":
        count = data[pos + 1]
        q = pos + 3
        for _ in range(count):
            q += 2
            q = data.index(b"\x00", q) + 1
            t = data[q]
            q += 1
            if t == 3:
                q += 7
            elif t == 6:
                q += 5
            elif t == 7:
                q = data.index(b"\x00", q) + 1
            else:
                raise ValueError("SELECT 选项类型 %d 未知 @ 0x%X" % (t, q - 1))
        return q - pos
    size = 1
    for _, typ in info["fields"]:
        if typ == "str":
            size += data.index(b"\x00", pos + size) - (pos + size) + 1
        elif typ == "u8":
            size += 1
        elif typ == "u16":
            size += 2
        elif typ in ("u32", "rel32", "abs32"):
            size += 4
        else:
            raise ValueError("字段类型 %r 不支持" % typ)
    return size
