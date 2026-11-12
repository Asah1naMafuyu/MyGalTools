# -*- coding: utf-8 -*-
"""
opcodelist.py - MIBOUJIN（Tanaka 引擎）SCB 脚本指令集定义

指令编码（由 MIBOUJIN.EXE 的脚本编译器 sub_410D70 与 100 个脚本样本验证）：

    每条指令 = [u8 length][u8 command][operands...]
    length  = 整条指令字节数（含 length 与 command 自身）
    command = ASCII 命令字符（部分为控制码 0x09）
    脚本以 0x00 结束；结束符之后可能还有少量对齐/残留字节，原样保留。

长度字段是自描述的，因此反汇编不依赖固定长度表；operands 的字段划分来自
样本统计（100 个脚本、约 8000 条指令全部吻合）与编译器代码交叉验证。
"""

# 文本类命令：operands = CP932 文本 + 结尾 0x00
TEXT_COMMANDS = {
    0x09: "TEXT",      # 正文/对白
    0x25: "SPEAKER",   # 说话人名牌，如【由希】
    0x2F: "TITLE",     # 场景/分支标题
    0x3A: "SCENE",     # 场景名（chapter1 等）
    0x3E: "ENDING",    # 结局标题
}

OPCODES = {
    0x09: {
        "mnemonic": "TEXT",
        "operands": [{"type": "text"}],
        "desc": "正文/对白；CP932，末尾 0x00 由汇编器补回",
    },
    0x21: {
        "mnemonic": "LABEL",
        "operands": [{"type": "u8"}, {"type": "u8"}, {"type": "text"}],
        "desc": "章节/场景标签；前缀 2 字节（00 00 / 00 40 / 21 40）",
    },
    0x23: {
        "mnemonic": "CHAR",
        "operands": [{"type": "name4"}, {"type": "u16"}, {"type": "u16"}, {"type": "u16"}],
        "desc": "角色定义：4 字节代码 + 3 个 u16（编号/类型/标志）",
    },
    0x24: {
        "mnemonic": "ANGLE",
        "operands": [{"type": "u16"}, {"type": "u16"}, {"type": "cstr"},
                     {"type": "cstr"}, {"type": "cstr"}],
        "desc": "多角度/多视点定义：两个 u16 + 三个 C 字符串",
    },
    0x25: {
        "mnemonic": "SPEAKER",
        "operands": [{"type": "text"}],
        "desc": "说话人名牌文本",
    },
    0x2E: {
        "mnemonic": "IF",
        "operands": [{"type": "sub"}],
        "desc": "条件/控制指令；子码 1=内嵌 F/R 判断，5/6=u16，其余=单字节码",
        "sub_opcodes": {
            0x01: "内嵌判断（F 标志或 R 变量）",
            0x05: "带 u16 参数",
            0x06: "带 u16 参数",
            0x03: "单字节码",
            0x08: "单字节码",
            0x09: "单字节码",
            0x0A: "单字节码",
            0x63: "单字节码",
        },
    },
    0x2F: {
        "mnemonic": "TITLE",
        "operands": [{"type": "text"}],
        "desc": "场景/分支标题文本",
    },
    0x3A: {
        "mnemonic": "SCENE",
        "operands": [{"type": "text"}],
        "desc": "场景名文本",
    },
    0x3E: {
        "mnemonic": "ENDING",
        "operands": [{"type": "text"}],
        "desc": "结局标题文本",
    },
    0x40: {
        "mnemonic": "RET",
        "operands": [{"type": "u8"}],
        "desc": "返回/段结束标记；样本中参数恒为 0",
    },
    0x43: {
        "mnemonic": "CMD43",
        "operands": [{"type": "u8"}, {"type": "u8"}],
        "desc": "仅出现 1 次，语义未确认",
    },
    0x46: {
        "mnemonic": "FLAG",
        "operands": [{"type": "op"}, {"type": "u16"}],
        "desc": "标志位运算：F- 清除 / F+ 置位",
    },
    0x47: {
        "mnemonic": "BG",
        "operands": [{"type": "u16"}, {"type": "u16"}, {"type": "u16"},
                     {"type": "cstr"}],
        "desc": "背景/事件资源：3 个 u16 + 资源名（bg_01、EV_01A_1 等）",
    },
    0x52: {
        "mnemonic": "VAR",
        "operands": [{"type": "op"}, {"type": "u16"}, {"type": "u16"}],
        "desc": "变量比较/赋值：R= 变量 值",
    },
    0x57: {
        "mnemonic": "SND",
        "operands": [{"type": "sound"}],
        "desc": "音频：M+u16 音乐编号；V+子类型+名字 语音/音效",
    },
}

# 0x2E 子码 1 内嵌的运算符命令
INLINE_OPS = {
    0x46: "FLAG",
    0x52: "VAR",
}

MENU = [
    ("TEXT", 0x09), ("LABEL", 0x21), ("CHAR", 0x23), ("ANGLE", 0x24),
    ("SPEAKER", 0x25), ("IF", 0x2E), ("TITLE", 0x2F), ("SCENE", 0x3A),
    ("ENDING", 0x3E), ("RET", 0x40), ("CMD43", 0x43), ("FLAG", 0x46),
    ("BG", 0x47), ("VAR", 0x52), ("SND", 0x57),
]
