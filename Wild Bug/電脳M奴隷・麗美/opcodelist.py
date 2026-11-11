# -*- coding: utf-8 -*-
"""
opcodelist.py -- WBUG_SCN v0.3 (WILD_BUG / REIMI) script bytecode definition.

This module is the single source of truth for disassembler.py / assembler.py.

Everything here was derived from REIMI.EXE (see exe/REIMI_ida_pseudocode.c and
vm_analysis.md):

  * loader / header         sub_426F86
  * VM main loop            sub_4291CD
  * byte reader             sub_427643   (4-byte little-endian dword buffer)
  * operand parser          sub_4276FE   (descriptor + immediate)
  * operand get / set       sub_427952 / sub_427DE1
  * core opcode dispatch    sub_428E41
  * host command dispatch   sub_406622 -> sub_41FFE0
"""

MAGIC = b"WBUG_SCN v0.3 \x1a\x00"
HEADER_SIZE = 0x38

# ---------------------------------------------------------------------------
# header field layout (10 dwords after the 16-byte magic)
# ---------------------------------------------------------------------------
HEADER_FIELDS = (
    ("flags", 0x10),        # bit0: extra block + per-instruction line info
                            # bit1: entry-point name table present
    ("entry", 0x14),        # default entry offset (code relative)
    ("code_off", 0x18),
    ("code_size", 0x1C),
    ("data_off", 0x20),
    ("data_size", 0x24),
    ("name_off", 0x28),     # 0xFFFFFFFF when absent
    ("name_count", 0x2C),
    ("extra_off", 0x30),    # 0xFFFFFFFF when absent
    ("extra_size", 0x34),
)

# ---------------------------------------------------------------------------
# operand addressing modes -- descriptor byte high nibble
# ---------------------------------------------------------------------------
# read:   what sub_427952 yields for the operand
# write:  where sub_427DE1 stores the result
MODES = {
    0x0: {"name": "imm",     "desc": "immediate value"},
    0x1: {"name": "addr",    "desc": "absolute code address (4-byte aligned)"},
    0x2: {"name": "data",    "desc": "offset into the script data segment"},
    0x3: {"name": "var",     "desc": "script variable slot (dword_48B444[index])"},
    0x4: {"name": "bit",     "desc": "bit <index> of the data segment"},
    0x5: {"name": "dbyte",   "desc": "signed byte at data[index]"},
    0x6: {"name": "dword",   "desc": "dword at data[index]"},
    0x7: {"name": "dword0",  "desc": "dword at data[index], clamped to >= 0"},
    0x8: {"name": "dbit",    "desc": "bit <data[index]> of the data segment"},
    0x9: {"name": "dbyte2",  "desc": "signed byte at data[data[index]]"},
    0xA: {"name": "dword2",  "desc": "dword at data[data[index]]"},
    0xB: {"name": "dword2_0", "desc": "dword at data[data[index]], clamped"},
    0xC: {"name": "bit2",    "desc": "bit <index> of the data segment (alias)"},
    0xD: {"name": "dbyte3",  "desc": "signed byte at data[index] (alias)"},
    0xE: {"name": "dword3",  "desc": "dword at data[index] (alias)"},
    0xF: {"name": "dword3_0", "desc": "dword at data[index], clamped (alias)"},
}

# ---------------------------------------------------------------------------
# immediate kinds -- descriptor byte low nibble
# ---------------------------------------------------------------------------
# (name, byte length, signed)
KINDS = {
    0x0: ("u8", 1, False),
    0x1: ("u16", 2, False),
    0x2: ("u24", 3, False),
    0x3: ("u32", 4, False),      # read at the next dword boundary
    0x4: ("i8", 1, True),
    0x5: ("i16", 2, True),
    0x6: ("i24", 3, True),
    0xD: ("one", 0, False),      # constant 1
    0xE: ("zero", 0, False),     # constant 0
    0xF: ("minus1", 0, False),   # constant -1
}

# kinds that carry an explicit value in the stream
EXPLICIT_KINDS = (0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6)

KIND_VALUES = {0xD: 1, 0xE: 0, 0xF: -1}


def kind_for_value(value, mode=None):
    """Canonical immediate kind for a value (this is what the compiler emits)."""
    if value == 1:
        return 0xD
    if value == 0:
        return 0xE
    if value == -1:
        return 0xF
    if value >= 0:
        if value <= 0xFF:
            return 0x0
        if value <= 0xFFFF:
            return 0x1
        if value <= 0xFFFFFF:
            return 0x2
        return 0x3
    if value >= -0x80:
        return 0x4
    if value >= -0x8000:
        return 0x5
    if value >= -0x800000:
        return 0x6
    return 0x3


# ---------------------------------------------------------------------------
# core opcodes 0x00..0x3F (interpreter level, sub_428E41)
# ---------------------------------------------------------------------------
CORE_OPCODES = {
    0x00: {"mnemonic": "END",    "args": 0, "desc": "terminator emitted after the last statement"},
    0x01: {"mnemonic": "SYS01",  "args": 2, "desc": "host callback 258 (unused)"},
    0x02: {"mnemonic": "MOV",    "args": 2, "desc": "dst = src"},
    0x04: {"mnemonic": "SETM1",  "args": 1, "desc": "dst = -1 (true)"},
    0x05: {"mnemonic": "SET0",   "args": 1, "desc": "dst = 0 (false)"},
    0x06: {"mnemonic": "FILL",   "args": 3, "desc": "fill dst[lo..hi] with value"},
    0x08: {"mnemonic": "ADD",    "args": 2, "desc": "dst += src"},
    0x09: {"mnemonic": "SUB",    "args": 2, "desc": "dst -= src"},
    0x0A: {"mnemonic": "MUL",    "args": 2, "desc": "dst *= src"},
    0x0B: {"mnemonic": "DIV",    "args": 2, "desc": "dst /= src"},
    0x0C: {"mnemonic": "MOD",    "args": 2, "desc": "dst %= src"},
    0x0D: {"mnemonic": "NEG",    "args": 1, "desc": "dst = -dst"},
    0x10: {"mnemonic": "AND",    "args": 2, "desc": "dst &= src"},
    0x11: {"mnemonic": "OR",     "args": 2, "desc": "dst |= src"},
    0x12: {"mnemonic": "XOR",    "args": 2, "desc": "dst ^= src"},
    0x13: {"mnemonic": "NOT",    "args": 1, "desc": "dst = ~dst"},
    0x18: {"mnemonic": "ROT",    "args": 2, "desc": "rotate dst by src (direction depends on operand type)"},
    0x19: {"mnemonic": "ROTR",   "args": 2, "desc": "rotate dst by src (reverse direction)"},
    0x1A: {"mnemonic": "SHL",    "args": 2, "desc": "dst <<= src"},
    0x1B: {"mnemonic": "SHR",    "args": 2, "desc": "dst = dst >> src (logical / arithmetic by type)"},
    0x20: {"mnemonic": "TRUE",   "args": 3, "desc": "dst = 1"},
    0x21: {"mnemonic": "EQ",     "args": 3, "desc": "dst = (a == b)"},
    0x22: {"mnemonic": "GT",     "args": 3, "desc": "dst = (a > b)"},
    0x23: {"mnemonic": "LT",     "args": 3, "desc": "dst = (a < b)"},
    0x27: {"mnemonic": "NAND",   "args": 3, "desc": "dst = !(a && b)"},
    0x28: {"mnemonic": "ANDL",   "args": 3, "desc": "dst = (a && b)"},
    0x2C: {"mnemonic": "GE",     "args": 3, "desc": "dst = (a >= b)"},
    0x2D: {"mnemonic": "LE",     "args": 3, "desc": "dst = (a <= b)"},
    0x2E: {"mnemonic": "NE",     "args": 3, "desc": "dst = (a != b)"},
    0x2F: {"mnemonic": "FALSE",  "args": 3, "desc": "dst = 0"},
    0x30: {"mnemonic": "JMP",    "args": 1, "desc": "jump to code address"},
    0x31: {"mnemonic": "JZ",     "args": 2, "desc": "jump to address when condition is false"},
    0x32: {"mnemonic": "JNZ",    "args": 2, "desc": "jump to address when condition is true"},
    0x33: {"mnemonic": "CALL",   "args": 1, "desc": "call subroutine at code address"},
    0x34: {"mnemonic": "CALLN",  "args": 1, "desc": "call script/section by name (push frame)"},
    0x35: {"mnemonic": "CALLN2", "args": 2, "desc": "call script/section by name + label"},
    0x36: {"mnemonic": "CALLF",  "args": 1, "desc": "call by name without frame"},
    0x37: {"mnemonic": "CALLF2", "args": 2, "desc": "call by name + label without frame"},
    0x3C: {"mnemonic": "RET",    "args": 0, "desc": "return from subroutine"},
    0x3D: {"mnemonic": "RETV",   "args": 1, "desc": "return with result value"},
    0x3E: {"mnemonic": "HALT",   "args": 0, "desc": "stop the script"},
    0x3F: {"mnemonic": "NOP",    "args": 0, "desc": "no operation / alignment filler"},
}

# ---------------------------------------------------------------------------
# host commands 0x40..0xFE (implemented by the game, sub_41FFE0)
# only the ones whose purpose is confirmed by the handler are named; the rest
# keep a stable SYS_xx name so that they still round-trip and can be identified
# by address in vm_analysis.md.
# ---------------------------------------------------------------------------
_HOST_NAMES = {
    0x40: ("REGIST_MSG_FRAME", "RegistMessageFrame"),
    0x48: ("MENU_ENTRY", None),
    0x50: ("TEXT_SELECT", None),
    0x70: ("SYS_70", None),
    0x80: ("MESSAGE", "MessageOut"),
    0x81: ("MESSAGE_ON", "MessageOn"),
    0x82: ("MESSAGE_OFF", "MessageOff"),
    0x83: ("MESSAGE_PAGE", "MassagePageRenew"),
    0x84: ("MESSAGE_MOVE", "MessageMove"),
    0x86: ("MESSAGE_SELECT", "MessageSelect"),
    0x87: ("MESSAGE_WAVE", "MessageWave"),
    0x8A: ("MESSAGE_RELEASE", "MessageRelease"),
    0x90: ("BODY_O_L_CHANGE", "BodyOLChange"),
    0x91: ("BODY_RELEASE", "BodyRelease"),
    0x92: ("BODY_DISP", "BodyDisp"),
    0x93: ("BODY_MOVE", "BodyMove"),
    0x97: ("BITMAP_RELEASE", "BitmapRelease"),
    0x98: ("BITMAP_BLT", "BitmapBlt"),
    0x9A: ("SPRT_SETUP_UNI", "SprtSetupUniBitmap"),
    0xA0: ("SPRT_RELEASE", "SprtRelease"),
    0xA1: ("SPRT_INFO_GET", "SprtInfoGet"),
    0xA2: ("SPRT_DISP", "SprtDisp"),
    0xA5: ("SPRT_MOVE", "SprtMove"),
    0xA8: ("SPRT_ATT_CHANGE", "SprtAttChange"),
    0xA9: ("SPRT_OL_DISP", "Sprt(Body)OLDisp"),
    0xB4: ("SPRT_MULTI_DM", "SprtMultiDMEntry"),
    0xFB: ("SYS_FB", None),
    0xFC: ("SYS_FC", None),
}

HOST_OPCODES = {}
for op in range(0x40, 0xFF):
    if op in _HOST_NAMES:
        name, official = _HOST_NAMES[op]
    else:
        name, official = "SYS_%02X" % op, None
        if op >= 0x40:
            name = "SYS_%02X" % op
    HOST_OPCODES[op] = {
        "mnemonic": name,
        "args": None,          # taken from the instruction stream
        "desc": "host command%s" % ((" (official: %s)" % official) if official else " (unverified)"),
        "official": official,
    }

# 0xFF: sub_428E41 a2 > 62 && a2 != 63 path -> halt with callback 257
HOST_OPCODES[0xFF] = {"mnemonic": "STOP", "args": None,
                      "desc": "terminate the interpreter loop", "official": None}

OPCODES = {}
OPCODES.update(CORE_OPCODES)
OPCODES.update(HOST_OPCODES)

# reserved / illegal core opcodes (the interpreter raises error 22/19 for them)
for _op in (0x03, 0x07, 0x0E, 0x0F, 0x14, 0x15, 0x16, 0x17,
            0x1C, 0x1D, 0x1E, 0x1F, 0x24, 0x25, 0x26, 0x29, 0x2A, 0x2B,
            0x38, 0x39, 0x3A, 0x3B):
    OPCODES[_op] = {"mnemonic": "UNUSED_%02X" % _op, "args": None,
                    "desc": "reserved: the interpreter rejects this opcode"}

MNEMONICS = {}
for _op, _info in OPCODES.items():
    MNEMONICS[_info["mnemonic"]] = _op

# instructions whose address operand must be encoded as a 4-byte value and
# whose data operand is always a 4-byte text pointer (compiler convention)
FORCED_KIND = {
    (0x80, 0): 0x3,   # MESSAGE text pointer
}

# opcodes whose first operand is an absolute code address (label target)
BRANCH_OPS = {0x30, 0x31, 0x32, 0x33}
COND_BRANCH_OPS = {0x31, 0x32}


def get_opcode(op):
    """Return the opcode descriptor for a raw byte."""
    return OPCODES.get(op)


def mnemonic(op):
    info = OPCODES.get(op)
    return info["mnemonic"] if info else "DB_%02X" % op


def opcode_of(mnemonic):
    return MNEMONICS.get(mnemonic)
