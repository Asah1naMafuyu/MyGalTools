# -*- coding: utf-8 -*-
"""
scb_format.py -- MIBOUJIN.SCB 容器层（供 scb_tool / disassembler / assembler 共用）

结构：
    0x00 u32 file_size | 0x04 u32 count | 0x08 u32 table_size | 0x0C u32 max_block_size
    0x10 count 条：{u32 block_offset, u8 record_len, u8[record_len-1] 文本}
    之后 count 个：{u32 block_size, u8[block_size-4] 脚本}
"""

from __future__ import annotations

import struct
from pathlib import Path

HEADER_SIZE = 0x10
ALIGN = 4


class ScbError(Exception):
    pass


def decode_text(raw: bytes, encoding: str = "cp932") -> str:
    try:
        return raw.rstrip(b"\x00").decode(encoding)
    except UnicodeDecodeError:
        return raw.rstrip(b"\x00").decode(encoding, errors="backslashreplace")


def encode_title(text: str, encoding: str = "cp932", rec_len: int | None = None) -> bytes:
    """标题 -> 字符串记录负载（含结尾 0x00）。rec_len 为原表项 record_len，
    用于保持原字符串表的定长布局（游戏按固定长度读表）。"""
    try:
        raw = text.encode(encoding) + b"\x00"
    except UnicodeEncodeError:
        raw = text.encode(encoding, errors="replace") + b"\x00"
    if rec_len and len(raw) < rec_len - 1:
        raw += b"\x00" * (rec_len - 1 - len(raw))
    while (4 + 1 + len(raw)) % ALIGN != 0:
        raw += b"\x00"
    if len(raw) > 0xFE:
        raise ScbError("标题过长: %r" % text[:20])
    return raw


def pad_block(payload: bytes) -> bytes:
    pad = (-len(payload)) % ALIGN
    return payload + b"\x00" * pad


_INVALID_CHARS = set('<>:"/\\|?*')
_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"} | {
    "%s%d" % (p, i) for p in ("COM", "LPT") for i in range(1, 10)
}


def safe_name(text: str, index: int) -> str:
    name = "".join(
        "_" if (ch in _INVALID_CHARS or ord(ch) < 0x20 or ord(ch) == 0x7F) else ch
        for ch in text.strip()
    )
    name = name.strip(" .")
    if not name:
        name = "segment_%03d" % index
    if name.split(".")[0].upper() in _RESERVED_NAMES:
        name = "_" + name
    return name


class ScbFile:
    def __init__(self, data: bytes, encoding: str = "cp932"):
        self.encoding = encoding
        self.data = data
        if len(data) < HEADER_SIZE:
            raise ScbError("文件小于 16 字节")
        self.file_size, self.count, self.table_size, self.max_block_size = struct.unpack_from(
            "<4I", data, 0)
        if self.file_size != len(data):
            raise ScbError("file_size 0x%X != 实际 0x%X" % (self.file_size, len(data)))
        if not (0 < self.count <= 0x10000):
            raise ScbError("条目数异常: %d" % self.count)
        if self.table_size % ALIGN:
            raise ScbError("table_size 未对齐")
        self.data_offset = HEADER_SIZE + self.table_size
        if self.data_offset > len(data):
            raise ScbError("字符串表越界")
        self.entries = self._parse_table()
        self.blocks = self._parse_blocks()
        self._validate()

    @classmethod
    def from_path(cls, path, encoding: str = "cp932"):
        return cls(Path(path).read_bytes(), encoding)

    def _parse_table(self):
        out = []
        pos = HEADER_SIZE
        end = self.data_offset
        for i in range(self.count):
            if pos + 5 > end:
                raise ScbError("表项 %d 越界" % i)
            off = struct.unpack_from("<I", self.data, pos)[0]
            rec_len = self.data[pos + 4]
            if rec_len < 5 or (4 + rec_len) % ALIGN:
                raise ScbError("表项 %d record_len 非法: %d" % (i, rec_len))
            if pos + 4 + rec_len > end:
                raise ScbError("表项 %d 越过表尾" % i)
            out.append({
                "index": i,
                "block_offset": off,
                "record_size": 4 + rec_len,
                "payload": self.data[pos + 5:pos + 4 + rec_len],
            })
            pos += 4 + rec_len
        if pos != end:
            # 字符串表尾部允许 0 填充（把 data_offset 对齐到 0x100）
            if any(b != 0 for b in self.data[pos:end]):
                raise ScbError("表解析结束 0x%X != 0x%X" % (pos, end))
        return out

    def _parse_blocks(self):
        out = []
        pos = self.data_offset
        for i in range(self.count):
            if pos + 4 > len(self.data):
                raise ScbError("块 %d 越界" % i)
            size = struct.unpack_from("<I", self.data, pos)[0]
            if size < 4 or size % ALIGN:
                raise ScbError("块 %d 长度非法: 0x%X" % (i, size))
            if pos + size > len(self.data):
                raise ScbError("块 %d 越过文件尾" % i)
            out.append({
                "index": i,
                "offset": pos,
                "size": size,
                "payload": self.data[pos + 4:pos + size],
            })
            pos += size
        if pos != len(self.data):
            raise ScbError("块解析结束 0x%X != 0x%X" % (pos, len(self.data)))
        return out

    def _validate(self):
        if [e["block_offset"] for e in self.entries] != [b["offset"] for b in self.blocks]:
            raise ScbError("表项 block_offset 与块偏移不一致")
        if self.max_block_size != max(b["size"] for b in self.blocks):
            raise ScbError("max_block_size 不一致")

    def names(self):
        used = set()
        out = []
        for e in self.entries:
            base = safe_name(decode_text(e["payload"], self.encoding), e["index"])
            name = base
            k = 2
            while name.casefold() in used:
                name = "%s_%d" % (base, k)
                k += 1
            used.add(name.casefold())
            out.append(name)
        return out


def build(entries, blocks, encoding: str = "cp932") -> bytes:
    """entries: 字符串记录负载列表；blocks: 脚本负载列表。"""
    if len(entries) != len(blocks):
        raise ScbError("表项数 %d 与块数 %d 不一致" % (len(entries), len(blocks)))
    count = len(entries)

    table = bytearray()
    positions = []
    for payload in entries:
        rec_len = 1 + len(payload)
        if rec_len > 0xFF:
            raise ScbError("字符串记录过长")
        positions.append(len(table))
        table += b"\x00\x00\x00\x00"
        table += bytes([rec_len])
        table += payload

    table_size = len(table)
    # 原版 data_offset = 0xA00。游戏内脚本加载按这个边界取块；
    # 表变短时补 0 到 0x100 边界，保持块从 0xA00 开始。
    data_offset = HEADER_SIZE + table_size
    pad = (-data_offset) % 0x100
    if pad:
        table += b"\x00" * pad
        table_size += pad
        data_offset += pad

    blocks_area = bytearray()
    max_block = 0
    pos = data_offset
    for i, payload in enumerate(blocks):
        payload = pad_block(payload)
        size = 4 + len(payload)
        struct.pack_into("<I", table, positions[i], pos)
        blocks_area += struct.pack("<I", size) + payload
        max_block = max(max_block, size)
        pos += size

    total = HEADER_SIZE + table_size + len(blocks_area)
    header = struct.pack("<4I", total, count, table_size, max_block)
    return header + bytes(table) + bytes(blocks_area)
