#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wbp_tool.py -- Wild Bug (WBUG) "ARCFORM2" .WBP archive tool.

Supports the archives used by REIMI (WILL / WILD_BUG, 2000):
    REIMI00.WBP   text / script package  (EX0 / ANI payloads)
    REIMI01.WBP   graphics package       (BMP payloads)

Container layout (reverse engineered from REIMI.EXE, bugarc2.c / bugbmp.c /
extract7 core):

    WBP header, 0x424 bytes
      0x00  char magic[16]        "ARCFORM2 WBUG \\x1A\\x00"
      0x10  u32 file_count
      0x14  u32 index_offset      always 0x424
      0x18  u32 index_size
      0x1C  u32 data_offset       = 0x424 + index_size
      0x20  u32 total_payload     sum of the (padded) file sizes in the index
      0x24  u32 hash[256]         offset of the first index record of a bucket
      index records, sorted by hash bucket:
          u32 offset, u32 size, u8 bucket, u8 name_len, u16 pad,
          u32 time_lo, u32 time_hi, char name[name_len]   (name_len % 4 == 0)
      a 21-byte terminator, then the payloads (each padded to a multiple of 4).

    Every payload is itself a "WPX" container:
      0x00  "WPX\\x1A"
      0x04  char type[4]          "EX0\\0", "ANI\\0", "BMP\\0"
      0x08  u32 table_entry_size  0x10
      0x0C  u8  version (1), u8 reserved (0), u8 entry_count, u8 entry_stride
      0x10  entries: u8 id, u8 method, u32 offset, u32 usize, u32 csize
            id 2  : script / animation payload (method 1 = LZSS, 0x80 = stored)
            id 16 : 16-byte bitmap info block (u16 x6, u8 bpp)
            id 17 : pixel data
            id 18 : 256-colour palette (768 bytes)
            id 19 : extra 8bpp plane
    method: bit7 set -> stored uncompressed; otherwise the low bits select one
    of the "extract7" decoders.  The archives only use method 1, which is a
    bit-packed LZSS with a literal/match flag bit and a gamma coded length.
"""
import argparse
import hashlib
import json
import os
import struct
import sys

MAGIC = b"ARCFORM2 WBUG \x1a\x00"
HDR_SIZE = 0x424
INDEX_TAIL = bytes.fromhex("0000000000000000ad000000000000000000000000")
WPX_MAGIC = b"WPX\x1a"
MAX_DIST = 65536


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def align4(x):
    return (x + 3) & ~3


def name_bytes(name):
    if isinstance(name, bytes):
        return name
    return name.encode("cp932", "replace")


def name_str(b):
    return b.decode("cp932", "replace")


def bucket_of(name):
    nb = name_bytes(name)
    return sum(nb[:4]) & 0xFF


def sha256(b):
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------
# LZSS ("extract7" method 1)
# --------------------------------------------------------------------------
def lzss_decompress(src, out_size, raw_prefix=1, planar=False, dist_table=None):
    """Decode one extract7 method-1 stream.

    raw_prefix bytes are stored verbatim, then the bit stream starts at the
    next 4-byte boundary.  planar=True selects the bitmap decoder
    (sub_43C764) which owns an 8-entry distance table, otherwise the plain
    decoder (sub_43DA8C) is used.
    """
    out = bytearray(src[:raw_prefix])
    pos = align4(raw_prefix)
    n = out_size
    L = len(src)
    bit_buf = 0
    bit_cnt = 0
    while len(out) < n:
        # ---- flag bit -----------------------------------------------------
        if bit_cnt == 0:
            if pos >= L:
                raise ValueError("compressed stream exhausted")
            bit_buf = src[pos]
            pos += 1
            bit_cnt = 8
        flag = bit_buf & 0x80
        bit_buf = (bit_buf << 1) & 0xFF
        bit_cnt -= 1
        if flag:
            if pos >= L:
                raise ValueError("compressed stream exhausted")
            out.append(src[pos])
            pos += 1
            continue
        # ---- distance -----------------------------------------------------
        if bit_cnt == 0:
            if pos >= L:
                raise ValueError("compressed stream exhausted")
            bit_buf = src[pos]
            pos += 1
            bit_cnt = 8
        b1 = bit_buf & 0x80
        bit_buf = (bit_buf << 1) & 0xFF
        bit_cnt -= 1
        if not planar:
            if b1:
                if pos >= L:
                    raise ValueError("compressed stream exhausted")
                dist = src[pos] + 1
                pos += 1
                base = 2
            else:
                if pos + 2 > L:
                    raise ValueError("compressed stream exhausted")
                dist = src[pos] | (src[pos + 1] << 8)
                dist += 1
                pos += 2
                base = 3
        else:
            if b1:
                if bit_cnt == 0:
                    if pos >= L:
                        raise ValueError("compressed stream exhausted")
                    bit_buf = src[pos]
                    pos += 1
                    bit_cnt = 8
                b2 = bit_buf & 0x80
                bit_buf = (bit_buf << 1) & 0xFF
                bit_cnt -= 1
                if b2:
                    if pos >= L:
                        raise ValueError("compressed stream exhausted")
                    dist = src[pos] + 1
                    pos += 1
                    base = 2
                else:
                    if pos + 2 > L:
                        raise ValueError("compressed stream exhausted")
                    dist = (src[pos] | (src[pos + 1] << 8)) + 1
                    pos += 2
                    base = 3
            else:
                # 3-bit index into the bitmap distance table
                idx = 0
                for _ in range(3):
                    if bit_cnt == 0:
                        if pos >= L:
                            raise ValueError("compressed stream exhausted")
                        bit_buf = src[pos]
                        pos += 1
                        bit_cnt = 8
                    idx = (idx << 1) | (1 if (bit_buf & 0x80) else 0)
                    bit_buf = (bit_buf << 1) & 0xFF
                    bit_cnt -= 1
                dist = (dist_table or DIST_TABLE)[idx]
                base = 2 if raw_prefix == 1 else 1
        # ---- length -------------------------------------------------------
        if bit_cnt == 0:
            if pos >= L:
                raise ValueError("compressed stream exhausted")
            bit_buf = src[pos]
            pos += 1
            bit_cnt = 8
        lb = bit_buf & 0x80
        bit_buf = (bit_buf << 1) & 0xFF
        bit_cnt -= 1
        if lb:
            length = base
        else:
            zeros = 0
            while True:
                if bit_cnt == 0:
                    if pos >= L:
                        raise ValueError("compressed stream exhausted")
                    bit_buf = src[pos]
                    pos += 1
                    bit_cnt = 8
                v = bit_buf & 0x80
                bit_buf = (bit_buf << 1) & 0xFF
                bit_cnt -= 1
                if v:
                    break
                zeros += 1
            val = 1
            for _ in range(zeros + 1):
                if bit_cnt == 0:
                    if pos >= L:
                        raise ValueError("compressed stream exhausted")
                    bit_buf = src[pos]
                    pos += 1
                    bit_cnt = 8
                val = (val << 1) | (1 if (bit_buf & 0x80) else 0)
                bit_buf = (bit_buf << 1) & 0xFF
                bit_cnt -= 1
            length = base + val - 1
        src_pos = len(out) - dist
        if dist <= 0 or src_pos < 0:
            raise ValueError("bad match distance %d at offset %d" % (dist, len(out)))
        if src_pos + length <= len(out):
            chunk = out[src_pos:src_pos + length]
            room = n - len(out)
            if len(chunk) > room:
                chunk = chunk[:room]
            out += chunk
        else:
            for i in range(length):
                if len(out) >= n:
                    break
                out.append(out[src_pos + i])
    return bytes(out)


# distance table used by the bitmap decoder (sub_439528 builds it from the
# row stride and the bytes-per-pixel)
DIST_TABLE = [3, 6, 9, 1917, 1920, 1923, 1926, 3840]


def make_dist_table(stride, bpp):
    if 5 * bpp < stride:
        return [bpp, 2 * bpp, 3 * bpp, stride - bpp, stride,
                stride + bpp, stride + 2 * bpp, 2 * stride]
    return [bpp * i for i in range(1, 9)]


class _BitWriter:
    __slots__ = ("out", "flag_pos", "flag_bit", "nbits")

    def __init__(self, prefix):
        self.out = bytearray(prefix)
        self.flag_pos = None
        self.flag_bit = 0
        self.nbits = 0

    def _new_flag(self):
        if self.flag_pos is not None:
            self.out[self.flag_pos] = self.flag_bit
        self.flag_pos = len(self.out)
        self.out.append(0)
        self.flag_bit = 0
        self.nbits = 0

    def bit(self, b):
        if self.nbits == 0:
            self._new_flag()
        if b:
            self.flag_bit |= 0x80 >> self.nbits
        self.nbits += 1
        if self.nbits == 8:
            self.out[self.flag_pos] = self.flag_bit
            self.flag_pos = None
            self.nbits = 0
            self.flag_bit = 0

    def byte(self, b):
        self.out.append(b & 0xFF)

    def finish(self):
        if self.nbits:
            self.out[self.flag_pos] = self.flag_bit
            self.flag_pos = None
            self.nbits = 0
        return bytes(self.out)


def lzss_compress(data, raw_prefix=1, planar=False, max_chain=32):
    """Greedy LZSS encoder producing an extract7 method-1 stream."""
    n = len(data)
    if n <= raw_prefix:
        return data
    prefix = bytes(data[:raw_prefix]) + b"\x00" * (align4(raw_prefix) - raw_prefix)
    bw = _BitWriter(prefix)
    # hash chains over 3-byte keys
    head = {}
    prev = [-1] * n
    i = raw_prefix

    def insert(p):
        if p + 3 <= n:
            key = data[p] | (data[p + 1] << 8) | (data[p + 2] << 16)
            prev[p] = head.get(key, -1)
            head[key] = p

    for p in range(0, raw_prefix):
        insert(p)
    while i < n:
        best_len = 0
        best_dist = 0
        if i + 3 <= n:
            key = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16)
            cand = head.get(key, -1)
            chain = 0
            maxl = n - i
            while cand >= 0 and i - cand <= MAX_DIST and chain < max_chain:
                l = 3
                while l < maxl and data[cand + l] == data[i + l]:
                    l += 1
                if l > best_len:
                    best_len = l
                    best_dist = i - cand
                    if l == maxl:
                        break
                cand = prev[cand]
                chain += 1
        min_len = 2 if 0 < best_dist <= 256 else 3
        if best_len >= min_len:
            bw.bit(0)
            if planar:
                if best_dist <= 256:
                    bw.bit(1)
                    bw.bit(1)
                    bw.byte(best_dist - 1)
                    base = 2
                else:
                    bw.bit(1)
                    bw.bit(0)
                    bw.byte((best_dist - 1) & 0xFF)
                    bw.byte(((best_dist - 1) >> 8) & 0xFF)
                    base = 3
            else:
                if best_dist <= 256:
                    bw.bit(1)
                    bw.byte(best_dist - 1)
                    base = 2
                else:
                    bw.bit(0)
                    bw.byte((best_dist - 1) & 0xFF)
                    bw.byte(((best_dist - 1) >> 8) & 0xFF)
                    base = 3
            if best_len == base:
                bw.bit(1)
            else:
                bw.bit(0)
                val = best_len - base + 1
                nbits = val.bit_length() - 1      # val = 1 + nbits payload bits
                for _ in range(nbits - 1):        # decoder counts zeros, then a 1
                    bw.bit(0)
                bw.bit(1)
                for k in range(nbits - 1, -1, -1):
                    bw.bit((val >> k) & 1)
            for k in range(best_len):
                insert(i + k)
            i += best_len
        else:
            bw.bit(1)
            bw.byte(data[i])
            insert(i)
            i += 1
    return bw.finish()


# --------------------------------------------------------------------------
# WPX container
# --------------------------------------------------------------------------
def parse_wpx(blob):
    if len(blob) < 0x10 or blob[:4] != WPX_MAGIC:
        raise ValueError("not a WPX container")
    typ = blob[4:8]
    b = u32(blob, 8)
    version = blob[12]
    count = blob[14]
    stride = blob[15] or 0x10
    entries = []
    for k in range(count):
        base = 0x10 + k * stride
        e = blob[base:base + stride]
        if len(e) < 16:
            raise ValueError("truncated WPX table")
        off, usize, csize = struct.unpack_from("<III", e, 4)
        entries.append({
            "id": e[0], "method": e[1], "off": off,
            "usize": usize, "csize": csize,
        })
    return {"type": typ, "b": b, "version": version, "stride": stride,
            "entries": entries, "table_end": 0x10 + count * stride}


def build_wpx(type_bytes, b, version, stride, payloads):
    """payloads: list of (id, method, stored_bytes, usize) in table order."""
    if not (1 <= version <= 255):
        raise ValueError("bad version")
    count = len(payloads)
    if count > 255:
        raise ValueError("too many WPX entries")
    head = bytearray()
    head += WPX_MAGIC
    head += type_bytes.ljust(4, b"\x00")[:4]
    head += struct.pack("<I", b)
    head += bytes([version, 0, count, stride])
    table_size = count * stride
    body_off = 0x10 + table_size
    table = bytearray()
    body = bytearray()
    for (eid, method, stored, usize) in payloads:
        csize_field = 0 if (method & 0x80) else len(stored)
        table += struct.pack("<BBHIII", eid, method, 0, body_off + len(body), usize, csize_field)
        table += b"\x00" * (stride - 16)
        body += stored
    return bytes(head + table + body)


# --------------------------------------------------------------------------
# bitmap helpers
# --------------------------------------------------------------------------
def write_bmp(width, height, bpp, palette, pixels):
    """palette: 768-byte RGB (only for bpp 8) or None.  pixels: raw rows."""
    if bpp == 24:
        pal = b""
        colors = 0
    elif bpp == 8:
        if palette is None or len(palette) != 768:
            raise ValueError("8bpp bitmap needs a 768-byte palette")
        pal = bytearray()
        for i in range(256):
            r, g, b = palette[i * 3:i * 3 + 3]
            pal += bytes((b, g, r, 0))
        pal = bytes(pal)
        colors = 256
    else:
        raise ValueError("unsupported bpp %d" % bpp)
    offbits = 14 + 40 + len(pal)
    filesize = offbits + len(pixels)
    fh = struct.pack("<2sIHHI", b"BM", filesize, 0, 0, offbits)
    # the archive stores the top row first: write a top-down (negative height) BMP
    ih = struct.pack("<IiiHHIIiiII", 40, width, -height, 1, bpp, 0,
                     len(pixels), 2835, 2835, colors, 0)
    return fh + ih + pal + bytes(pixels)


def read_bmp(data):
    if data[:2] != b"BM" or len(data) < 54:
        raise ValueError("not a BMP file")
    offbits = struct.unpack_from("<I", data, 10)[0]
    hdr_size = struct.unpack_from("<I", data, 14)[0]
    width, height = struct.unpack_from("<ii", data, 18)
    bpp = struct.unpack_from("<H", data, 28)[0]
    colors = struct.unpack_from("<I", data, 46)[0]
    top_down = height < 0
    height = abs(height)
    pal = None
    if bpp == 8:
        pstart = 14 + hdr_size
        pcount = colors if colors else 256
        raw = data[pstart:pstart + pcount * 4]
        pal = bytearray()
        for i in range(256):
            if i < pcount:
                b, g, r = raw[i * 4], raw[i * 4 + 1], raw[i * 4 + 2]
            else:
                b = g = r = 0
            pal += bytes((r, g, b))
        pal = bytes(pal)
    stride = ((width * bpp // 8) + 3) & ~3
    need = stride * height
    pixels = data[offbits:offbits + need]
    if len(pixels) != need:
        raise ValueError("truncated pixel data")
    if not top_down:
        # bottom-up BMP: normalise to top-down so the row order is preserved
        # when the file is written back by write_bmp()
        rows = [pixels[r * stride:(r + 1) * stride] for r in range(height)]
        pixels = b"".join(reversed(rows))
    return width, height, bpp, pal, bytes(pixels)


# --------------------------------------------------------------------------
# WBP container
# --------------------------------------------------------------------------
def parse_wbp(path_or_bytes):
    if isinstance(path_or_bytes, (bytes, bytearray)):
        data = bytes(path_or_bytes)
        src_path = None
    else:
        src_path = path_or_bytes
        with open(src_path, "rb") as f:
            data = f.read()
    if len(data) < HDR_SIZE or data[:16] != MAGIC:
        raise ValueError("not an ARCFORM2 WBP archive")
    count = u32(data, 0x10)
    tbl_off = u32(data, 0x14)
    tbl_size = u32(data, 0x18)
    data_off = u32(data, 0x1C)
    total = u32(data, 0x20)
    hashes = struct.unpack_from("<256I", data, 0x24)
    pos = tbl_off
    limit = data_off if data_off >= tbl_off else len(data)
    entries = []
    while pos + 20 <= limit:
        off, size = struct.unpack_from("<II", data, pos)
        bucket = data[pos + 8]
        nlen = data[pos + 9]
        pad = struct.unpack_from("<H", data, pos + 10)[0]
        tlo, thi = struct.unpack_from("<II", data, pos + 12)
        raw_name = data[pos + 20:pos + 20 + nlen]
        if nlen == 0 or off < tbl_off or off + size > len(data):
            break
        entries.append({
            "name": raw_name.rstrip(b"\x00"),
            "offset": off, "size": size, "bucket": bucket,
            "time_lo": tlo, "time_hi": thi, "pad": pad,
        })
        pos += 20 + nlen
    end_of_entries = pos
    tail = data[end_of_entries:limit] if limit > end_of_entries else b""
    return {
        "data": data, "path": src_path, "count": count, "index_offset": tbl_off,
        "index_size": tbl_size, "data_offset": data_off, "total": total,
        "hashes": hashes, "entries": entries, "tail": tail,
    }


def build_wbp(files, tail=INDEX_TAIL):
    """files: list of dicts with name(bytes), blob(bytes), time_lo, time_hi.
    The list must already be in hash-bucket order."""
    files = sorted(files, key=lambda f: bucket_of(f["name"]))
    sizes = []
    for f in files:
        nl = align4(len(f["name"]))
        nl = max(nl, 4)
        sizes.append(nl)
    index_size = sum(20 + n for n in sizes) + len(tail)
    data_start = HDR_SIZE + index_size
    cur = data_start
    rec_pos = HDR_SIZE
    hashes = [0] * 256
    recs = []
    last_bucket = None
    for f, nl in zip(files, sizes):
        b = bucket_of(f["name"])
        if last_bucket != b:
            hashes[b] = rec_pos
            last_bucket = b
        recs.append((cur, len(f["blob"]), b, nl, f))
        cur += align4(len(f["blob"]))
        rec_pos += 20 + nl
    total = sum(len(f["blob"]) for f in files)
    hdr = bytearray(HDR_SIZE)
    hdr[0:16] = MAGIC
    struct.pack_into("<I", hdr, 0x10, len(files))
    struct.pack_into("<I", hdr, 0x14, HDR_SIZE)
    struct.pack_into("<I", hdr, 0x18, index_size)
    struct.pack_into("<I", hdr, 0x1C, data_start)
    struct.pack_into("<I", hdr, 0x20, total)
    for i in range(256):
        struct.pack_into("<I", hdr, 0x24 + 4 * i, hashes[i])
    out = bytearray(hdr)
    for (off, size, b, nl, f) in recs:
        out += struct.pack("<IIBBHII", off, size, b, nl, f.get("pad", 0),
                           f.get("time_lo", 0), f.get("time_hi", 0))
        out += f["name"].ljust(nl, b"\x00")
    out += tail
    if len(out) != data_start:
        raise AssertionError("index size mismatch")
    for f in files:
        blob = f["blob"]
        out += blob
        out += b"\x00" * (align4(len(blob)) - len(blob))
    return bytes(out)


# --------------------------------------------------------------------------
# decode / encode one WBP file entry
# --------------------------------------------------------------------------
def decode_wbp_entry(blob):
    """Decode a complete WBP file entry into a structured description."""
    info = parse_wpx(blob)
    entries = {}
    raw_slices = {}
    for e in info["entries"]:
        n = e["csize"] if e["csize"] else e["usize"]
        raw_slices[e["id"]] = blob[e["off"]:e["off"] + n]
    # the bitmap info block must be available before any pixel entry
    if 0x10 in raw_slices:
        entries[0x10] = raw_slices[0x10][:16]
    for e in info["entries"]:
        eid = e["id"]
        raw = raw_slices[eid]
        method = e["method"]
        stored = bool(method & 0x80) or e["csize"] == 0
        if stored:
            entries[eid] = raw[:e["usize"]]
            continue
        if method & ~0x01:
            raise ValueError("unsupported compression method 0x%02X (id 0x%02X)" % (method, eid))
        if eid == 2:
            entries[eid] = lzss_decompress(raw, e["usize"], 1, False)
        else:
            bppb, table, stride, bpp = _bitmap_params(info, entries, eid)
            entries[eid] = lzss_decompress(raw, e["usize"], bppb, True, table)
    return info, entries


def _bitmap_params(info, entries, eid):
    """Return (raw_prefix, dist_table, stride, bpp) for a bitmap payload."""
    inf = entries.get(0x10)
    if inf is None or len(inf) < 16:
        return 1, None, 0, 0
    w, h = struct.unpack_from("<HH", inf, 4)
    bpp = inf[12]
    if eid == 0x13:
        # case 19: an 8bpp plane, one byte per pixel, stride = width
        return 1, make_dist_table(align4(w), 1), align4(w), 8
    if bpp not in (8, 24, 32):
        bpp = 24
    stride = ((w * (bpp // 8)) + 3) & ~3
    bppb = bpp // 8
    return bppb, make_dist_table(stride, bppb), stride, bpp


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_list(args):
    for path in args.inputs:
        arc = parse_wbp(path)
        print("== %s  (%d files, index 0x%X bytes @ 0x%X, data @ 0x%X)"
              % (path, len(arc["entries"]), arc["index_size"],
                 arc["index_offset"], arc["data_offset"]))
        print("   %-16s %10s  %-6s %s" % ("name", "size", "type", "entries"))
        d = arc["data"]
        for e in arc["entries"]:
            blob = d[e["offset"]:e["offset"] + e["size"]]
            try:
                info = parse_wpx(blob)
                t = info["type"].rstrip(b"\x00").decode("latin1")
                ids = ",".join("%02X" % x["id"] for x in info["entries"])
            except Exception:
                t = "?"
                ids = "?"
            print("   %-16s %10d  %-6s %s" % (name_str(e["name"]), e["size"], t, ids))


def _stem(name):
    n = name_str(name)
    base, ext = os.path.splitext(n)
    return base


def cmd_extract(args):
    arc = parse_wbp(args.inputs[0])
    outdir = args.output or (os.path.splitext(args.inputs[0])[0] + "_unpacked")
    filesdir = os.path.join(outdir, "files")
    os.makedirs(filesdir, exist_ok=True)
    manifest = {
        "tool": "wbp_tool",
        "format": "ARCFORM2 WBUG",
        "source": os.path.abspath(args.inputs[0]),
        "index_tail": (arc["tail"] or INDEX_TAIL).hex(),
        "files": [],
    }
    d = arc["data"]
    count = 0
    for e in arc["entries"]:
        blob = d[e["offset"]:e["offset"] + e["size"]]
        try:
            info, entries = decode_wbp_entry(blob)
        except Exception as exc:
            print("  !! %s: %s" % (name_str(e["name"]), exc))
            continue
        name = e["name"]
        stem = _stem(name)
        rec = {
            "name": name_str(name),
            "bucket": e["bucket"],
            "time_lo": e["time_lo"],
            "time_hi": e["time_hi"],
            "wpx": {
                "type": info["type"].rstrip(b"\x00").decode("latin1"),
                "raw_type": info["type"].hex(),
                "b": info["b"],
                "version": info["version"],
                "stride": info["stride"],
                "entries": [],
            },
        }
        is_bmp = info["type"][:3] == b"BMP"
        if is_bmp and 0x11 in entries:
            inf = entries.get(0x10, b"")
            if len(inf) >= 16:
                w, h = struct.unpack_from("<HH", inf, 4)
                bpp = inf[12]
            else:
                w = h = 0
                bpp = 24
            pal = entries.get(0x12)
            bmpname = stem + ".bmp"
            bmp = write_bmp(w, h, bpp, pal, entries[0x11])
            with open(os.path.join(filesdir, bmpname), "wb") as f:
                f.write(bmp)
            rec["wpx"]["entries"].append(
                {"id": 0x10, "method": 0x80, "kind": "info",
                 "data": entries.get(0x10, b"").hex(), "usize": 16})
            rec["wpx"]["entries"].append(
                {"id": 0x11, "method": 1, "kind": "pixels", "file": bmpname,
                 "usize": len(entries[0x11]), "sha256": sha256(entries[0x11])})
            if 0x12 in entries:
                rec["wpx"]["entries"].append(
                    {"id": 0x12, "method": 0x80, "kind": "palette", "file": bmpname,
                     "usize": len(entries[0x12]), "sha256": sha256(entries[0x12])})
            if 0x13 in entries:
                side = stem + ".id19.bin"
                with open(os.path.join(filesdir, side), "wb") as f:
                    f.write(entries[0x13])
                rec["wpx"]["entries"].append(
                    {"id": 0x13, "method": 1, "kind": "plane", "file": side,
                     "usize": len(entries[0x13]), "sha256": sha256(entries[0x13])})
        else:
            data = entries.get(2, entries.get(0x11, b""))
            fname = name_str(name)
            with open(os.path.join(filesdir, fname), "wb") as f:
                f.write(data)
            rec["wpx"]["entries"].append(
                {"id": 2, "method": 1, "kind": "payload", "file": fname,
                 "usize": len(data), "sha256": sha256(data)})
        # preserve the exact entry order of the original container
        orig_order = [x["id"] for x in info["entries"]]
        rec["wpx"]["entries"].sort(key=lambda x: orig_order.index(x["id"]) if x["id"] in orig_order else 99)
        manifest["files"].append(rec)
        count += 1
    with open(os.path.join(outdir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    print("extracted %d/%d files -> %s" % (count, len(arc["entries"]), outdir))


def _compress_entry(eid, data, planar):
    raw_prefix = 3 if planar else 1
    if len(data) <= raw_prefix:
        return 0x80, data, len(data)
    comp = lzss_compress(data, raw_prefix, planar)
    if len(comp) >= len(data):
        return 0x80, data, len(data)
    return 0x01, comp, len(data)


def cmd_pack(args):
    indir = args.inputs[0]
    mpath = os.path.join(indir, "manifest.json")
    with open(mpath, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    filesdir = os.path.join(indir, "files")
    outpath = args.output or (os.path.basename(os.path.normpath(indir)).rstrip("/\\") + ".wbp")
    src_entries = None
    src_path = args.source
    if src_path is None and not getattr(args, "no_reuse", False):
        cand = manifest.get("source")
        if cand and os.path.isfile(cand) and os.path.abspath(cand) != os.path.abspath(outpath):
            src_path = cand
    if src_path:
        print("reusing unchanged compressed data from %s" % src_path)
        src = parse_wbp(src_path)
        src_entries = {}
        for e in src["entries"]:
            blob = src["data"][e["offset"]:e["offset"] + e["size"]]
            try:
                info = parse_wpx(blob)
            except Exception:
                continue
            src_entries[name_str(e["name"]).upper()] = {
                x["id"]: blob[x["off"]:x["off"] + (x["csize"] if x["csize"] else x["usize"])]
                for x in info["entries"]}
    files = []
    reused = 0
    recomp = 0
    for rec in manifest["files"]:
        name = name_bytes(rec["name"])
        key = name_str(name).upper()
        wpx_info = rec["wpx"]
        stride = wpx_info.get("stride", 16)
        final = []
        for e in wpx_info["entries"]:
            eid = e["id"]
            kind = e.get("kind")
            if kind in ("payload", "plane"):
                with open(os.path.join(filesdir, e["file"]), "rb") as f:
                    data = f.read()
            elif kind == "info":
                data = bytes.fromhex(e["data"])
            elif kind in ("pixels", "palette"):
                with open(os.path.join(filesdir, e["file"]), "rb") as f:
                    bmp = f.read()
                w, h, bpp, pal, pixels = read_bmp(bmp)
                data = pixels if kind == "pixels" else (pal if pal is not None else b"\x00" * 768)
            else:
                raise ValueError("unknown entry kind %r" % kind)

            if eid == 0x10 or (e.get("method", 1) & 0x80):
                final.append((eid, 0x80, data, len(data)))
                continue
            orig_sha = e.get("sha256")
            if (src_entries is not None and orig_sha and sha256(data) == orig_sha
                    and key in src_entries and eid in src_entries[key]):
                final.append((eid, 1, src_entries[key][eid], len(data)))
                reused += 1
                continue
            m, comp, usize = _compress_entry(eid, data, eid != 2)
            final.append((eid, m, comp, usize))
            recomp += 1
        if "raw_type" in wpx_info:
            type_bytes = bytes.fromhex(wpx_info["raw_type"])
        else:
            type_bytes = wpx_info["type"].encode("latin1").ljust(4, b"\x00")[:4]
        blob = build_wpx(type_bytes, wpx_info.get("b", 0x10),
                         wpx_info.get("version", 1), stride, final)
        files.append({"name": name, "blob": blob,
                      "time_lo": rec.get("time_lo", 0),
                      "time_hi": rec.get("time_hi", 0)})
    tail = bytes.fromhex(manifest.get("index_tail") or INDEX_TAIL.hex())
    out = build_wbp(files, tail)
    with open(outpath, "wb") as f:
        f.write(out)
    print("packed %d files -> %s  (%d bytes, %d compressed payloads reused, %d recompressed)"
          % (len(files), outpath, len(out), reused, recomp))


def cmd_verify(args):
    arc = parse_wbp(args.inputs[0])
    indir = args.inputs[1]
    with open(os.path.join(indir, "manifest.json"), "r", encoding="utf-8") as f:
        manifest = json.load(f)
    filesdir = os.path.join(indir, "files")
    bad = 0
    for rec in manifest["files"]:
        for e in rec["wpx"]["entries"]:
            if e.get("sha256") is None:
                continue
            with open(os.path.join(filesdir, e["file"]), "rb") as f:
                data = f.read()
            if e.get("kind") in ("pixels", "palette"):
                w, h, bpp, pal, pixels = read_bmp(data)
                data = pixels if e["kind"] == "pixels" else pal
            if sha256(data) != e["sha256"]:
                bad += 1
                print("MISMATCH %s id %02X" % (rec["name"], e["id"]))
    print("verify: %d mismatches" % bad)
    return 1 if bad else 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(
        description="Wild Bug ARCFORM2 (.WBP) archive tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="drag & drop: a .wbp file extracts, a directory packs")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("list", help="list archive contents")
    p.add_argument("inputs", nargs="+")
    p = sub.add_parser("extract", help="unpack (auto decompress)")
    p.add_argument("inputs", nargs=1)
    p.add_argument("-o", "--output")
    p = sub.add_parser("pack", help="repack (auto compress)")
    p.add_argument("inputs", nargs=1)
    p.add_argument("-o", "--output")
    p.add_argument("--source", help="original archive, reuse unchanged compressed data")
    p.add_argument("--no-reuse", action="store_true",
                   help="always recompress, never reuse the source archive")
    p = sub.add_parser("verify", help="verify extracted payloads against manifest")
    p.add_argument("inputs", nargs=2)
    args = ap.parse_args(argv)
    if not args.cmd:
        # drag & drop behaviour
        if len(argv) == 1:
            if os.path.isdir(argv[0]):
                args.cmd = "pack"
                args.inputs = [argv[0]]
                args.output = None
                args.source = None
                args.no_reuse = False
            else:
                args.cmd = "extract"
                args.inputs = [argv[0]]
                args.output = None
        else:
            ap.print_help()
            return 2
    if args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "extract":
        cmd_extract(args)
    elif args.cmd == "pack":
        cmd_pack(args)
    elif args.cmd == "verify":
        return cmd_verify(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
