#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decrypt.py -- 姦獄島 (Liquid-Shine, NScripter 2.95) nscript.dat 解密/加密工具

这个游戏的 NScripter 引擎在普通 "XOR 0x84" 之外，还加了一层自定义的
32 字节分组密码。nscript.dat 的每个 32 字节块都独立用同一把 96 字节密钥加密。

算法（逆向自 kg.exe 的 sub_428EA0 / sub_429040 / sub_492700）：

    K1 = key[0:48], K2 = key[48:96]
    F(x) = MD5 压缩函数(IV, x)   # 只做一次 64 字节块的 MD5 压缩，不做 padding

    解密一个 32 字节块 C = (C_lo, C_hi):
        s1   = F(C_hi || K1)
        t    = C_lo XOR s1
        s2   = F(t    || K2)
        P_lo = C_hi XOR s2
        s3   = F(P_lo || K1)
        P_hi = t    XOR s3
        P    = P_lo || P_hi

    文件明文 = 每个块的 P 再逐字节 XOR 0x84。

用法:
    python decrypt.py decrypt nscript.dat nscript.txt
    python decrypt.py encrypt nscript.txt  nscript_new.dat
"""
import argparse
import struct
import sys

# 从 kg.exe 的 .rdata 0x4B2B00 处提取，引擎初始化时只复制前 96 字节
KEY = (b"sdajklfdsknlfkangokudsnmadfsnklasdasdjklsdajklgdnmlasdfnklas"
       b"asdklmdsajklgvfsdsdasadsadsadwqerdsf")
assert len(KEY) == 96, len(KEY)
K1 = KEY[:48]
K2 = KEY[48:96]

IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
MASK = 0xFFFFFFFF

# MD5 的 64 步常量与循环左移位数（预先算好，加速）
MD5_K = tuple(int(abs(__import__("math").sin(i + 1)) * (1 << 32)) & MASK for i in range(64))
MD5_S = ((7, 12, 17, 22) * 4 + (5, 9, 14, 20) * 4 +
         (4, 11, 16, 23) * 4 + (6, 10, 15, 21) * 4)


def md5_compress(state, block):
    """对 64 字节 block 做一次 MD5 压缩，返回新的 4 字状态（16 字节）。"""
    m = struct.unpack("<16I", block)
    a, b, c, d = state
    aa, bb, cc, dd = a, b, c, d
    k = MD5_K
    s = MD5_S
    for i in range(16):
        f = (b & c) | (~b & d)
        a = (a + f + k[i] + m[i]) & MASK
        a = (a << s[i] | a >> (32 - s[i])) & MASK
        a = (a + b) & MASK
        a, b, c, d = d, a, b, c
    for i in range(16, 32):
        f = (d & b) | (~d & c)
        g = (5 * i + 1) & 15
        a = (a + f + k[i] + m[g]) & MASK
        a = (a << s[i] | a >> (32 - s[i])) & MASK
        a = (a + b) & MASK
        a, b, c, d = d, a, b, c
    for i in range(32, 48):
        f = b ^ c ^ d
        g = (3 * i + 5) & 15
        a = (a + f + k[i] + m[g]) & MASK
        a = (a << s[i] | a >> (32 - s[i])) & MASK
        a = (a + b) & MASK
        a, b, c, d = d, a, b, c
    for i in range(48, 64):
        f = c ^ (b | (~d & MASK))
        g = (7 * i) & 15
        a = (a + f + k[i] + m[g]) & MASK
        a = (a << s[i] | a >> (32 - s[i])) & MASK
        a = (a + b) & MASK
        a, b, c, d = d, a, b, c
    return struct.pack("<4I", (aa + a) & MASK, (bb + b) & MASK,
                       (cc + c) & MASK, (dd + d) & MASK)


def decrypt_block(c):
    """解密一个 32 字节块（尚未 XOR 0x84）。"""
    c_lo, c_hi = c[:16], c[16:32]
    s1 = md5_compress(IV, c_hi + K1)
    t = bytes(x ^ y for x, y in zip(c_lo, s1))
    s2 = md5_compress(IV, t + K2)
    p_lo = bytes(x ^ y for x, y in zip(c_hi, s2))
    s3 = md5_compress(IV, p_lo + K1)
    p_hi = bytes(x ^ y for x, y in zip(t, s3))
    return p_lo + p_hi


def encrypt_block(p):
    """加密一个 32 字节块（输入是已 XOR 0x84 的明文）。"""
    p_lo, p_hi = p[:16], p[16:32]
    t = bytes(x ^ y for x, y in zip(p_hi, md5_compress(IV, p_lo + K1)))
    c_hi = bytes(x ^ y for x, y in zip(p_lo, md5_compress(IV, t + K2)))
    c_lo = bytes(x ^ y for x, y in zip(t, md5_compress(IV, c_hi + K1)))
    return c_lo + c_hi


def xor84(data):
    return bytes(b ^ 0x84 for b in data)


def decrypt_bytes(raw):
    assert len(raw) % 32 == 0, "nscript.dat 大小不是 32 的倍数"
    out = bytearray()
    for i in range(0, len(raw), 32):
        out += xor84(decrypt_block(raw[i:i + 32]))
    return bytes(out)


def encrypt_bytes(text):
    data = xor84(text)
    if len(data) % 32:
        data += b"\x00" * (32 - len(data) % 32)
    out = bytearray()
    for i in range(0, len(data), 32):
        out += encrypt_block(data[i:i + 32])
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description="姦獄島 nscript.dat 解密/加密")
    ap.add_argument("mode", choices=["decrypt", "encrypt"])
    ap.add_argument("input")
    ap.add_argument("output")
    args = ap.parse_args()

    raw = open(args.input, "rb").read()
    if args.mode == "decrypt":
        out = decrypt_bytes(raw)
    else:
        out = encrypt_bytes(raw)
    open(args.output, "wb").write(out)
    print(f"{args.mode}: {args.input} ({len(raw)} bytes) -> {args.output} ({len(out)} bytes)")


if __name__ == "__main__":
    main()
