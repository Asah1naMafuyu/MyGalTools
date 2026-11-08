"""disassembler.py — 把 scr.bnd 中的脚本二进制转换为语义汇编文本。

用法：
    python disassembler.py <脚本文件或目录> [-o <输出目录或文件>] [--encoding cp932]

支持单个文件，也支持目录批处理。
默认输出到输入文件所在目录，文件名为 <原名>.asm.txt。
输出文本为 UTF-8；--encoding 只决定二进制里字符串按什么编码解释。
"""

from __future__ import annotations

import argparse
import codecs
import os
import sys

from opcodelist import (
    CHOICE_OPS,
    DEFAULT_ENCODING,
    JUMP_OPS,
    OPCODES,
    ScriptError,
    iter_records,
    opcode_info,
)


def format_text(blob: bytes, encoding: str) -> str:  # type: ignore[no-redef]
    """把文本单元解码并转义为 asm 字符串内容。"""
    body = blob.rstrip(b"\x00")
    text = body.decode(encoding, errors="surrogateescape")
    out = []
    for ch in text:
        code = ord(ch)
        if 0xDC80 <= code <= 0xDCFF:          # surrogateescape 的非法字节
            out.append("{{%02X}}" % (code - 0xDC00))
        elif ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "{":
            out.append("{{7B}}")
        elif ch == "}":
            out.append("{{7D}}")
        elif code < 0x20 or code == 0x7F:
            out.append("{{%02X}}" % code)
        else:
            out.append(ch)
    return "".join(out)


def hexv(v: int) -> str:
    return "0x%X" % v


def collect_targets(records) -> set:
    targets = set()
    for rec in records:
        if rec.op in JUMP_OPS:
            targets.add(rec.args[0] * 4)
        elif rec.op in CHOICE_OPS:
            for _, target in rec.entries:
                targets.add(target * 4)
        elif rec.op == 0x09 and len(rec.args) == 3 and rec.args[0] == 2:
            # SET_VARS n==2：变量==1 时跳到 arg2（dword 下标）
            targets.add(rec.args[2] * 4)
    return targets


def format_record(rec, encoding: str, labels: dict) -> str:
    op = rec.op
    m = opcode_info(op)["mnemonic"]

    if op == 0x21:      # TITLE
        return '%s "%s"' % (m, format_text(rec.texts[0], encoding))
    if op == 0x22:      # LABEL
        return '%s "%s"' % (m, format_text(rec.texts[0], encoding))
    if op == 0x05:      # MESSAGE
        return '%s %s, "%s"' % (m, hexv(rec.args[0]),
                                 format_text(rec.texts[0], encoding))
    if op == 0x06:      # MESSAGE_AUTO
        return '%s %s, %s, "%s"' % (m, hexv(rec.args[0]), hexv(rec.args[1]),
                                     format_text(rec.texts[0], encoding))
    if op == 0x07:      # CHOICE
        parts = []
        for blob, target in rec.entries:
            off = target * 4
            if off not in labels:
                raise ScriptError(
                    f"0x{rec.offset:X}: CHOICE 目标 0x{off:X} 不是记录边界")
            parts.append('"%s" -> %s' % (format_text(blob, encoding), labels[off]))
        return m + (" " + ", ".join(parts) if parts else "")
    if op == 0x11:      # JUMP
        off = rec.args[0] * 4
        if off not in labels:
            raise ScriptError(
                f"0x{rec.offset:X}: JUMP 目标 0x{off:X} 不是记录边界")
        return "%s %s" % (m, labels[off])
    if op == 0x12:      # CALL_SCRIPT
        return "%s %s, %s" % (m, hexv(rec.args[0]), hexv(rec.args[1]))
    if op == 0x09:
        if len(rec.args) == 3 and rec.args[0] == 2:
            off = rec.args[2] * 4
            if off not in labels:
                raise ScriptError(
                    f"0x{rec.offset:X}: JMP_IF_VAR 目标 0x{off:X} 不是记录边界")
            return "JMP_IF_VAR %s, %s" % (hexv(rec.args[1]), labels[off])
        vals = rec.args[1:]
        return m + (" " + ", ".join(hexv(v) for v in vals) if vals else "")
    if op == 0x0B or op == 0x0C:
        return "%s %s" % (m, hexv(rec.args[0]))
    if op == 0x13 or op == 0x23 or op == 0x1B or op == 0x1D or op == 0x1E:
        return m
    # 其余 fixed 指令
    if rec.args:
        return m + " " + ", ".join(hexv(v) for v in rec.args)
    return m


def disassemble_data(data: bytes, encoding: str, name: str) -> str:
    records = list(iter_records(data))
    targets = collect_targets(records)
    labels = {off: "loc_%08X" % off for off in targets}

    # 所有目标必须是真实记录边界
    starts = {rec.offset for rec in records}
    bad = sorted(set(targets) - starts)
    if bad:
        raise ScriptError(
            "跳转目标不在记录边界: " + ", ".join("0x%X" % x for x in bad[:8]))

    lines = []
    lines.append("; scr.bnd script disassembly — 魔法少女アイ plus DVD")
    lines.append("; file: %s   size: %d bytes (%d dwords)"
                 % (name, len(data), len(data) // 4))
    lines.append(".encoding %s" % encoding)
    lines.append(".file %s" % name)
    lines.append("")

    for rec in records:
        if rec.offset in labels:
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(labels[rec.offset] + ":")
        lines.append("    " + format_record(rec, encoding, labels))

    lines.append("")
    return "\n".join(lines)


def is_script(path: str) -> bool:
    """判断文件是否是脚本：首 dword 的保留字节为 0 且 opcode 合法。"""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return (len(head) == 4 and head[1] == 0 and head[2] == 0
            and head[3] in OPCODES)


def default_output(input_path: str, output: str | None) -> str:
    if output:
        return output
    base = os.path.basename(input_path)
    root, _ = os.path.splitext(base)
    return os.path.join(os.path.dirname(os.path.abspath(input_path)),
                        root + ".asm.txt")


def process_file(path: str, output: str | None, encoding: str) -> str:
    with open(path, "rb") as f:
        data = f.read()
    name = os.path.splitext(os.path.basename(path))[0]
    text = disassemble_data(data, encoding, name)
    out_path = default_output(path, output)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return out_path


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="scr.bnd 脚本反汇编器")
    parser.add_argument("input", nargs="?", help="脚本文件或目录")
    parser.add_argument("-o", "--output", help="输出文件或输出目录")
    parser.add_argument("--encoding", default=DEFAULT_ENCODING,
                        help="二进制字符串编码（默认 cp932）")
    parser.add_argument("--recursive", action="store_true", help="递归处理目录")
    args = parser.parse_args(argv)

    if not args.input:
        parser.print_help()
        return 1
    try:
        codecs.lookup(args.encoding)
    except LookupError:
        print("不支持的编码: %s" % args.encoding, file=sys.stderr)
        return 2

    src = args.input
    if not os.path.exists(src):
        print("输入不存在: %s" % src, file=sys.stderr)
        return 2

    if os.path.isfile(src):
        if not is_script(src):
            print("[跳过] %s（非脚本文件）" % src)
            return 0
        try:
            out = process_file(src, args.output, args.encoding)
        except ScriptError as e:
            print("[失败] %s: %s" % (src, e), file=sys.stderr)
            return 3
        print("[OK] %s -> %s" % (src, out))
        return 0

    # 目录
    errors = 0
    count = 0
    skipped = 0
    for root, dirs, files in os.walk(src):
        if not args.recursive:
            dirs[:] = []
        for fn in sorted(files):
            if fn.startswith("."):
                continue
            path = os.path.join(root, fn)
            if not is_script(path):
                skipped += 1
                continue
            rel = os.path.relpath(path, src)
            out = None
            if args.output:
                out_dir = args.output if os.path.isdir(args.output) or not os.path.splitext(args.output)[1] \
                    else os.path.dirname(args.output)
                out = os.path.join(out_dir, os.path.splitext(rel)[0] + ".asm.txt")
            try:
                process_file(path, out, args.encoding)
                count += 1
            except ScriptError as e:
                print("[失败] %s: %s" % (path, e), file=sys.stderr)
                errors += 1
        if not args.recursive:
            break
    print("完成：%d 个文件，跳过 %d 个非脚本，%d 个失败"
          % (count, skipped, errors))
    return 0 if errors == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
