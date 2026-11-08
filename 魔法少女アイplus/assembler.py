"""assembler.py — 把语义汇编文本重新编码为原游戏脚本二进制。

用法：
    python assembler.py <asm.txt 或目录> [-o <输出文件/目录>] [--encoding gbk]

支持单个文件，也支持目录批处理。
默认输出 <输入名去掉 .asm.txt>（即原游戏对应的无后缀脚本文件）。
--encoding 指定重建时文本使用的二进制编码；未指定时读取 .encoding 指令。
"""

from __future__ import annotations

import argparse
import codecs
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from opcodelist import (
    DEFAULT_ENCODING,
    OPCODES,
    ScriptError,
    encode_text,
    text_units,
)

MNEMONIC_TO_OP = {info["mnemonic"]: op for op, info in OPCODES.items()}
# 0x09 在 n==2 时不是批量赋值，而是“变量==1 则跳转”的条件分支。
MNEMONIC_TO_OP["JMP_IF_VAR"] = 0x09

LABEL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*$")
INSN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$")


@dataclass
class Ins:
    line: int
    mnemonic: str
    op: int
    b0: int
    kind: str
    args: list = field(default_factory=list)
    text: bytes = b""
    entries: List[Tuple[bytes, str]] = field(default_factory=list)
    target: str = ""
    units: int = 0
    size: int = 0
    offset: int = 0


def strip_comment(line: str) -> str:
    out = []
    in_q = False
    esc = False
    for ch in line:
        if esc:
            out.append(ch)
            esc = False
            continue
        if ch == "\\":
            out.append(ch)
            esc = True
            continue
        if ch == '"':
            in_q = not in_q
            out.append(ch)
            continue
        if ch == ";" and not in_q:
            break
        out.append(ch)
    return "".join(out)


def split_operands(s: str) -> List[str]:
    parts, buf = [], []
    in_q = False
    esc = False
    for ch in s:
        if esc:
            buf.append(ch)
            esc = False
            continue
        if ch == "\\":
            buf.append(ch)
            esc = True
            continue
        if ch == '"':
            in_q = not in_q
            buf.append(ch)
            continue
        if ch == "," and not in_q:
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p != ""]


def parse_int(tok: str) -> int:
    try:
        return int(tok, 0)
    except ValueError:
        raise ScriptError(f"非法数值: {tok}") from None


def unquote(tok: str) -> str:
    tok = tok.strip()
    if len(tok) < 2 or not tok.startswith('"') or not tok.endswith('"'):
        raise ScriptError(f"需要带引号的字符串: {tok}")
    return tok[1:-1]


def _encode(text: str, encoding: str, what: str = "文本") -> bytes:
    try:
        return encode_text(text, encoding)
    except UnicodeEncodeError as e:
        bad = text[e.start:e.end] if e.start is not None else "?"
        raise ScriptError(
            f"{what}中的字符 {bad!r} 无法用 {encoding} 编码（请改用全角字符或翻译成中文）"
        ) from None


def parse_choice_token(tok: str) -> Tuple[str, str]:
    tok = tok.strip()
    if not tok.startswith('"'):
        raise ScriptError(f"CHOICE 选项格式错误: {tok}")
    esc = False
    end = -1
    for i in range(1, len(tok)):
        ch = tok[i]
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            end = i
            break
    if end < 0:
        raise ScriptError(f"CHOICE 字符串未闭合: {tok}")
    content = tok[1:end]
    rest = tok[end + 1:].strip()
    m = re.match(r"^->\s*([A-Za-z_][A-Za-z0-9_]*)$", rest)
    if not m:
        raise ScriptError(f"CHOICE 选项缺少 -> 标签: {tok}")
    return content, m.group(1)


def parse_asm(text: str, encoding: str) -> Tuple[List[Ins], Dict[str, int], str]:
    """返回 (指令列表, 标签→dword 下标, 声明的文件名)。"""
    ins_list: List[Ins] = []
    labels: Dict[str, int] = {}
    pc = 0
    file_name = ""
    declared_encoding: Optional[str] = None

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("."):
            parts = line.split(None, 1)
            key = parts[0].lower()
            val = parts[1].strip() if len(parts) > 1 else ""
            if key == ".encoding":
                declared_encoding = val
            elif key == ".file":
                file_name = val
            elif key in (".size", ".comment"):
                pass
            else:
                print("[警告] 第 %d 行：未知伪指令 %s" % (lineno, key),
                      file=sys.stderr)
            continue

        m = LABEL_RE.match(line)
        if m:
            name = m.group(1)
            if name in labels:
                raise ScriptError(f"第 {lineno} 行：标签重复 {name}")
            labels[name] = pc
            continue

        m = INSN_RE.match(line)
        if not m:
            raise ScriptError(f"第 {lineno} 行：无法解析：{raw}")
        mnemonic = m.group(1).upper()
        rest = m.group(2).strip()
        if mnemonic not in MNEMONIC_TO_OP:
            raise ScriptError(f"第 {lineno} 行：未知指令 {mnemonic}")
        op = MNEMONIC_TO_OP[mnemonic]
        info = OPCODES[op]
        kind = "branch_var" if mnemonic == "JMP_IF_VAR" else info["kind"]
        ins = Ins(line=lineno, mnemonic=mnemonic, op=op, b0=info["b0"],
                  kind=kind)

        try:
            _parse_operands(ins, rest, encoding)
        except ScriptError as e:
            raise ScriptError(f"第 {lineno} 行：{e}") from None

        ins.offset = pc
        ins.size = _instruction_size(ins)
        ins_list.append(ins)
        pc += ins.size

    if declared_encoding:
        # 只用于报告；实际编码由 main 决定
        pass
    return ins_list, labels, file_name


def _parse_operands(ins: Ins, rest: str, encoding: str) -> None:
    kind = ins.kind
    toks = split_operands(rest) if rest else []

    if kind == "branch_var":                 # JMP_IF_VAR
        if len(toks) != 2:
            raise ScriptError("需要 (变量号, 目标标签)")
        ins.args = [parse_int(toks[0])]
        ins.target = toks[1].strip()
        return

    if kind == "text":                       # TITLE / LABEL
        if len(toks) != 1:
            raise ScriptError("需要 1 个字符串操作数")
        ins.text = _encode(unquote(toks[0]), encoding)
        ins.units = text_units(len(ins.text))
    elif kind == "message":                  # MESSAGE
        if len(toks) != 2:
            raise ScriptError("需要 (voice_id, \"文本\")")
        ins.args = [parse_int(toks[0])]
        ins.text = _encode(unquote(toks[1]), encoding)
        ins.units = text_units(len(ins.text))
    elif kind == "message2":                 # MESSAGE_AUTO
        if len(toks) != 3:
            raise ScriptError("需要 (voice_id, param, \"文本\")")
        ins.args = [parse_int(toks[0]), parse_int(toks[1])]
        ins.text = _encode(unquote(toks[2]), encoding)
        ins.units = text_units(len(ins.text))
    elif kind == "choice":                   # CHOICE
        if toks:
            if len(toks) > 0x1000:
                raise ScriptError("选项过多")
            for tok in toks:
                content, label = parse_choice_token(tok)
                ins.entries.append((_encode(content, encoding), label))
        ins.args = [len(ins.entries)]
    elif kind == "list":                     # SET_VARS
        if len(toks) % 2:
            raise ScriptError("SET_VARS 的值必须成对（变量号, 值）")
        if not toks:
            raise ScriptError("SET_VARS 至少需要一对值")
        ins.args = [parse_int(t) for t in toks]
    elif kind == "jump":                     # JUMP
        if len(toks) != 1:
            raise ScriptError("需要 1 个标签")
        ins.args = [toks[0].strip()]
    elif kind == "call":                     # CALL_SCRIPT
        if len(toks) != 2:
            raise ScriptError("需要 (脚本编号, 入口下标)")
        ins.args = [parse_int(toks[0]), parse_int(toks[1])]
    else:                                    # fixed
        if len(toks) != int(OPCODES[ins.op]["argc"]):
            raise ScriptError("需要 %d 个操作数" % OPCODES[ins.op]["argc"])
        ins.args = [parse_int(t) for t in toks]


def _instruction_size(ins: Ins) -> int:
    kind = ins.kind
    if kind == "fixed":
        return 1 + len(ins.args)
    if kind == "text":
        return 1 + 1 + ins.units
    if kind == "message":
        return 1 + 1 + 1 + ins.units
    if kind == "message2":
        return 1 + 2 + 1 + ins.units
    if kind == "choice":
        return 1 + 1 + sum(2 + text_units(len(blob)) for blob, _ in ins.entries)
    if kind == "list":
        return 1 + len(ins.args)
    if kind == "branch_var":
        return 4
    if kind == "jump":
        return 2
    if kind == "call":
        return 3
    raise ScriptError("未知 kind")


def _blob(text: bytes) -> Tuple[int, bytes]:
    if b"\x00" in text:
        raise ScriptError("文本中不允许出现 NUL 字节")
    units = text_units(len(text))
    blob = text + b"\x00\x00"
    blob += b"\x00" * (units * 4 - len(blob))
    return units, blob


def assemble(ins_list: List[Ins], labels: Dict[str, int], encoding: str,
             source: str = "") -> bytes:
    out = bytearray()

    for ins in ins_list:
        word = (ins.op << 24) | (ins.b0 & 0xFF)
        out += word.to_bytes(4, "little")
        kind = ins.kind

        if kind == "fixed":
            for v in ins.args:
                out += _u32(v)
        elif kind == "text":
            units, blob = _blob(ins.text)
            out += _u32(units) + blob
        elif kind == "message":
            out += _u32(ins.args[0])
            units, blob = _blob(ins.text)
            out += _u32(units) + blob
        elif kind == "message2":
            out += _u32(ins.args[0]) + _u32(ins.args[1])
            units, blob = _blob(ins.text)
            out += _u32(units) + blob
        elif kind == "choice":
            out += _u32(len(ins.entries))
            for blob_text, label in ins.entries:
                units, blob = _blob(blob_text)
                out += _u32(units) + blob + _u32(_label_index(labels, label))
        elif kind == "list":
            vals = ins.args
            out += _u32(len(vals))
            for v in vals:
                out += _u32(v)
        elif kind == "branch_var":
            out += _u32(2) + _u32(ins.args[0]) + _u32(_label_index(labels, ins.target))
        elif kind == "jump":
            out += _u32(_label_index(labels, ins.args[0]))
        elif kind == "call":
            out += _u32(ins.args[0]) + _u32(ins.args[1])
        else:
            raise ScriptError("未知 kind")

        if ins.op == 0x21 and ins.units > 10:
            where = ("%s " % source) if source else ""
            try:
                title = ins.text.decode(encoding, "replace")
            except Exception:
                title = ""
            if len(title) > 30:
                title = title[:30] + "..."
            print("[警告] %s第 %d 行：TITLE %r 长度 %d units，超过样本最大值 10，"
                  "可能覆盖标题缓冲区" % (where, ins.line, title, ins.units),
                  file=sys.stderr)

    return bytes(out)


def _label_index(labels: Dict[str, int], name: str) -> int:
    try:
        return labels[name]
    except KeyError:
        raise ScriptError(f"未解析的标签: {name}") from None


def _u32(v: int) -> bytes:
    if not (0 <= v <= 0xFFFFFFFF):
        raise ScriptError(f"数值越界: {v}")
    return v.to_bytes(4, "little")


def default_output(input_path: str, output: str | None) -> str:
    if output:
        return output
    base = os.path.basename(input_path)
    if base.lower().endswith(".asm.txt"):
        base = base[:-8]
    else:
        base = os.path.splitext(base)[0]
    
    # 直接返回去掉 .asm.txt 的原名，不加任何后缀
    return os.path.join(os.path.dirname(os.path.abspath(input_path)), base)


def process_file(path: str, output: str | None, cli_encoding: str | None) -> str:
    with open(path, "r", encoding="utf-8-sig") as f:
        text = f.read()

    # 先确定编码：命令行 > .encoding 指令 > 默认
    encoding = cli_encoding
    if not encoding:
        for line in text.splitlines():
            s = strip_comment(line).strip()
            if s.lower().startswith(".encoding"):
                encoding = s.split(None, 1)[1].strip()
                break
    if not encoding:
        encoding = DEFAULT_ENCODING
    try:
        codecs.lookup(encoding)
    except LookupError:
        raise ScriptError(f"不支持的编码: {encoding}") from None

    ins_list, labels, _ = parse_asm(text, encoding)
    data = assemble(ins_list, labels, encoding, path)
    out_path = default_output(path, output)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="scr.bnd 脚本汇编器")
    parser.add_argument("input", nargs="?", help="asm.txt 文件或目录")
    parser.add_argument("-o", "--output", help="输出文件或目录")
    parser.add_argument("--encoding", help="重建文本编码（如 gbk / cp932）")
    parser.add_argument("--recursive", action="store_true", help="递归处理目录")
    args = parser.parse_args(argv)

    if not args.input:
        parser.print_help()
        return 1
    src = args.input
    if not os.path.exists(src):
        print("输入不存在: %s" % src, file=sys.stderr)
        return 2

    if os.path.isfile(src):
        try:
            out = process_file(src, args.output, args.encoding)
        except ScriptError as e:
            print("[失败] %s: %s" % (src, e), file=sys.stderr)
            return 3
        print("[OK] %s -> %s" % (src, out))
        return 0

    errors = 0
    count = 0
    for root, dirs, files in os.walk(src):
        if not args.recursive:
            dirs[:] = []
        for fn in sorted(files):
            if not fn.lower().endswith(".asm.txt"):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, src)
            out = None
            if args.output:
                # 同样，直接去掉两次后缀，输出无后缀文件名
                out = os.path.join(args.output,
                                   os.path.splitext(os.path.splitext(rel)[0])[0])
            try:
                process_file(path, out, args.encoding)
                count += 1
            except ScriptError as e:
                print("[失败] %s: %s" % (path, e), file=sys.stderr)
                errors += 1
        if not args.recursive:
            break
    print("完成：%d 个文件，%d 个失败" % (count, errors))
    return 0 if errors == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())