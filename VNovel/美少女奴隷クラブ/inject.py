#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inject.py — 把译文 json 写回 .scr（xor 0x44）
============================================

与 extract.py 配对，直接对着原始 .scr 重建，不经过 asm：

    Scr/*.scr --extract--> json_jp --(翻译)--> json_cn --inject--> cn_scr/*.scr

行为：

  * 从**原始 .scr** 重新推导页结构（哪些行属于哪一页、缩进、页尾标记），
    所以 json 只需要 ``message``，不允许增删条目；
  * message 有改动的条目按 **20 个全角字符**重新折行，首行补回 ``　`` 缩进，
    末行补回原来的 ``●▲`` / ``▲`` / ``■``；``「●`` 会拆回单独一行；
  * message 没改动的条目**逐字节保留原行**（只按目标编码重新编码）；
  * 其余行（命令 / 注释 / 标签 / 空行）原样保留；
  * 目标编码默认 gbk；GBK 里没有的字符按 cp932 回退写出（并给出提示）。

用法：

    python inject.py json_cn -o cn_scr                  # json → 加密 scr（默认）
    python inject.py json_cn -o txt --no-encrypt        # json → UTF-8 文本（方便改 ●▲）
    python inject.py txt文件夹 -o cn_scr --encrypt      # UTF-8 文本 → 加密 scr
    python inject.py scr文件夹 -o txt --no-encrypt      # scr → UTF-8 文本
    python inject.py json_cn -o cn_scr --src Scr

`--no-encrypt` / `-不加密`：不输出 .scr，改输出同名 `.scr.txt`（UTF-8，逐行可读）。
`--encrypt` / `-加密`：把文本/明文脚本打包成 xor44 的 .scr。

文本回打包时的编码：**对白行用 `--encoding`（默认 gbk），命令 / 注释 / 标签用
`--src-encoding`（默认 cp932，即保持 JIS 不动）**。
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract import (  # noqa: E402
    MARKERS, classify, collect_entries, read_scr, write_scr,
)

# 折行宽度（全角字符数）
LINE_WIDTH = 20.0

# 禁则：不能出现在行首的字符（原稿里标点从不出现于行首）
NO_START = set(
    "、。，．・：；？！‥ー"
    "」』】〕》〉）］｝"
    "%,.!?:;)]}"
)


def char_width(ch: str) -> float:
    return 0.5 if ord(ch) < 0x80 else 1.0


def wrap_text(text: str, width: float = LINE_WIDTH):
    """按全角宽度折行，做基本禁则处理。返回行列表。"""
    if not text:
        return [""]
    lines = []
    i, n = 0, len(text)
    while i < n:
        cur = []
        w = 0.0
        while i < n:
            cw = char_width(text[i])
            if cur and w + cw > width:
                break
            cur.append(text[i])
            w += cw
            i += 1
        # 下一行若以禁则字符开头，把本行末字挪到下一行
        while i < n and text[i] in NO_START and len(cur) > 1:
            i -= 1
            cur.pop()
        lines.append("".join(cur))
    return lines


def build_lines(entry, message: str):
    """把一条译文还原成若干对白行。"""
    msg = message.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

    if entry["indent"] and msg.startswith("\u3000"):
        msg = msg[1:]
    while msg and msg[-1] in MARKERS:
        msg = msg[:-1]

    if entry["kind"] == "title":
        return [msg + entry["marker"]]

    lead = entry.get("lead")
    if lead and msg.startswith(lead):
        out = [lead + entry["lead_marker"]] + wrap_text(msg[len(lead):])
    elif lead and msg.startswith("\u300c"):
        out = ["\u300c" + entry["lead_marker"]] + wrap_text(msg[1:])
    else:
        out = wrap_text(("\u3000" if entry["indent"] else "") + msg)
        if lead:
            out[0] += entry["lead_marker"]

    if entry.get("marker_own_line"):
        out.append(entry["marker"])
    else:
        out[-1] += entry["marker"]
    return out


def encode_line(s: str, encoding: str, fallback: str):
    """按目标编码编码；个别字符编不了就用回退编码写，返回 (bytes, 回退字符数)。"""
    try:
        return s.encode(encoding), 0
    except UnicodeEncodeError:
        pass
    buf = bytearray()
    missed = 0
    for ch in s:
        try:
            buf += ch.encode(encoding)
        except UnicodeEncodeError:
            buf += ch.encode(fallback)
            missed += 1
    return bytes(buf), missed


def write_txt(path: Path, texts, final_newline: bool):
    """写 UTF-8 文本（CRLF、无 BOM），一行对应脚本一行。"""
    body = "\r\n".join(texts)
    if final_newline:
        body += "\r\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(body)


def decode_line(b: bytes, encoding: str, src_encoding: str) -> str:
    """命令/注释/标签按源编码解码，对白按目标编码解码。"""
    first = b[:1]
    enc = src_encoding if (not b.strip() or first in (b";", b":", b"#")) else encoding
    try:
        return b.decode(enc)
    except UnicodeDecodeError:
        return b.decode(enc, "replace")


def inject_file(src: Path, json_path: Path, out_path: Path,
                encoding="gbk", fallback="cp932", src_encoding="cp932",
                as_txt=False):
    """返回 (条目数, 是否有改动, 回退字符数, 保持原编码行数)。

    as_txt=True 时输出 UTF-8 文本，否则输出 xor44 的 .scr。
    """
    byte_lines, eol, final_newline, src_plain = read_scr(src)
    texts = [x.decode(src_encoding) for x in byte_lines]
    records = [classify(t) for t in texts]
    entries = collect_entries(records)

    data = json.loads(json_path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        raise SystemExit("%s: 不是 JSON 数组" % json_path)
    if len(data) != len(entries):
        raise SystemExit("%s: 条目数 %d != 原文可提取条目 %d"
                         % (json_path, len(data), len(entries)))

    out = []          # [(bytes, text)]
    cursor = 0
    changed = False
    missed_total = 0
    kept_total = 0

    def push_other(a, b):
        for k in range(a, b):
            out.append((byte_lines[k], texts[k]))

    for idx, (entry, item) in enumerate(zip(entries, data)):
        if "message" not in item:
            raise SystemExit("%s 第 %d 条缺少 message" % (json_path, idx + 1))
        if item["message"] != entry["message"]:
            changed = True
        push_other(cursor, entry["start"])
        if item["message"] == entry["message"]:
            # 未改动：原文照搬；若目标编码不同则顺手转换（转不了就保留原字节）
            for k in range(entry["start"], entry["end"]):
                try:
                    b = texts[k].encode(encoding)
                except UnicodeEncodeError:
                    b = byte_lines[k]
                    kept_total += 1
                out.append((b, texts[k]))
        else:
            new_lines = build_lines(entry, item["message"])
            if entry.get("lead"):
                # 「● 单独一行，中间的命令/注释行原样保留
                b, m = encode_line(new_lines[0], encoding, fallback)
                out.append((b, new_lines[0]))
                missed_total += m
                push_other(entry["start"] + 1, entry["body_start"])
                rest = new_lines[1:]
            else:
                rest = new_lines
            for s in rest:
                b, m = encode_line(s, encoding, fallback)
                out.append((b, s))
                missed_total += m
        cursor = entry["end"]
    push_other(cursor, len(byte_lines))

    if as_txt:
        write_txt(out_path, [t for _, t in out], final_newline)
    else:
        write_scr(out_path, [b for b, _ in out], eol, final_newline, src_plain)
    return len(entries), changed, missed_total, kept_total


def iter_json(root: Path, recursive=False):
    for cur, dirs, files in os.walk(root):
        if not recursive:
            dirs[:] = []
        for fn in sorted(files):
            if fn.lower().endswith(".json") and fn != "manifest.json":
                yield Path(cur) / fn


def scr_to_txt(src: Path, dst: Path, encoding: str, src_encoding: str):
    """明文/加密 .scr -> UTF-8 文本。"""
    byte_lines, eol, final_newline, plain = read_scr(src)
    texts = [decode_line(b, encoding, src_encoding) for b in byte_lines]
    write_txt(dst, texts, final_newline)
    return len(texts)


def pack_txt(src: Path, dst: Path, encoding: str, src_encoding: str, fallback: str):
    """UTF-8 文本 -> xor44 的 .scr。对白用 encoding，其余用 src_encoding（JIS）。"""
    text = src.read_text(encoding="utf-8-sig")
    final_newline = text.endswith("\n")
    body = text.replace("\r\n", "\n").replace("\r", "\n")
    if final_newline:
        body = body[:-1]
    lines = body.split("\n") if body else []

    out = []
    missed = 0
    for ln in lines:
        kind, _ = classify(ln)
        enc = encoding if kind == "T" else src_encoding
        try:
            out.append(ln.encode(enc))
        except UnicodeEncodeError:
            b, m = encode_line(ln, enc, fallback)
            out.append(b)
            missed += m
    data = b"\r\n".join(out) + (b"\r\n" if final_newline else b"")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(bytes(b ^ 0x44 for b in data))
    return len(lines), missed


def detect_input(path: Path):
    if path.is_file():
        s = path.suffix.lower()
        if s == ".json":
            return "json"
        if s == ".txt":
            return "txt"
        if s == ".scr":
            return "scr"
        return None
    names = [p.name.lower() for p in path.iterdir() if p.is_file()]
    if any(n.endswith(".json") and n != "manifest.json" for n in names):
        return "json"
    if any(n.endswith(".txt") for n in names):
        return "txt"
    if any(n.endswith(".scr") for n in names):
        return "scr"
    return None


def list_files(path: Path, suffix: str, recursive=False):
    if path.is_file():
        return [path]
    out = []
    for cur, dirs, files in os.walk(path):
        if not recursive:
            dirs[:] = []
        for fn in sorted(files):
            if fn.lower().endswith(suffix):
                out.append(Path(cur) / fn)
    return out


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="inject.py",
        description="json 写回 .scr；也可在 .scr 与 UTF-8 文本之间互转",
        epilog="示例:\n"
               "  python inject.py json_cn -o cn_scr                # json -> 加密 scr\n"
               "  python inject.py json_cn -o txt --no-encrypt      # json -> UTF-8 文本\n"
               "  python inject.py txt文件夹 -o cn_scr --encrypt    # 文本 -> 加密 scr\n"
               "  python inject.py scr文件夹 -o txt --no-encrypt    # scr -> UTF-8 文本\n"
               "  python inject.py json_cn -o cn_scr --src Scr",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="译文 JSON / .scr / .txt 文件或文件夹")
    parser.add_argument("-o", "--out", default="cn_scr", help="输出目录（默认 cn_scr）")
    parser.add_argument("--src", default="Scr", help="原始 .scr 目录（默认 Scr）")
    parser.add_argument("--encoding", default="gbk",
                        help="对白文本编码（默认 gbk）")
    parser.add_argument("--src-encoding", default="cp932",
                        help="命令 / 注释编码（默认 cp932，即保持 JIS）")
    parser.add_argument("--fallback", default="cp932", help="编码缺失字符的回退编码")
    parser.add_argument("--no-encrypt", "-不加密", dest="no_encrypt", action="store_true",
                        help="输出 UTF-8 文本 .scr.txt（不写 .scr）")
    parser.add_argument("--encrypt", "-加密", dest="encrypt", action="store_true",
                        help="把文本 / 明文脚本打包成 xor44 的 .scr（默认）")
    parser.add_argument("--in-place", action="store_true",
                        help="直接覆盖 --src（首次覆盖前备份 .bak）")
    parser.add_argument("--recursive", action="store_true", help="递归处理子目录")
    args = parser.parse_args(argv)

    if args.encrypt and args.no_encrypt:
        print("--encrypt 与 --no-encrypt 只能选一个", file=sys.stderr)
        return 2

    inp = Path(args.input)
    if not inp.exists():
        print("输入不存在: %s" % inp, file=sys.stderr)
        return 2
    kind = detect_input(inp)
    if kind is None:
        print("认不出输入类型（需要 .json / .scr / .txt）: %s" % inp, file=sys.stderr)
        return 2
    out_dir = Path(args.out)

    # ---- 文本 -> scr ----
    if kind == "txt":
        files = list_files(inp, ".txt", args.recursive)
        if not files:
            print("没有找到 .txt: %s" % inp, file=sys.stderr)
            return 2
        out_dir.mkdir(parents=True, exist_ok=True)
        total = missed_all = 0
        for f in files:
            dst = out_dir / f.name[:-4]          # S00_01.scr.txt -> S00_01.scr
            n, missed = pack_txt(f, dst, args.encoding, args.src_encoding, args.fallback)
            total += n
            missed_all += missed
            print("[OK] %s -> %s  (%d 行%s)"
                  % (f.name, dst.name, n, ", %d 字符回退" % missed if missed else ""))
        print("完成：%d 个文本，%d 行%s -> %s/"
              % (len(files), total,
                 "，共 %d 字符回退" % missed_all if missed_all else "", out_dir))
        return 0

    # ---- scr -> scr / txt ----
    if kind == "scr":
        files = list_files(inp, ".scr", args.recursive)
        if not files:
            print("没有找到 .scr: %s" % inp, file=sys.stderr)
            return 2
        out_dir.mkdir(parents=True, exist_ok=True)
        for f in files:
            if args.no_encrypt:
                dst = out_dir / (f.name + ".txt")
                n = scr_to_txt(f, dst, args.encoding, args.src_encoding)
                print("[OK] %s -> %s  (%d 行)" % (f.name, dst.name, n))
            else:
                raw = f.read_bytes()
                if raw[:1] == b";":
                    raw = bytes(b ^ 0x44 for b in raw)
                (out_dir / f.name).write_bytes(raw)
                print("[OK] %s -> %s  (加密)" % (f.name, f.name))
        print("完成：%d 个脚本 -> %s/" % (len(files), out_dir))
        return 0

    # ---- json 注入 ----
    if args.in_place and args.no_encrypt:
        print("--in-place 只能配合 .scr 输出，不能和 --no-encrypt 一起用", file=sys.stderr)
        return 2
    src_dir = Path(args.src)
    if not src_dir.exists():
        print("原始脚本目录不存在: %s（用 --src 指定）" % src_dir, file=sys.stderr)
        return 2

    files = list_files(inp, ".json", args.recursive)
    files = [f for f in files if f.name != "manifest.json"]
    if not files:
        print("没有找到 .json 文件: %s" % inp, file=sys.stderr)
        return 2

    if not args.in_place:
        out_dir.mkdir(parents=True, exist_ok=True)

    total = done = changed_files = fallback_chars = 0
    for jf in files:
        scr_name = jf.name[: -len(".json")]          # S00_01.scr
        src_scr = src_dir / scr_name
        if not src_scr.exists():
            print("[跳过] %s（找不到 %s）" % (jf.name, src_scr))
            continue
        if args.in_place:
            target = src_scr
            bak = src_scr.with_name(src_scr.name + ".bak")
            if not bak.exists():
                bak.write_bytes(src_scr.read_bytes())
        else:
            target = out_dir / (scr_name + ".txt" if args.no_encrypt else scr_name)
        n, changed, missed, kept = inject_file(
            src_scr, jf, target, args.encoding, args.fallback,
            args.src_encoding, args.no_encrypt)
        total += n
        done += 1
        changed_files += 1 if changed else 0
        fallback_chars += missed
        extra = ""
        if kept:
            extra += ", %d 行保持原编码" % kept
        if args.no_encrypt:
            extra += ", 文本"
        print("[OK] %s -> %s  (%d 条%s%s%s)"
              % (jf.name, target.name, n, ", 有改动" if changed else "",
                 ", %d 字符回退" % missed if missed else "", extra))

    print("完成：%d 个 json，%d 条，%d 个有改动%s -> %s（%s）"
          % (done, total, changed_files,
             "，共 %d 字符回退" % fallback_chars if fallback_chars else "",
             "原地" if args.in_place else str(out_dir) + "/",
             "UTF-8 文本" if args.no_encrypt else "xor44"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
