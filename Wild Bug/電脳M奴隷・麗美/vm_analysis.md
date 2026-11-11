# WBUG_SCN v0.3 脚本字节码 VM 分析

本文档是 `opcodelist.py` / `disassembler.py` / `assembler.py` 的唯一真值源，
内容全部来自对 `REIMI.EXE` 的静态逆向（IDA 伪 C 分析），
并用 `REIMI00.WBP` 中全部 70 个 `.WBI` 脚本做了逐字节验证。

## 0. 结论摘要

| 项目 | 结论 |
|---|---|
| 容器 | `WBUG_SCN v0.3 \x1A\x00` + 10 个 u32 字段 + 名字表 / 模块名 / 代码 / 数据 |
| 取指 | 4 字节小端 dword 缓冲；指令 4 字节对齐，`0x3F`(NOP) 填充 |
| 指令 | `opcode[1]`；opcode≠0x3F 时再读 `参数个数[1]`；flags.bit0 时再读 3 字节行号 |
| 操作数 | 1 字节描述符：高 4 位=寻址方式，低 4 位=立即数编码 |
| 指令集 | 0x00–0x3F 为解释器核心指令；0x40–0xFE 为宿主命令 |
| 文本 | 独立的 data 段，NUL 结尾、偏移引用；引用点必须内联显示 |
| 验证 | 70/70 脚本 `反汇编 → 汇编` 逐字节一致 |

## 1. 容器格式

```
偏移   内容
0x00   char magic[16] = "WBUG_SCN v0.3 \x1A\x00"
0x10   u32 flags          bit0: 有模块名区 + 每条指令带 3 字节行号
                          bit1: 有入口名字表
0x14   u32 entry          默认入口（代码段内偏移）
0x18   u32 code_off
0x1C   u32 code_size
0x20   u32 data_off
0x24   u32 data_size
0x28   u32 name_off       没有时为 0xFFFFFFFF
0x2C   u32 name_count
0x30   u32 extra_off      没有时为 0xFFFFFFFF
0x34   u32 extra_size
```

节的物理顺序固定为：名字表 → 模块名 → 代码 → 数据（各自紧接，无额外对齐）。
名字表每项 36 字节：`char name[32]; u32 entry;`（例如 `@PS-0001`、`@PR-0001`）。
模块名区是 NUL 结尾的模块名（如 `LOAD.SCN`），长度补齐到 `align4(len+2)`。

加载器 `sub_426F86`：

```
memcmp(buf, "WBUG_SCN", 8)
buf[10]=='0' && buf[12]=='3'            // 版本必须是 v0.3
code  = buf + dword[6],  size dword[7]
data  = buf + dword[8],  size dword[9]
names = buf + dword[10], count dword[11]  (每项 36 字节)
extra = buf + dword[12], size dword[13]
entry = dword[5]（-1 表示无默认入口）
```

## 2. 取指与指令边界

主循环 `sub_4291CD`：

```
loop:
    op = read_byte()
    if op == 0x3F:            # NOP
        count = 0
    else:
        count = read_byte()
        if flags & 1:
            file = read_byte(); line = read_u16()
        for i in range(count):
            parse_operand(&desc[i*8])
    dispatch(op, count, desc)
```

关键点：字节读取用的是 **4 字节 dword 缓冲**（`sub_427643`）：

```
if buffer_count == 0:
    buffer = *(u32*)(code + pc); pc += 4; buffer_count = 4
b = buffer & 0xFF; buffer >>= 8; buffer_count -= 1
```

因此 `pc` 始终是 4 的倍数，指令也都被编译器对齐到 4 字节（不足用 `0x3F` 填充）。
一个 4 字节立即数（kind 3）由 `sub_4276B8` 读取：它直接读 `*(u32*)(code + pc)`
并 `pc += 4`，**丢弃缓冲区里剩余的字节**（这些字节仍会被后续取指当作 NOP 执行）。
这解释了为什么反汇编器必须模拟 dword 缓冲，而不能简单地顺序读字节。

## 3. 操作数描述符

1 字节：`mode = b >> 4`，`kind = b & 0x0F`。

### 3.1 kind（立即数编码）

| kind | 名称 | 长度 | 说明 |
|---|---|---|---|
| 0x0 | u8 | 1 | 无符号 |
| 0x1 | u16 | 2 | 无符号 |
| 0x2 | u24 | 3 | 无符号 |
| 0x3 | u32 | 4 | 在下一个 dword 边界读取（见上） |
| 0x4 | i8 | 1 | 有符号 |
| 0x5 | i16 | 2 | 有符号 |
| 0x6 | i24 | 3 | 有符号 |
| 0xD | one | 0 | 常量 1 |
| 0xE | zero | 0 | 常量 0 |
| 0xF | minus1 | 0 | 常量 -1 |

编译器的选择规律（对语料统计得到，汇编器按此复现）：
数值 0/1/-1 用 0xE/0xD/0xF；其余按最小值宽选择 0x0/0x1/0x2；
负值用 0x4/0x5/0x6；**代码地址（mode 1）与 MESSAGE(0x80) 的文本指针固定用 0x3**。

### 3.2 mode（寻址方式）

| mode | 名称 | 读取（sub_427952） | 写入（sub_427DE1） |
|---|---|---|---|
| 0x0 | imm | 立即数 | 不可写 |
| 0x1 | addr | 立即数（代码地址） | 不可写 |
| 0x2 | data | 数据段偏移（+数据基址） | 不可写 |
| 0x3 | var | 变量 `var[index]` | `var[index] = v`（index < 256） |
| 0x4 | bit | 数据段 `data[imm]` 的第 imm 位 | 置位/清位 |
| 0x5 | dbyte | `data[index]`（有符号字节） | 写字节 |
| 0x6 | dword | `data[index]`（dword） | 写 dword |
| 0x7 | dword0 | 同上，负数夹到 0 | 同上，负数夹到 0 |
| 0x8 | dbit | `data[data[index]]` 的位 | 置位/清位 |
| 0x9 | dbyte2 | `data[data[index]]` 字节 | 写字节 |
| 0xA | dword2 | `data[data[index]]` dword | 写 dword |
| 0xB | dword2_0 | 同上，夹 0 | 同上 |
| 0xC | bit2 | 与 0x4 相同 | 与 0x4 相同 |
| 0xD | dbyte3 | 与 0x5 相同 | 与 0x5 相同 |
| 0xE | dword3 | 与 0x6 相同 | 与 0x6 相同 |
| 0xF | dword3_0 | 与 0x7 相同 | 与 0x7 相同 |

0xC–0xF 与 0x4–0x7 在本引擎里语义完全相同，编译器对两者都有使用，
因此汇编器按原文的 mode 原样写回。

## 4. 指令集

### 4.1 核心指令 0x00–0x3F（sub_428E41）

| op | 助记符 | 参数 | 语义 |
|---|---|---|---|
| 0x00 | END | 0 | 代码结尾标记（解释器报错码 19，正常不会执行到） |
| 0x01 | SYS01 | 2 | 宿主回调 258（本语料未使用） |
| 0x02 | MOV | 2 | dst = src |
| 0x04 | SETM1 | 1 | dst = -1 |
| 0x05 | SET0 | 1 | dst = 0 |
| 0x06 | FILL | 3 | dst[lo..hi] = value |
| 0x08 | ADD | 2 | dst += src |
| 0x09 | SUB | 2 | dst -= src |
| 0x0A | MUL | 2 | dst *= src |
| 0x0B | DIV | 2 | dst /= src |
| 0x0C | MOD | 2 | dst %= src |
| 0x0D | NEG | 1 | dst = -dst |
| 0x10 | AND | 2 | dst &= src |
| 0x11 | OR | 2 | dst \|= src |
| 0x12 | XOR | 2 | dst ^= src |
| 0x13 | NOT | 1 | dst = ~dst |
| 0x18 | ROT | 2 | 按操作数类型循环移位 |
| 0x19 | ROTR | 2 | 反向循环移位 |
| 0x1A | SHL | 2 | dst <<= src |
| 0x1B | SHR | 2 | dst >>= src |
| 0x20 | TRUE | 3 | dst = 1 |
| 0x21 | EQ | 3 | dst = (a == b) |
| 0x22 | GT | 3 | dst = (a > b) |
| 0x23 | LT | 3 | dst = (a < b) |
| 0x27 | NAND | 3 | dst = !(a && b) |
| 0x28 | ANDL | 3 | dst = (a && b) |
| 0x2C | GE | 3 | dst = (a >= b) |
| 0x2D | LE | 3 | dst = (a <= b) |
| 0x2E | NE | 3 | dst = (a != b) |
| 0x2F | FALSE | 3 | dst = 0 |
| 0x30 | JMP | 1 | 跳转 |
| 0x31 | JZ | 2 | 条件为假时跳转 |
| 0x32 | JNZ | 2 | 条件为真时跳转 |
| 0x33 | CALL | 1 | 调用代码地址（压栈帧） |
| 0x34 | CALLN | 1 | 按名字调用脚本/段（压栈帧） |
| 0x35 | CALLN2 | 2 | 按名字 + 标签调用 |
| 0x36 | CALLF | 1 | 按名字调用（不压栈帧） |
| 0x37 | CALLF2 | 2 | 按名字 + 标签调用（不压栈帧） |
| 0x3C | RET | 0 | 子程序返回 |
| 0x3D | RETV | 1 | 带返回值返回 |
| 0x3E | HALT | 0 | 停止脚本 |
| 0x3F | NOP | 0 | 空操作 / 对齐填充 |

其余 0x03/0x07/0x0E/0x0F/0x14–0x17/0x1C–0x1F/0x24–0x26/0x29–0x2B/0x38–0x3B
在解释器里走错误分支，视为非法指令；`opcodelist.py` 中保留为 `UNUSED_xx`。

### 4.2 宿主命令 0x40–0xFE（sub_406622 → sub_41FFE0）

参数个数由指令流给出，不需要按 opcode 硬编码。已确认语义的：

| op | 助记符 | 官方名（处理函数内的调试字符串） |
|---|---|---|
| 0x40 | REGIST_MSG_FRAME | RegistMessageFrame |
| 0x80 | MESSAGE | MessageOut |
| 0x81 | MESSAGE_ON | MessageOn |
| 0x82 | MESSAGE_OFF | MessageOff |
| 0x83 | MESSAGE_PAGE | MassagePageRenew |
| 0x84 | MESSAGE_MOVE | MessageMove |
| 0x86 | MESSAGE_SELECT | MessageSelect |
| 0x87 | MESSAGE_WAVE | MessageWave |
| 0x8A | MESSAGE_RELEASE | MessageRelease |
| 0x90 | BODY_O_L_CHANGE | BodyOLChange |
| 0x91 | BODY_RELEASE | BodyRelease |
| 0x92 | BODY_DISP | BodyDisp |
| 0x93 | BODY_MOVE | BodyMove |
| 0x97 | BITMAP_RELEASE | BitmapRelease |
| 0x98 | BITMAP_BLT | BitmapBlt |
| 0x9A | SPRT_SETUP_UNI | SprtSetupUniBitmap |
| 0xA0 | SPRT_RELEASE | SprtRelease |
| 0xA1 | SPRT_INFO_GET | SprtInfoGet |
| 0xA2 | SPRT_DISP | SprtDisp |
| 0xA5 | SPRT_MOVE | SprtMove |
| 0xA8 | SPRT_ATT_CHANGE | SprtAttChange |
| 0xA9 | SPRT_OL_DISP | Sprt(Body)OLDisp |
| 0xB4 | SPRT_MULTI_DM | SprtMultiDMEntry |

其余宿主命令（0x41–0x7F、0x85、0x88–0x8F、0x94–0x96、0x99、
0x9B–0x9F、0xA3–0xA4、0xA6–0xA7、0xAA–0xB3、0xB5–0xFB 等）在
`opcodelist.py` 中以 `SYS_xx` 命名，参数个数照抄指令流。它们的处理函数
位于 `sub_4040A8`–`sub_41FDF6`，本次未逐个确认语义，标记为**未验证**。

0xFF 在解释器中走 `a2 > 62 && a2 != 63` 分支，会结束解释循环，命名 `STOP`。

## 5. 数据段与文本

数据段是一串 NUL 结尾的字符串，字符串之间用 0–3 个 0 字节补齐；
指令用 `mode=2` 的立即数（相对数据段的偏移）引用它们。
所有引用都落在字符串首字节（70 个脚本全部验证，没有指向字符串内部的引用）。

反汇编器把它建模为两类记录：

```
TEXT(id=原偏移)  字符串内容（不含结尾 NUL）
GAP(id=原偏移)   补齐用的原始字节（通常全 0）
```

记录按原偏移排序后依次排列即可还原原数据段：`TEXT` 写内容 + `0x00`，`GAP` 原样写。
引用点内联写成 `Text(0x0000 "…")`，同一个 id 在多处引用时共享同一定义；
修改文本长度后汇编器会重新计算所有 TEXT 的新偏移，并回填所有 `mode=2` 操作数。

## 6. 与工具实现的对应

| 汇编语法 | 含义 |
|---|---|
| `loc_XXXX:` | 代码标签（仅分支目标/入口/名字表入口） |
| `.line N` / `.line N, F` | 下一条指令的 3 字节行号信息（flags.bit0） |
| `MESSAGE Text(0x0000) "…"` | 内联文本引用（id = 原数据段偏移） |
| `#123` / `#-1` | 立即数 |
| `v3` | 变量槽 |
| `bit[5]` | 数据段位 |
| `dword[0x6B]` | 数据段 dword |
| `{k=X}` | 立即数编码与规范编码不同时，显式保留 kind |
| `.data` 中的 `gap_XXXX: .bytes …` | 补齐字节 |
| `.data` 中的 `text_XXXX: .text "…"` | 未被引用的字符串 |

汇编器布局顺序：数据段（TEXT/GAP 按 id 排序）→ 代码段（每条指令 4 字节对齐、
`0x3F` 填充、kind 3 立即数对齐到下一个 dword）→ 名字表 → 模块名 → 文件头。

## 7. 验证

| 项目 | 结果 |
|---|---|
| 70 个 `.WBI` 反汇编 | 全部成功，指令流恰好耗尽代码段 |
| 70 个 `.WBI` 反汇编→汇编 | **逐字节一致**（SHA-256 相同） |
| 字符串改写 | 改一条文本后重汇编，长度/偏移/引用自动更新，可再次反汇编 |
| 编码 | `--encoding cp932`（原文）与 `--encoding gbk`（中文）均验证通过 |

反汇编清单 `asm.txt` 固定写成 **UTF-8**；`--encoding` 只决定脚本内嵌字符串字节的
解码（反汇编）与回写（汇编）编码，二者互不影响。

## 8. 未知项

1. 0x40–0xFE 中约 150 个宿主命令未逐个确认语义（仅确认上表 23 个），
   以 `SYS_xx` 命名并在 `opcodelist.py` 中标注 "unverified"。
2. `flags` 的 bit1 与名字表的关系、以及 bit2 以上是否还有含义，未在其他样本上验证。
3. 名字表项 `name[32]` 的合法字符集未穷举（本语料只有 `@PS-nnnn` / `@PR-nnnn`）。
