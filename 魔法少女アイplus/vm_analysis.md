# scr.bnd / 魔法少女アイ plus DVD 脚本 VM 分析

本文是 `opcodelist.py`、`disassembler.py`、`assembler.py` 的格式真值源。
所有结论均来自对 `aiplusdvd.exe` 的静态反汇编与 301 个样本的逐字节验证，
并对全部 300 个脚本做过「反汇编 → 汇编」零突变回归（SHA 级逐字节一致）。

- 目标：`scr.bnd`（Colors / Hue，2001-2002 引擎）
- 样本：`extracted/00000` … `extracted/00300`（`scr_bnd.py extract` 解包）
- 可执行文件：`aiplusdvd.exe`（PE32，ImageBase = 0x400000）
- 工具链：Python 3.9+，无第三方依赖

---

## 1. 归档容器 scr.bnd

```
u32 count
count × { u32 offset; u32 decomprlen; u32 size; }
data[...]
```

- `count = 301`，头部长度 `4 + count*12 = 3616 = 0xE20`。
- `offset` 指向该条目的 LZSS 压缩块；`size` 为压缩长度；`decomprlen` 为解压后长度。
- 条目按文件名 `00000`、`00001` … 顺序对应。

LZSS 解压参数（与 `aiplusdvd.exe` 一致）：

- 4 KB 环形窗口，初始填充 `0x00`，初始写入位置 `0xFEE`；
- 控制字节 bit=1：1 字节字面量；
- 控制字节 bit=0：2 字节匹配
  - `offset = ((hi & 0xF0) << 4) | lo`
  - `length = 3 + (hi & 0x0F)`
- 匹配时窗口位置与 offset 都自增，按 `0xFFF` 回绕。

`bnd.py` 的 `pack --base scr.bnd` 会复用未修改条目的原始压缩块，
因此只翻译少量文件时归档体积几乎不变；全量重建则使用全字面量编码
（`0xFF` + 8 字节），游戏解压器同样接受。

`00000` 不是脚本：内容为 `"ai_plus"` + 版本/配置字段，原样保留。

---

## 2. 脚本文件布局

脚本是 **4 字节对齐的 dword 流**，没有文件头；从头到尾都是指令，
最后一条通常是 `END`（0x23）。`PC` 是 **dword 下标**，不是字节偏移：

```
dword_index = byte_offset / 4
```

每条指令的首 dword：

```
31..24   opcode
23..8    保留，样本中恒为 0
 7..0    b0（编译器写入；每个 opcode 恒定，运行时调度器忽略）
```

即 `header = (opcode << 24) | b0`（小端写出后，字节 3 为 opcode）。

### 2.1 调度器证据

`0x412D50` 处：

```asm
mov  eax, [0x93C93C]        ; PC
mov  edx, [0x93D468]        ; code dword array
mov  ecx, [edx + eax*4]     ; 取指令 dword
shr  ecx, 24                ; 高字节 = opcode
movsx ecx, cl
inc  eax
dec  ecx                    ; 表下标 = opcode - 1
cmp  ecx, 0x22
ja   default
jmp  dword ptr [ecx*4 + 0x412E54]   ; 35 项跳转表
```

跳转表 `0x412E54` 共 35 项，对应 opcode `0x01..0x23`。
因此 opcode 0x00 不是有效指令；样本中也不存在。

### 2.2 b0 字段

`b0` 在样本中对每个 opcode 恒定，调度器在 `shr ecx, 24` 后完全丢弃它；
各 handler 也只从后续 dword 取操作数。它不影响执行，但属于原始字节，
工具会原样保留（`opcodelist.OPCODES[*]["b0"]`）。
推测它是编译器写入的“参数个数/栈效应”辅助字段，未证实。

---

## 3. 文本存储

文本指令使用「单元数（units）」而不是字节长度：

```
[units:u32] [文本字节] [0x00 0x00] [0x00 填充至 units*4]
```

- `units = ceil((len(text) + 2) / 4)`，全部 23,827 个文本块均取最小值；
- 文本中不允许出现 `0x00`；
- 编码为 CP932（Shift-JIS）；翻译后可改为 GBK；
- 文本指令之外的字节全部按原样保存。

工具在反汇编时验证：尾部 2 字节为终止符、其后全为零、中间无 NUL。
汇编时按新文本长度重算 `units` 与后续所有 PC 下标。

---

## 4. 跳转、调用与重定位

| 指令 | 操作数 | 语义 | 重定位 |
|---|---|---|---|
| `JUMP` (0x11) | 1 个 dword | `PC = arg`（同文件内跳转） | 必须 |
| `CHOICE` (0x07) | count + count*(units,text,target) | 选择后跳到 target | 必须 |
| `CALL_SCRIPT` (0x12) | (script_id, entry_pc) | 压栈、切换脚本、从目标脚本的 `entry_pc` 执行 | 目标文件内的入口需重定位 |

`JUMP` 的 157 个目标、`CHOICE` 的 228 个目标，全部落在记录边界上，
已逐一验证。`CALL_SCRIPT` 的第二个参数是 **目标脚本内** 的 dword 下标，
不是当前文件的；例如 `00299` 的调试菜单：

```
CALL_SCRIPT 1, 0x05     ; 进入 00001 的 0x14 字节处（"Ｓ１－００１" 标签）
```

`00001` 自身的 271 条调用全部是 `CALL_SCRIPT <场景文件>, 0`。

**重定位策略**：反汇编器把同文件内的跳转目标输出为 `loc_XXXXXXXX`
标签；汇编器先确定所有标签的 dword 下标，再回填。文本变长/变短后
不再依赖任何硬编码地址，因此可以安全翻译。

---

## 5. 操作码表

`形式` 中 `u32` 表示一个 4 字节操作数；`units` 表示 1 个长度字 + 文本块。
`PC 增量` 指执行后 PC 前进的 dword 数。

| op | mnemonic | 形式 | PC 增量 | handler | 说明 | 置信度 |
|---|---|---|---|---|---|---|
| 01 | PLAY_BGM | u32 | 2 | 0x4030C0 | 播放 BGM；0x3E8/0x3E9/0x3EA 为音量/停止特殊值 | 推断 |
| 02 | PLAY_SE | u32 | 2 | 0x403130 | 播放音效；同样支持 0x3E8..0x3EA | 推断 |
| 03 | PLAY_SOUND | u32,u32,u32 | 4 | 0x4031B0 | (id, channel, loop)，写入 3 个声道槽 | 确认 |
| 04 | SCREEN_EFFECT | u32 | 2 | 0x403210 | 屏幕/窗口绘制或淡入淡出 | 推断 |
| 05 | MESSAGE | u32 + units + text | 3+units | 0x412D9A → 0x407690 | (voice_id) + 对白 | 确认 |
| 06 | MESSAGE_AUTO | u32,u32 + units + text | 4+units | 0x412DAB → 0x407690 | 自动/特殊模式对白 | 确认 |
| 07 | CHOICE | u32 + count*(units+text+target) | 2+Σ(2+units) | 0x412DBC | 选项菜单 | 确认 |
| 08 | SET_VAR | u32,u32 | 3 | 0x403AF0 | 变量[arg1] = 字节(arg2) | 确认 |
| 09 | JMP_IF_VAR / SET_VARS | n==2: u32,u32；n>=4: n×u32 | 2+n | 0x403B20 | n==2：变量==1 时跳到 arg2；n>=4：(变量,值) 批量赋值 | 确认 |
| 0A | BRANCH_0A | u32,u32,u32 | 4 | 0x403C20 | 条件分支（本作未使用） | 推断 |
| 0B | INC_COUNTER | u32 | 2 | 0x403C70 | 计数器[arg]++ | 确认 |
| 0C | DEC_COUNTER | u32 | 2 | 0x403C90 | 计数器[arg]-- | 确认 |
| 0D | BRANCH_0D | u32,u32,u32 | 4 | 0x403CB0 | 条件分支（未使用） | 推断 |
| 0E | BRANCH_0E | u32,u32,u32 | 4 | 0x403D00 | 条件分支（未使用） | 推断 |
| 0F | BRANCH_0F | u32,u32,u32 | 4 | 0x403D50 | 条件分支（未使用） | 推断 |
| 10 | BRANCH_10 | u32,u32,u32 | 4 | 0x403DB0 | 条件分支（未使用） | 推断 |
| 11 | JUMP | u32 | 2 | 0x412DEE | 无条件跳转 | 确认 |
| 12 | CALL_SCRIPT | u32,u32 | 3 | 0x403E80 | 调用脚本（压 SJP 栈） | 确认 |
| 13 | RETURN | — | 1 | 0x410E30 | 从 CALL_SCRIPT 返回；空栈报 `RET-STACK-ERROR!!` | 确认 |
| 14 | LOAD_BG | u32,u32 | 3 | 0x407A40 | 加载背景层 | 确认 |
| 15 | CLEAR_BG | — | 1 | 0x407B90 | 释放背景层 | 确认 |
| 16 | LOAD_CHAR | u32,u32 | 3 | 0x407BC0 | 加载角色立绘层 | 确认 |
| 17 | CLEAR_CHAR | — | 1 | 0x407CC0 | 释放角色立绘层 | 确认 |
| 18 | LOAD_FG | u32,u32 | 3 | 0x407CF0 | 加载前景/特效层 | 确认 |
| 19 | CLEAR_FG | u32 | 2 | 0x407DE0 | 释放前景层 | 确认 |
| 1A | SKIP2 | u32,u32 | 3 | 0x412E20 | 跳过 2 个 dword（占位） | 确认 |
| 1B | NOP | — | 1 | 0x412DF7 | 空操作 | 确认 |
| 1C | WAIT | u32 | 2 | 0x403F20 | 等待指定毫秒 | 确认 |
| 1D | WAIT_STATE | — | 1 | 0x403F70 | 等待状态 0x0B（未使用） | 确认 |
| 1E | QUIT | — | 1 | 0x403F90 | 设置退出标志，状态 0x13 | 确认 |
| 1F | RANDOM | u32,u32 | 3 | 0x403FB0 | 随机数（未使用） | 确认 |
| 20 | SET_MODE | u32 | 2 | 0x404000 | 设置模式字节（未使用） | 推断 |
| 21 | TITLE | units + text | 2+units | 0x404030 | 章节标题，复制到标题缓冲 | 确认 |
| 22 | LABEL | units + text | 2+units | 0x4040A0 | 命名标签，运行时跳过文本 | 确认 |
| 23 | END | — | 1 | 0x4040C0 | 脚本终点哨兵，弹出“到达脚本终点”消息框 | 确认 |

> 0x01/0x02 的具体分工（BGM 还是 SE）仅由参数分布与调用上下文推断；
> 它们不影响汉化，翻译时保持数字参数不变即可。

### 5.1 0x07 CHOICE 的结构

```
CHOICE
  u32 count
  count × {
      u32 units
      text[units*4]
      u32 target_pc     ; 选中后跳到该 dword 下标
  }
```

`target_pc` 指向同文件的 `LABEL`（0x22）记录，已用 00003/00017/00023
等样本逐一核对。例如 00003 的 `0x42F * 4 = 0x10BC`，正好是
`LABEL "選択肢１Ａ"` 的记录起点。

### 5.2 0x09 JMP_IF_VAR / SET_VARS

```
u32 n
n == 2:
    u32 var        ; 变量号
    u32 target     ; 目标 PC（dword 下标）
    ; 若 var == 1，则 PC = target
n >= 4:
    n × u32        ; (变量号, 值) 成对批量赋值
```

`n == 2` 是**条件跳转**，不是赋值。`target` 必须随文本长度变化重定位，
否则会跳到错误的记录。00165 的选择状态机就依赖这一指令；旧工具把它当
普通数据，导致翻译后三个选项选完仍循环。

`n == 2` 的记录总长为 `2 + n = 4` 个 dword（头 + n + var + target）。
长度算错会让后续标签整体错位。

`n >= 4` 才是真正的批量赋值，例如
`SET_VARS 0x14,1, 0x15,1, 0x16,1, 0x17,0x514`。

### 5.3 0x13 与 0x23

`RETURN` 的 handler 在调用栈为空时，会以 `0x43C680` 处的字符串
`RET-STACK-ERROR!!` 弹出错误框；非空时从 `0x93D334/0x93D338`
弹回段号与 PC。这确认 0x12/0x13 是配对调用/返回。

`END` 直接执行会以 `0x43C614` 的
`スクリプトの終端に到達しました。` 弹框，并结束脚本；
正常脚本都会在 `RETURN` 后留下这个哨兵。

---

## 6. 文本渲染与编码

文本绘制函数位于 `0x407690` 附近：

- 每次从文本指针取 **2 字节**，与 `"CR"`（`0x43C5FC`）比较；
  `CR` 被解释为显式换行，随后指针 +2；
- 非 `CR` 时按 2 字节一个字符送 `0x4033F0` 绘制；
- 行字符计数达到 `0x16 = 22` 时自动换行。

因此：

1. 文本必须按 **双字节字符** 组织；ASCII 字符会破坏 2 字节步进
   （`CR` 是唯一的显式例外）。汉化时请使用全角标点，不要插入半角
   英文字母/数字。
2. 自动换行宽度约 22 个全角字符，建议每行不超过 20 字。
3. 字体由 `CreateFontA` 创建（`0x41677E`），charset 硬编码为
   `0x80 = SHIFTJIS_CHARSET`；`system.dat` 被读入 `0x44C158` 的结构体，
   `+0x00` 为 BGM 音量、`+0x04` 为字号（0x28）、`+0x08` 为一个标志字节
   （0x01），字体名从 **偏移 9** 开始（默认 `ＭＳ ゴシック`）。

### 汉化所用编码

把二进制文本改成 GBK 并在 `CreateFontA` 中把 charset 改为
`0x86 = GB2312_CHARSET`、字体名改为 `SimSun`/`宋体` 后，
`TextOutA` 即可按 GBK 解码并绘制简体中文。`GBK.py` 完成这两处补丁。

GBK 与 CP932 同为双字节编码，上述「每 2 字节一个字符」的循环
仍然成立；`CR` 仍是 ASCII 的 `0x43 0x52`，不会被误判。

---

## 7. 跨文件调用

`CALL_SCRIPT` 的第一个参数是脚本编号（00001…00300 对应 1…300）。
`00001` 是场景索引：`LABEL "Ｓ１－００１"` 后紧跟
`CALL_SCRIPT <该场景文件号>, 0`。

`00299` 是开发调试菜单，它用 `CALL_SCRIPT 1, <entry>` 直接进入
`00001` 的各个标签。`entry` 是 `00001` 内的 dword 下标，因此：

- 如果保持 `00001` 的文本长度不变（例如不翻译其中的场景名），
  `00299` 的 34 个入口仍然有效；
- 如果翻译了 `00001` 的标签且长度改变，需要同步重算 `00299` 的入口
  （当前工具不做跨文件标签解析；这两个文件都不是正常流程的剧情文本）。

---

## 8. 零突变验证

```bash
python disassembler.py extracted -o dis
python assembler.py dis -o rebuild
# 再逐文件比较 dis 与 rebuild
```

对每个脚本执行：

1. `disassembler` 生成 UTF-8 语义汇编；
2. `assembler` 以同一编码重建；
3. 与原始二进制逐字节比较。

`00000`（配置文件）不参与反汇编，打包时原样复制。

---

## 9. 未完成/存疑项

- `0x01/0x02` 的 BGM/SE 分工未从资源表确认；
- `0x04` 的效果类型（淡入淡出/窗口绘制）未细究；
- `0x0A/0x0D..0x10` 条件分支的具体条件未分析（本作样本未使用）；
- `b0` 字段的编译器语义未知，但工具逐字节保留。
