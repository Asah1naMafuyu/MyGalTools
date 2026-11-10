# VNOVEL 脚本格式与引擎分析（SCRIPT_FORMAT.md）

目标：`美少女奴隷クラブ` / `D_Club.exe`（游戏根目录，内含 `D_Club\` 数据目录）
用途：记录脚本容器格式、命令语法与引擎行为，是本项目工具的**唯一真值源**。
`extract.py` / `inject.py` / `gbk_patch.py` / `patch_voice.py` 的实现与本文冲突时，
以本文为准并同步修正代码。

---

## 1. 结论摘要

| 项目 | 结论 |
|---|---|
| 引擎 | "Visual Novel Player Ver 1.0"，内部名 `VNOVEL`，MFC 4.2 / MSVC 6 的 32 位 PE |
| 脚本 | `SCR\*.SCR`，**按行组织的文本脚本**，不是定长/变长二进制字节码 |
| 编码 | CP932（Shift-JIS），CRLF 换行 |
| 加密 | 整文件逐字节 `xor 0x44`；**当且仅当首字节不是 `;` 时**才异或 |
| 行类型 | `;` 注释 / `:` 标签 / `#` 命令 / 其它为对白文本 |
| 分派 | 大小写不敏感的**前缀**比较：先比 `#BG.`、`#SP1.` 等对象前缀，再比方法名 |
| 操作数 | 双引号字符串、十进制整数、逗号列表、`变量=值` 表达式 |
| 指令长度 | 行式：一条"指令"= 一行（不含 CRLF），长度由行内容决定 |
| 对齐 | 无。记录之间只有 CRLF，没有任何填充字节 |

> 重要：脚本的"指令"是**文本命令**，因此不存在 opcode 字节表；所谓"opcode"
> 就是 `#对象.方法` 这个字符串本身。行式文本可以直接增删行，跳转只认 `:` 标签，
> 所以工具不需要反汇编/汇编层，直接按行处理即可。

---

## 2. 证据基础

全部结论来自对 `D_Club.exe`（441,856 字节，PE32 i386，ImageBase 0x400000）的
静态逆向。逆向产出物在 `bishojo/exe/`（体积大，不随工具发布）：

| 文件 | 说明 |
|---|---|
| `D_Club_pseudocode.c` | 1953 个函数的 Hex-Rays 伪 C（全量） |
| `D_Club_full.asm` | IDA 全量反汇编清单 |
| `D_Club_functions.asm` | 按函数分块的汇编视图 |
| `D_Club_strings.txt` | 字符串表 |
| `D_Club_meta.txt` | 段、导入、入口 |
| `ida/dump_all.py` | 生成上述输出的 IDA 脚本 |
| `ida/xref_scan.py` | 关键字符串 xref / vtable 扫描脚本 |

复现命令：

```bat
"%IDADIR%\idat.exe" -A -S"exe\ida\dump_all.py" "exe\ida\D_Club.exe"
```

---

## 3. 引擎结构（与脚本相关的部分）

| 函数 | 作用 |
|---|---|
| `sub_408890` | `CVNovelDoc` 打开文档：读 `VAR.DEF/CG.DEF/EVENT.DEF/BGM.DEF`，再打开 `%s\SCR\%s`，构造 `CArchive` 并调用虚表槽 2（`Serialize`） |
| `sub_4083D0` | 无文档名时的打开路径：`FindFirstFileA("*.SCR")` 取第一个脚本，同样走 `Serialize` |
| `sub_408520` | `CVNovelDoc::Serialize`：一次性读出文件 → 解密 → 按 `\n` 切行 → 存入 `CStringArray` |
| `sub_40EE80` | 逐行执行器 `CVNovelView::ExecLine`：跳过 `;`/`:` 行，按首字符区分文本与命令并分派 |
| `sub_40C530` 等 | 视图/定时器/画面刷新，脚本语义之外的显示层 |
| `sub_410B80` | 读操作数：双引号字符串读入静态缓冲区 `byte_45BF38` |
| `sub_410D60` | 读操作数：十进制整数（`atoi` 风格，可带 `-`） |

对象 → 处理函数（由 `sub_40EE80` 的 `_strcmpi(..., aXxx)` 链反推）：

| 前缀 | 处理函数 |
|---|---|
| `#BG.` | `sub_411690` |
| `#SP1.` | `sub_413A20` |
| `#SP2.` | `sub_414150` |
| `#SP3.` | `sub_4148A0` |
| `#ANIME.` | `sub_418220` |
| `#ANIME2.` | `sub_418750` |
| `#VOICE.` | `sub_414FE0` |
| `#SOUND.` | `sub_415310` |
| `#BGM.` | `sub_415680` |
| `#GLASS` / `#GLASS.LOAD` | `sub_40D960` |
| `#WAIT` `#GO` `#TITLE` `#BACK` `#IF` `#LET` `#ENABLE` `#NAME` `#SELECT` `#MSGBOX` `#INPUT` `#DEBUG` `#END` `#JUMP` | 内联在 `sub_40EE80` |

除上述之外，`GS_`/`SG_` 之类并非命令；`#ON` / `#OFF` **不是独立命令**，
它们是 `#DEBUG` 的参数关键字（`sub_40EE80` 里 `aOn`/`aOff` 出现在读串之后）。

---

## 4. 脚本容器格式

### 4.1 解密

`sub_408520` 原文（伪 C 行 5639–5645）：

```c
(*(...))(... , result, v4);      /* CFile::Read 整个文件到 malloc 缓冲 */
v5[v4] = 0;
if ( *v5 != 59 ) {               /* 59 == ';' */
    for ( i = 0; i < v4; ++i )
        v5[i] ^= 0x44u;
}
```

结论：

* `raw[0] == ';'` → 文件是明文，直接使用；
* 否则 → 整文件 `xor 0x44`。
* **判定依据是原始字节**，不是解密后的内容。因此 `raw[0]` 只有两种可能：
  `';'`（明文）或 `0x7F`（`';' ^ 0x44`，加密）。本项目 56 个脚本全部为后者。

### 4.2 切行

同一函数随后：

```c
for ( j = strtok(v5, Delimiter); j; j = strtok(0, Delimiter) ) {
    v8 = strlen(j) + 1;
    if ( j[v8 - 2] == 13 )      /* 去掉行尾 CR */
        j[v8 - 2] = 0;
    CStringArray::SetAtGrow(..., j);
}
```

`Delimiter` 是 `.data:0x4541D0` 处的 2 字节 `"\n"`（紧跟 `asc_4541CC` 的 `';'`）。

由此得到三条硬性事实：

1. 只按 `\n` 切分，**行尾 CR 是内容的一部分后被单独剥掉**；
2. `strtok` 会**吞掉连续分隔符**，即空行在运行时被丢弃（但文件里可以存在空行，
   重建时必须原样保留）；
3. 文件末尾是否有 CRLF 不影响加载，但影响字节复原 → `extract.py` 记录、`inject.py` 原样还原。

### 4.3 记录类型

| 首字节 | 类型 | 引擎行为 |
|---|---|---|
| `;` | 注释 | 执行器跳过（`asc_4541CC` = `";"`） |
| `:` | 标签 | 执行器跳过，但 `#GO`/`#IF ... JUMP` 会按名字查找行号 |
| `#` | 命令 | 进入分派链（`asc_457238` = `"#"`） |
| 其它 | 对白文本 | 交给 `sub_415AC0` 绘制 |

对白文本行常见以全角空格 `U+3000`（`81 40`）起头表示缩进；行内 `●▲`、`■`
等符号是翻页/换行标记的视觉占位（由绘制函数处理，脚本语法层面就是普通字符）。

### 4.4 换行与对齐

脚本记录之间**只有** `0D 0A`，没有填充、没有对齐、没有指针表、没有偏移字段。
因此本格式不存在 `.align` 伪指令的需求。

---

## 5. 命令语法与分派

### 5.1 语法

```
line        := comment | label | command | text | empty
comment     := ';' { any-char }
label       := ':' name
command     := '#' object-tail
object-tail := OBJECT { '.' METHOD } [ args ]
```

* 分派用 `CString::Left(line, N)` + `_strcmpi`，**大小写不敏感**（`#bg.load`
  与 `#BG.LOAD` 等价）。
* 对象前缀本身带点：`aBg` 的内容是 `"#BG."`，`aSp1` 是 `"#SP1."`，
  单级命令 `aWait` 是 `"#WAIT"`（实测 `#WAIT1000` 也能命中，因为前缀匹配）。
* `#TITLE` 后面跟的是 CString（可含空格），`#GO` 后跟带引号的文件名。

### 5.2 操作数

两个专用读取函数决定了操作数的书写方式：

* `sub_410B80`：先 `TrimLeft`，可选跳过 `,`，再要求 `"`，一直读到下一个 `"`；
  没有引号则返回 0。→ 字符串操作数**必须带双引号**。
* `sub_410D60`：先 `TrimLeft`，可选跳过 `,`，再读可选 `-` 和连续数字。
  → 整数操作数**必须是十进制字面量**。

调用顺序即参数顺序，因此：

```
#BG.LOAD "BG_01.BMP"          → LOAD(file="BG_01.BMP")
#ANIME.LOAD "EV_01E2.BMP",51,50 → LOAD(file, x=51, y=50)   (逗号可省略)
#BG.WIPE 2                    → WIPE(effect=2)
#ANIME.MOTION 560,5,"000121…"  → MOTION(interval, count, pattern)
```

### 5.3 行尾注释

命令行里 `;` 之后全部是注释，引擎在解析参数时不会再读取。脚本中大量使用
`<TAB><TAB>;说明` 的形式做对齐注释，TAB 数量不一致（1–4 个），
这些 TAB 属于**原始字节**，翻译时必须原样保留。

### 5.4 标签与跳转

* 标签行形如 `:SECOND`，全脚本共 3 个（`SECOND`、`CLEAR`、`LAST`）。
* `#GO "Sxx_xx.SCR"` 切换脚本文件；`#IF 条件 JUMP "标签"` 在**当前脚本**内跳转。
* 跳转按标签名查找 `CStringArray` 中的行号，再设置行游标 `this[26]`；
  因此不存在绝对地址，重写文本不会破坏跳转 —— 只要标签行原样保留。

### 5.5 未定义命令

引擎对未知命令的行为是：`AfxMessageBox("Error: Unknow Command : ...")` 后继续。
本样本中存在两类"合法地错误"的行：

| 行 | 成因 |
|---|---|
| `#ANIME.OLOR 0,0,255` | 原文拼写错误（应为 COLOR），共 10 处 |
| `#BG.WIPE3` | 少写空格，共 1 处 |

此外还有 `#ANIME.STOP"`（行尾多一个引号）、`#BG.LOAD"EV_03.BMP"`（缺空格）
等笔误。**这些都必须逐字节保留**，否则游戏行为会改变（虽然只是弹框，但弹框
会阻塞流程）。`extract.py` 不提取命令行，`inject.py` 也不改写它们。

---

## 6. 指令表

45 条脚本中实际出现的指令 + 引擎中存在但脚本未使用的指令，摘要：

| 类别 | 指令 |
|---|---|
| 背景 | `BG.LOAD` `BG.WIPE` `BG.HIDE` `BG.SHOW` `BG.VSCROLL` `BG.RVSCROLL` `BG.HSCROLL` `BG.RHSCROLL` |
| 立绘 | `SP1/SP2/SP3` × `LOAD` `WIPE` `HIDE` `SHOW` `COLOR` `MOVE` |
| 动画 | `ANIME`/`ANIME2` × `LOAD` `MOTION` `COLOR` `STOP` |
| 音频 | `VOICE`/`SOUND`/`BGM` × `LOAD` `PLAY` `STOP` |
| 流程 | `WAIT` `GO` `LET` `ENABLE` `IF` `JUMP` `SELECT` `END` `NAME` `TITLE` `BACK` `GLASS` `GLASS.LOAD` `MSGBOX` `INPUT` `DEBUG` |

"opcode 长度/格式表"在本格式中的等价物：

| 字段 | 含义 |
|---|---|
| `byte_pattern` | 行首字节特征，如 `b"#BG.WIPE"`（大小写不敏感匹配） |
| `length` | 行式变长：`strlen(line)`；本样本实测最长 66 字节，平均 24.1 字节 |
| `operand_schema` | `str` / `int` / `intlist` / `expr` / `word` / `label` / `block` |
| `sub_opcode` | 无（方法名就是二级分派） |
| `variants` | 同一前缀不同方法，见 `COMMANDS` 的 `prefix` + 方法名 |

---

## 7. 直接按行处理（extract.py / inject.py）

脚本解密后就是纯文本行，跳转全部走 `:` 标签，因此**增删对白行是安全的**，
工具直接对 `.scr` 工作，不再做字节码反汇编：

* `extract.py`：`xor 0x44` 解密 → 按行分类（`;` 注释 / `:` 标签 / `#` 命令 / 其它对白）
  → 对白按“页”合并成一条 message → JSON；
* `inject.py`：按原始 `.scr` 重新推导页结构，把改动过的 message 按 20 全角重折行，
  补回缩进与 `●▲` / `■`，其余行原样保留 → 重新 `xor 0x44` 写回。

| 项目 | 处理 |
|---|---|
| 加密 | 首字节 `;` → 明文，否则整文件 xor 0x44；回写保持一致 |
| 换行 | CRLF；末尾是否带 CRLF 原样保留 |
| 页边界 | 页首 `　「（『`，页尾 `●▲` / `▲` / `■` |
| 缩进 | 页首全角空格记为 `indent`，注入时补回 |
| `「●` | 引号行 + 停顿符与后文合并为一条，注入时拆回 |
| 未改动页 | 原字节照搬（只按目标编码转换一次） |

零突变：同编码下 extract → inject 逐字节一致（见第 9 节）。

---

## 8. 已知限制

1. **转场效果编号**（`WIPE_EFFECTS`）只按脚本注释与调用点归纳，未穷举；
   编号本身不影响重建。
2. `#SELECT` 选择肢块的完整语义（选项数上限、分支变量名）未逐条验证，
   脚本样本中未出现该指令。
3. `.def` 文件（`Bgm.def/Cg.def/Event.def`）同样是 `xor 0x44` + CRLF 行文本
   （`;` 注释、`显示名,"文件",OFF` 三段式）；`gbk_patch.py --defs` 会替换显示名并重新 xor。
4. 对白是"每行一条记录"，游戏按行绘制；注入时按 **20 个全角字符** 重新折行
   （`inject.py` 的 `LINE_WIDTH`），超过会溢出对白框。
5. **字体与代码页**：绘制走 `TextOutA` + `CreateFontIndirectA`，
   `lfCharSet = 1`（DEFAULT_CHARSET），字面名 `ＭＳ 明朝`（`.data:0x456FC8`），
   `lfHeight = -26`，`lfWeight = 0x2BC`。也就是说渲染按**系统 ANSI 代码页**
   解释字节：
   * 保持 CP932：只能使用 JIS 里存在的汉字，且系统需为日文代码页
     （或使用 Locale Emulator）；
   * 改译简体中文：应把脚本编码改为 GBK/CP936，并同时把 `lfCharSet` 改成
     134（`0x86`，GB2312_CHARSET）、字体名改成中文字体（如 `SimHei`/黑体）。
   本工具已支持 `--encoding gbk`，字体/字符集补丁由 `gbk_patch.py` 完成：

   | 补丁点 | 偏移 | 改动 |
   |---|---|---|
   | 4 处 `lfCharSet` 立即数 | `0x0089BC` `0x00AFC5` `0x00B287` `0x00C58B` | `01` → `86` |
   | 字体名 | `0x0555C8`（`.data:0x456FC8`，9 字节 + NUL） | `ＭＳ 明朝` → `SimHei` |
   | 全角空格常量 | `0x0554AC`（`.data:0x456EAC`） | `81 40` → `A1 A1` |
   | `■` 常量 | `0x0555E0`（`.data:0x456FE0`） | `81 A1` → `A1 F6` |
   | `●` 常量 | `0x055990`（`.data:0x457390`） | `81 9C` → `A1 F1` |
   | `▲` 常量 | `0x055994`（`.data:0x457394`） | `81 A3` → `A1 F8` |

   **文本控制符号**（`sub_415EF0` 逐字打印时 `strcmp(当前字符, 常量)`）：
   `●` = 停顿（`hWnd[45]=1` 后继续）、`▲` = 等待翻页、`■` = 清屏等待、
   `　` = 缩进。它们是 CP932 硬编码字节，脚本转 GBK 后必须同步改，
   否则符号会被当正文画出、且不再停顿（实测表现为文字一路播下去停不下来）。

   注意 `TextOutA` 与 `IsDBCSLeadByte` 都依赖系统代码页，因此打完补丁后
   必须在**中文(936)** 代码页下运行，否则仍然是乱码。

   **语音不打断**：`#VOICE.STOP` 在 `sub_414FE0` 里调用 `sub_407310`
   （`IDirectSoundBuffer::Stop`），VA `0x00415285`、5 字节 `E8 86 20 FF FF`。
   脚本里它几乎总是紧跟在一句台词后，于是玩家点下一句时语音被切断。
   把这 5 字节改成 `NOP`，语音就自然播完；下一句 `#VOICE.PLAY` 走 `sub_407260`
   重新装载缓冲，不会叠音。补丁由 `patch_voice.py` 完成，`--restore` 可还原。
6. **运行时验证**：GBK 补丁、语音不打断、图片还原都已在实机确认；脚本层是
   字节级往返验证（加密 / 明文 / 文本三条链路）。名字输入画面的假名表
   （`0x55270` 起的 16 位假名表）仍是 CP932，未做转换。

---

## 9. 验证结果

```
输入：Scr/*.scr 共 56 个文件，2334 条对白页
步骤：extract.py → json_jp → inject.py（--encoding cp932）→ 重建 .scr
结果：56/56 SHA-256 与原始文件一致（零突变）
```

命令：

```bat
python extract.py Scr -o json_jp
python inject.py json_jp --src Scr -o _out --encoding cp932
python inject.py json_jp --src Scr -o _txt --encoding cp932 --no-encrypt
python inject.py _txt -o _back --encrypt --encoding cp932
```

两条链路逐字节对比 `Scr/` 全部一致；GBK 构建用
`python inject.py json_cn --src Scr -o cn_scr --encoding gbk`，
详细结果见 `TESTING.md`。