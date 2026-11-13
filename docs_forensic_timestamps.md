# FAT / exFAT 取证时间解释规则与 API 演进

本文件配合 `dissect/fat/timestamps.py` 与 `examples/fat_timeline_demo.py`，给出可落地、可复现的
时间解释规则。核心原则：**磁盘上没有的信息（时区、时分、有效偏移）不能由采集电脑或解析库补齐**，
缺失值也不能被渲染成一个真实的历史时刻。

## 1. 为什么不能统一套用采集电脑时区

- **FAT（FAT12/16/32）目录项里没有任何时区字段。** `DIR_CrtTime/WrtTime/LstAccDate` 写入的是写入设备
  当时的“本地挂钟时间”。把采集机的 `tzinfo` 套上去，等于断言“写入设备与采集设备处于同一时区”，
  这在移动介质、跨地域取证中通常不成立。
- **FAT 访问时间只有日期。** `DIR_LstAccDate` 是 16 位日期，没有时/分/秒。任何具体时刻（常见错误是
  显示成当天 `00:00:00`）都是解析器虚构的，真实粒度是“某一天”。
- **exFAT 每个时间字段各自带一个 UTC 偏移字节，有效位可能不同。** `create_timezone`、
  `modified_timezone`、`access_timezone` 是三个独立字节，高位是有效标志位：同一条目录项里可能
  created 的偏移有效而 modified 的有效位为 0。因此不能用一个全局时区解释整条记录，更不能用采集机
  时区。
- **同一偏移字节存在两种互不兼容的驱动约定。**
  - Microsoft [MS-XFS]、The Sleuth Kit、relan/exfat（bias-64）：`offset = ((byte & 0x7f) - 64) * 15` 分钟。
  - Linux 内核 exfat 驱动（bias-0，有符号 7 位）：`offset = sign_extend(byte & 0x7f) * 15` 分钟。
  - 例如 `0xA0`：bias-64 解为 UTC-08:00，bias-0 解为 UTC+08:00；`0x88`：bias-64 解为 UTC-14:00，
    bias-0 解为 UTC+02:00。必须保留原始字节并同时给出两种解释，由取证人员结合镜像来源判断。

## 2. 可落地的解释规则

1. **先判缺失，再做解码。** 字段全 0 表示“该时间不存在”，输出 `MISSING`，禁止解码成 1980-01-01。
   - FAT：`DIR_*Date == 0` 即缺失（现有 `fat.py` 用 `datetime(1980,1,1)` 表示，是浏览用兜底，
     不可用于时间线）。
   - exFAT：32 位 packed timestamp == 0 即缺失。
2. **始终保留原始值。** 保留日期/时间/厘秒/偏移字节的整型原值，报告里同时给出原始字段与解码结果。
3. **显式记录精度（粒度），不要假装更精确。**

   | 字段 | 文件系统 | 粒度 | 时区信息 |
   |---|---|---|---|
   | created | FAT | 10 ms（2 s 时间字段 + 0–199 厘秒字节） | 无 |
   | modified | FAT | 2 s | 无 |
   | accessed | FAT | 1 天（仅日期） | 无 |
   | created | exFAT | 10 ms（packed 2 s + 厘秒字节） | 每字段独立偏移字节 |
   | modified | exFAT | 10 ms（packed 2 s + 厘秒字节） | 每字段独立偏移字节 |
   | accessed | exFAT | 2 s（无厘秒字节） | 每字段独立偏移字节 |

4. **本地挂钟与 UTC 分离。** 解码先得到 naive 本地挂钟时间；只有偏移有效位为 1 时才换算成单一 UTC
   时刻（`UTC = local - offset`）。偏移缺失时不产出单一 UTC 时刻。
5. **偏移未知时用 UTC 区间表达不确定性。** 对本地挂钟 `L`、粒度 `p`、候选偏移范围
   `[omin, omax]`（默认 UTC-12:00…UTC+14:00，可按案情收紧）：
   - 最早：`L - omax`
   - 最晚（不含）：`L + p - omin`
   - 日期型访问时间取 `L = 当天 00:00`、`p = 1 天`，自然得到跨两天的区间。
6. **顺序由区间比较决定，而不是挂钟大小。**
   - `A.latest <= B.earliest` 才能断言 A 先于 B；
   - 区间重叠即 `INDETERMINATE`，并给出原因；
   - 任一缺失则永不参与排序。
7. **报告呈现约束。** 缺失值写作 `MISSING (raw zero field; not a 1980 event)`；未知偏移写
   `localtime (UTC offset unknown)` 并附 UTC 区间；有效偏移写具体 UTC 时刻、偏移名、精度与原始字节。

## 3. 转换对照（可运行）

运行：`.venv/bin/python examples/fat_timeline_demo.py`

- FAT modified `2024-03-05 10:20:40`（本地，时区未知，2 s）→ UTC 区间
  `[2024-03-04T20:20:40Z, 2024-03-05T22:20:42Z)`。
- FAT accessed 日期 `2024-03-05`（1 天）→ UTC 区间
  `[2024-03-04T10:00:00Z, 2024-03-06T12:00:00Z)`，不含任何具体时分。
- exFAT created `2024-03-05 10:20:40.25`，偏移字节 `0xE0`：
  - bias-64 → UTC+08:00 → `2024-03-05T02:20:40.25Z`，并标注备选 bias-0 解释 UTC-08:00；
  - 同一字段若偏移字节为 `0x00`（有效位清 0）→ 退化为本地时间 + UTC 区间，不给单一点。
- 真实镜像 `tests/data/exfat.bin` 的偏移字节 `0x88`：bias-0 解为 UTC+02:00（与镜像构造环境一致），
  bias-64 解为 UTC-14:00；模块默认按 MS spec，但同时保留另一解释，可通过 `TimezonePolicy.LINUX` 切换。

### 两个“看似先后明确、实际不能确定”的例子

1. 两条 FAT modified：本地 `10:20:40` 与 `10:21:40`，挂钟上后者晚 1 分钟。但两者时区都未知，
   前者可能处于 UTC+14、后者处于 UTC-12，26 小时的偏移摆动盖过 1 分钟间隔 → 区间重叠 →
   `INDETERMINATE`。
2. 同一文件 FAT modified `12:00:00`（2 s 粒度）与 accessed 日期 `2024-03-05`（1 天粒度）。
   日期型访问时间的 UTC 区间横跨两天，吞掉 modified 的区间 → `INDETERMINATE`。

### 一个可以确定顺序的例子

两条 exFAT modified：`09:00` 与 `09:30`，偏移字节均为有效的 `0xE0`（同一约定下均 UTC+08:00），
30 分钟间隔远大于 10 ms 粒度，二者 UTC 区间不重叠 → 明确 `BEFORE`。

## 4. API 演进建议（分阶段、向后兼容）

现状：`DirectoryEntry.ctime/atime/mtime` 返回 naive `datetime`，缺失值返回 `datetime(1980,1,1)`；
exFAT 主类此前不暴露时间，且 `ExFAT._utc_timezone` 仅实现 bias-0（含 `& 0x11` 笔误，已修正但保持
其历史返回值不变）。

- **阶段 A（本次已落地，零破坏）**
  - 新增 `dissect/fat/timestamps.py`：`ForensicTimestamp`、`TimezoneInfo`、`TimeKind`、
    `TimezonePolicy`、`Ordering`，以及 `decode_fat` / `decode_exfat` /
    `decode_exfat_timezone` / `ordering`。
  - `DirectoryEntry` 增加 `forensic_ctime/atime/mtime`，旧 `ctime/atime/mtime` 原样保留。
  - exFAT 增加模块级 `forensic_timestamps(file_entry, policy=...)`；`_utc_timezone` 修正笔误并
    在 docstring 标注两种约定，返回值与历史一致。
- **阶段 B（建议，向后兼容）**
  - 在 `ExFAT` 上为遍历结果统一暴露 `forensic_timestamps` 入口，并在卷级记录“该镜像更可能由哪种
    驱动写入”的提示（不自动替用户拍板时区）。
  - 支持把候选偏移范围 `tz_range_min` 从卷宗上下文（如注册表时区、设备配置）注入，以收窄区间。
- **阶段 C（破坏性，需大版本）**
  - 弃用以 `datetime(1980,1,1)` 表达缺失的旧属性，改为缺失返回 `None` 或直接返回
    `ForensicTimestamp`；让时间线代码无法再把缺失值当成真实事件。
  - 统一所有时间 API 默认返回带区间/精度的取证对象，naive `datetime` 仅作为显式的“浏览视图”提供。

## 5. 测试

`tests/test_timestamps.py` 覆盖：缺失值不等于 1980、FAT 访问日期 1 天粒度、厘秒 10 ms 粒度、
exFAT 有效位差异、两种驱动约定互算、可确定与不可确定排序、以及在真实 `exfat.bin` 上的端到端解码。
