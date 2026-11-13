# exFAT 目录结构模糊测试入口

针对 `dissect.fat.exfat` 目录解析的小规模**结构化**模糊测试，目标是判断恶意
entry-set 与目录/簇回边是否会耗尽取证进程（无限循环、递归崩溃或过量展开）。
它不做随机字节翻转，只联动修改解析器真正依赖的语义字段，并用固定种子保证可重放。

## 组成

| 文件 | 职责 |
| --- | --- |
| `exfat_image.py` | 纯 `struct` 合成最小合法 exFAT 镜像（VBR + 单 FAT + 单簇多级目录树），并记录每个 entry-set/FAT 的字节偏移供定向变异。 |
| `structured_fuzz.py` | 固定 LCG 种子驱动的协调变异器与可重放语料（`SEED_CORPUS`）。 |
| `bounded_walker.py` | 独立的预算受限、带回边检测的 walker，是判定“格式异常”与“真正耗尽”的核心 oracle。 |
| `process_runner.py` | 进程边界驱动器，以及刻意移除全部终止条件的**控制版 walker**。 |
| `../test_exfat_directory_fuzz.py` | 回归测试，含进程内快速判定与跨进程终止性验证。 |

## 变异如何联动

变异器始终成对修改相关字段，而不是只翻转单个字节：

- `secondary_count`：改 FILE 条目的 secondary count，与随后实际读取的
  stream/filename 条目数联动，覆盖 `subentry_count - 1` 驱动的文件名循环。
- `stream_flags`：清除 STREAM 条目的 not-fragmented 位，使目录改走 FAT 链解析。
- `filename_entries`：在保持 count 一致的前提下，把某个 FILENAME 次级条目标记为非在用。
- `directory_pointer`：把目录 STREAM 的 `location` 指向已访问的根目录簇，制造目录回边。
- `fat_backedge`：把根目录 FAT 表项的 EOC 改成自指，移除簇链终止条件。
- `invalid_cluster`：把目录指向簇堆之外，验证越界是结构性错误而非循环。

## 独立读取预算与进程边界

`bounded_walker.Budget` 维护互相独立的计数：读取字节数、目录条目数、目录深度、
FAT 链步数、目录数量，各自有独立上限，与镜像大小无关。FAT 解析带簇 `seen` 集合，
目录遍历带 `visited` 集合和显式深度上限。

判定三分类：

- `OK`：正常终止，结构合法。正常的多级目录必须落在这一类。
- `MALFORMED`：结构异常但会自行终止（越界簇、entry-set 溢出、次级类型错误等），
  **不会**被当作漏洞。
- `EXHAUSTION`：触发了无防护解析器不具备的守卫（回边或预算耗尽）。

生产解析器 `ExFAT` 与控制版 walker 没有这些守卫，因此通过 `process_runner`
在独立子进程 + 墙钟超时内运行：挂死表现为 `timeout`，递归爆栈表现为 `crashed`，
都不会拖垮测试进程本身。

## 触发路径（最小化样本）

```bash
# 列出固定种子语料及每个样本的预算判定
python -m tests.fuzz list

# 把最小样本和 manifest.json 落盘，便于离线复现
python -m tests.fuzz dump-samples ./samples

# 在进程边界上对某个样本运行真实解析器 / 控制版 walker / 有界 walker
python -m tests.fuzz process fat_backedge --mode control-walker
python -m tests.fuzz process directory_pointer --mode real-parser
```

每个样本约 71 KiB（单 FAT + 少量单簇目录），是触发对应路径所需的最小镜像。

## 控制版本（负对照）

`process_runner._unbounded_control_walk` 与有界 walker 解析完全相同的目录语义，
但删除了 FAT `seen`、目录 `visited`、深度/条目/字节全部预算。在回边样本上它永不
终止，证明检测能力来自这些守卫本身：

| 样本 | 有界 walker（进程内） | 控制版 walker（子进程） | 真实 ExFAT（子进程） |
| --- | --- | --- | --- |
| baseline（多级正常目录） | completed | completed | completed |
| fat_backedge | completed（瞬时） | timeout | timeout |
| directory_pointer | completed（瞬时） | crashed（RecursionError） | crashed（RecursionError） |

## 回归判据

运行 `pytest tests/test_exfat_directory_fuzz.py`，必须满足：

1. 合法多级目录被真实 `ExFAT` 解析且 walker 判为 `OK`，无任何误报。
2. 固定种子两次生成的语料逐字节一致；换种子至少一个样本变化。
3. 每个语料样本的 walker 判定都等于其预期分类，所有 `MALFORMED` 不会升级为
   `EXHAUSTION`。
4. 收紧读取预算会触发 `ExhaustionError`，默认预算下同一镜像仍是 `OK`。
5. 跨进程：有界 walker 在回边样本上始终 `completed`；控制版与真实解析器在
   FAT 回边上 `timeout`、目录回边上 `crashed`；baseline 三者都 `completed`。
