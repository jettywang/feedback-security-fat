# exFAT 主/备启动区域独立验证报告

## 背景

取证后端 `dissect/fat/exfat.py` 目前只检查 `fs_name == b"EXFAT   "`(exfat.py:39-40),
随后直接信任启动区几何参数。它从不验证:

- 主启动区(扇区 0-11)的启动校验和(扇区 11);
- 备份启动区(扇区 12-23)的存在、有效性或与主区的一致性;
- 引导签名 0xAA55、MustBeZero、字段取值范围等结构约束;
- VolumeFlags(脏位/介质故障位),备份区的活动状态更不会与当前状态区分。

本材料针对主、备启动区域建立独立验证,并记录现有读取器对每个样本的接受结果。
所有预期判据由 `tests/exfat_boot/expectations.py` 手工推导,验证器
`tests/exfat_boot/verifier.py` 仅依据 exFAT 规范用标准库实现,**不调用生产解析器**。

## 样本构造

按 exFAT 启动区规则构造 512 与 4096 字节扇区镜像(`tests/exfat_boot/builder.py`):

| 扇区 | 内容 |
|---|---|
| 0 | 主引导扇区(几何参数、VolumeFlags、PercentInUse、0xAA55) |
| 1-8 | 扩展引导扇区(尾部 0xAA550000) |
| 9-10 | OEM 参数 / 保留(全零) |
| 11 | 主校验扇区(32 位校验值重复填满) |
| 12-23 | 备份启动区域(同上布局) |
| 24.. | FAT(512: 扇区 128;4096: 扇区 24),簇堆紧随其后 |

簇堆:簇 2 = 分配位图,簇 3 = 大写表(带校验),簇 4 = 根目录(卷标 EVIDENCE、
位图项、大写表项、HELLO.TXT 条目组,条目组校验有效),簇 5 = HELLO.TXT 内容。

每个扇区尺寸 6 个变异样本(共 12 个,`tests/data/exfat_boot/`):

| 样本 | 变异 |
|---|---|
| `valid` | 无,主备一致 |
| `rootdir_relocated_csum_ok` | 主+备 `root_dir_cluster` 4→5(受校验覆盖的几何字段),校验和诚实重算 |
| `heap_shifted_csum_bad` | 仅主区 `cluster_heap_sector` +1,**不**重算校验和;备份完好 |
| `flags_independent` | VolumeFlags/PercentInUse 独立变化:主区 clean/75%,备区 dirty/50%(二者本就被排除在校验之外) |
| `checksum_sector_bit` | 主校验扇区中某一个重复校验值翻转 1 位 |
| `backup_geom_diverge` | 备区 `root_dir_cluster` 4→6 并重算备区校验,主区不动 |

## 判据矩阵(手工推导)与读取器接受结果

三层结论分离:**校验有效** ≠ **结构自洽** ≠ **文件内容可定位**;三者都满足才记为可信。
512 与 4096 样本结论相同。

| 样本 | 主校验 | 备校验 | 主结构 | 主备一致 | 内容可定位(主/备) | 可信 | 现有读取器 |
|---|---|---|---|---|---|---|---|
| valid | ✓ | ✓ | ✓ | ✓ | ✓/✓ | **是** | 接受,内容正确 |
| rootdir_relocated_csum_ok | ✓ | ✓ | ✓ | ✓ | ✗/✗ | 否 | 接受魔数后**附带崩溃**(AttributeError,非校验拒绝) |
| heap_shifted_csum_bad | ✗ | ✓ | ✗ | ✗ | ✗/✓(可经备份恢复) | 否 | 同上,附带 AttributeError |
| flags_independent | ✓ | ✓ | ✓ | ✓ | ✓/✓ | **是** | 接受,内容正确 |
| checksum_sector_bit | ✗ | ✓ | ✓ | ✓ | ✓/✓ | 否 | **接受且内容正确(缺口)** |
| backup_geom_diverge | ✓ | ✓ | ✓ | ✗ | ✓/✗ | 否 | **接受,分歧不可见(缺口)** |

要点:

- `rootdir_relocated_csum_ok` 证明"校验有效 + 结构在界内"仍可能指向错误内容——
  可解析不等于可信,内容可定位必须单独验证。
- `checksum_sector_bit` 证明读取器对校验无效的主区毫无察觉,照常返回正确内容。
- `flags_independent` 证明 VolumeFlags/PercentInUse 可独立变化而不影响校验;
  当前状态只能取主区(0x0000 clean),**备区的 dirty 位不是当前状态**。
- `heap_shifted_csum_bad` 中备份区完好且内容可经备份定位,但读取器从不读备份区。
- 读取器对几何损坏的"拒绝"是 `volume_entry` 为 None 引发的 AttributeError
  (exfat.py:60),属于附带崩溃,不是有意的校验拒绝。

## 证据链:从启动区原始字节到一次实际文件读取

由 `verifier.trace_file_read` 生成(`test_evidence_trace_ends_in_verified_file_read`
断言其以 MATCH 结尾):

```
sector_size = 512 (bytes_per_sector_exp = 9)
[1] main boot sector geometry (raw little-endian bytes):
    0x50 fat_sector          = 80 00 00 00 -> 128
    0x54 fat_sector_count    = 08 00 00 00 -> 8
    0x58 cluster_heap_sector = 88 00 00 00 -> 136
    0x5C cluster_heap_count  = 40 00 00 00 -> 64
    0x60 root_dir_cluster    = 04 00 00 00 -> 4
[2] boot checksum: computed 0x112514f1, stored 0x112514f1 (sector 11)
[3] FAT[4] @ byte 0x10010 = 0xffffffff (EOC) -> root dir chain = [4]
[4] root dir sector = 136 + (4-2)*1 = 138 (byte 0x11400)
[5] root dir entries: volume label 'EVIDENCE', upcase checksum valid = True, files = ['HELLO.TXT']
[6] HELLO.TXT entry-set checksum valid = True
[7] file content @ sector 139 (byte 0x11600), 51 bytes, sha256 = 831a5527...2d5128c3
    content = b'EVIDENCE-512: exFAT boot region validation sample.\n'
    expected sha256 = 831a5527...2d5128c3 -> MATCH
```

4096 扇区样本同样完整定位(fat_sector=24,根目录扇区 27,文件扇区 28,
sha256 = 47b21845...fcbab29f,MATCH)。

## 缺口与建议接入点

以下检查当前不存在,对应测试以 xfail(strict) 保留在
`tests/test_exfat_boot_region.py::TestGaps`,修复后会转为 XPASS 提示更新:

1. **启动校验和验证** — 接入点 `dissect/fat/exfat.py:40`(魔数检查之后、
   使用任何几何字段之前):计算扇区 0-10 的启动校验和(跳过 0x6A/0x6B/0x70),
   与扇区 11 的重复值比对。失败应抛出专用异常而非附带 AttributeError。
2. **备份区回退** — 接入点 `dissect/fat/exfat.py:37`(VBR 读取处):主区校验
   失败时读取扇区 12 的备份 VBR;`heap_shifted_csum_bad` 可经备份完整恢复。
3. **主备一致性交叉检查** — 比较两区受校验覆盖的字节(排除
   VolumeFlags/PercentInUse),分歧应作为取证标记暴露(如
   `boot_regions_agree` 属性)。
4. **VolumeFlags 表面化** — 脏位/介质故障位应作为卷状态暴露,且只能取主区
   值;备区活动状态是快照,不能当成当前状态。
5. **结构约束** — 0xAA55 引导签名、MustBeZero、扇区/簇移位范围、
   FAT/簇堆/根目录簇边界,可并入接入点 1 的同一验证函数。

## 复现

```
python -m tests.exfat_boot.generate          # 重新生成 tests/data/exfat_boot/*.bin
pytest tests/test_exfat_boot_region.py -q    # 45 passed, 8 xfailed
```
