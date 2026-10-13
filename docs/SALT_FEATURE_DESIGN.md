# RHash 哈希加盐（Salt）功能设计方案

## 1. 目标与背景
为 RHash 命令行工具新增 `--salt`、`--salt-hex` 与 `--salt-file` 参数，支持在哈希计算前混入用户自定义的 Salt 数据：
1. 产生不同于公开发布的标准哈希摘要（防彩虹表/公共库比对）；
2. 对相同的 Salt 和输入数据，输出严格稳定且可重现；
3. 支持大文件、多文件、流式输入（stdin）、消息模式（`-m`）以及校验模式（`-c`）；
4. 保持 RHash 原生的进度条百分比（`-P`）、速度统计（`--speed`）和总大小统计准确无偏差。

## 2. 方案选型：前缀追加（Prefix: `Hash(Salt || Data)`）

### 2.1 为什么采用前缀追加
- **零内存与流式性能**：RHash 核心采用块级流式计算（`rhash_update_fd`）。在打开文件后、读取真实数据前，先执行一次 `rhash_update(rctx, salt, salt_len)`，哈希状态机预先吸收 Salt，随后顺序吸收数据。无论处理几十 KB 还是上百 GB 文件，内存消耗为零，无需在内存中拼接数据。
- **避免长度扩展攻击（Length Extension Attack）**：
  若采用尾追加 `Hash(Data || Salt)`，对于 MD5、SHA-1、SHA-2 等 Merkle–Damgård 结构哈希算法，攻击者在知晓哈希值和数据长度的前提下，无需获知 Salt 内容即可顺延状态构造出带相同 Salt 的扩展数据摘要。前缀加盐使 Salt 在第 1 个数据分组前即参与状态压缩，截断了纯哈希状态续接的漏洞。
- **树状与分块算法兼容**：对于 TTH、AICH、ED2K、BLAKE3 等树状或大块切片算法，前缀注入会确定性地混入首块及树节点中，保持确定性稳定性。

## 3. 架构修改点与核心逻辑

### 3.1 选项解析层（`parse_cmdline.h`, `parse_cmdline.c`）
1. **`struct options_t` 结构扩展**：
   - `char* salt;`：指向 Salt 原始字节缓冲。
   - `size_t salt_size;`：Salt 字节长度。
2. **选项表注册**：
   - `--salt=<string>`：使用 `F_UFNC` 处理，Windows 下自动转为 UTF-8 编码，跨平台字节序一致。
   - `--salt-hex=<hex>`：使用 `F_UFNC` 处理，解析 16 进制字符串为原始二进制字节，支持任意字节序列（包括 `\0` 等不可打印字符），内存交由 `opt.mem` 统一管理回收。
   - `--salt-file=<file>`：使用 `F_TFNC` 处理，原生支持跨平台宽字符/UTF-8 路径。以二进制模式完整读取指定文件内容作为 Salt（最大安全上限 1GB，支持包含 `\0` 等二进制内容），内存接入 `opt.mem` 统一管理回收。后指定的选项（`--salt` / `--salt-hex` / `--salt-file`）自动覆盖前指定的选项。
3. **配置合并与时序校验**：
   - 在 `apply_cmdline_options()` 中增加 `conf_opt.salt` 到 `opt.salt` 的合并，支持配置文件 `rhashrc`。
   - 在 `make_final_options_checks()` 中校验互斥条件：禁止与 `--torrent` / `RHASH_BTIH` 联合使用（BitTorrent piece 结构不兼容加盐）。

### 3.2 哈希计算注入层（`calc_sums.c`）
在 `calc_sums()` 函数中，位于 `re_init_rhash_context(info)` 之后、`info->msg_offset = info->rctx->msg_size;` 之前注入 Salt：
```c
re_init_rhash_context(info);
if (opt.salt_size > 0) {
    if (info->hash_mask & hash_id_to_bit64(RHASH_BTIH))
        die(_("--salt can't be used with BitTorrent hashes\n"));
    rhash_update(info->rctx, opt.salt, opt.salt_size);
}
/* store initial msg_size, for correct calculation of percents */
info->msg_offset = info->rctx->msg_size;
```

**关键设计原理**：
RHash 内部通过 `info->msg_offset` 记录开始处理文件内容前的字节偏移量。后续 `output.c` 中计算进度百分比和速度时：
`offset -= info->msg_offset;`
最终文件大小：
`info->size = info->rctx->msg_size - info->msg_offset;`
将 Salt 注入在 `re_init_rhash_context` 与 `info->msg_offset` 之间，恰好使 `msg_offset` 包含 Salt 的长度，使得后续的文件进度、文件大小和速度统计 100% 保持为文件的真实指标，完全不受 Salt 干扰。

## 4. 第三方验证方案
使用 Python 标准库 `hashlib` 及第三方通用实现编写独立测试脚本：
对于任意输入 `Data` 和 `Salt`（无论是来自 `--salt` 字符串、`--salt-hex` 16进制、还是 `--salt-file` 二进制文件），Python 使用标准逻辑：
`hashlib.<alg>(salt_bytes + data_bytes).hexdigest()`
对比 `rhash --salt... --<alg> <file>` 的输出，验证两者完全逐字一致。
覆盖算法包括：MD5、SHA1、SHA224、SHA256、SHA384、SHA512、SHA3-256、SHA3-512、BLAKE2b、BLAKE2s、CRC32 等。
此外对空 Salt 文件、包含 `\0` 字节的二进制 Salt 文件、超过 1MB 安全上限拦截以及不存在文件的异常报错均进行了自动化验证。

