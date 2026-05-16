# Self-host M6 Change Split Notes

本文件记录当前 `codex/quiet-rsext4-m6-logs` 分支相对官方
`rcore-os/tgoskits:main` 的整理方式，方便后续按可读、可审查的 PR
逐步合入。

## Upstream merge status

- 官方远端：`upstream = https://github.com/rcore-os/tgoskits.git`
- 已拉取并尝试合并：`git merge upstream/main`
- 结果：`Already up to date`

这说明当前分支已经包含官方 `main`，这次不需要解决 merge conflict。

## Recommended PR partitions

### 1. rsext4 日志降噪

分支：`codex/pr-rsext4-quiet-logs`

用途：
- 降低 M6 guest 编译时 rsext4 的高频诊断输出。
- 保留需要排障时可重新打开的诊断入口。
- 让长时间 QEMU/TCG 编译的串口日志更可读，避免真正的 cargo error 被大量文件系统调试日志淹没。

拆分原因：
- 这是观测性和日志策略调整，不改变核心文件系统语义。
- 适合作为独立小 PR 审查，风险边界清楚。

### 2. rsext4 inode bitmap 修复

分支：`codex/pr-rsext4-inode-bitmap`

用途：
- 修复未初始化 inode bitmap 被重复使用的问题。
- 避免 rootfs 在长时间 guest 编译、QEMU 被中断或 panic 后出现 inode/bitmap
  不一致，降低后续 `Input/output error` 和 ext4 checksum 问题的概率。

拆分原因：
- 这是文件系统正确性修复，应独立于日志降噪和 StarryOS syscall 改动审查。
- 它解释了为什么后续需要 `e2fsck` 修复已有镜像副本，但代码层面应单独合入。

### 3. StarryOS `ppoll` 用户缓冲修复

建议分支：`codex/pr-starry-ppoll-user-buffer`

用途：
- `sys_ppoll` 不再把用户态 `pollfd` slice 直接传入会阻塞的 `do_poll`。
- 进入阻塞前先复制到内核缓冲区，`do_poll` 只修改内核内存。
- 调用成功后再把 `revents` 等结果复制回用户缓冲区。

拆分原因：
- 这是 guest 编译过程中暴露出的 StarryOS syscall 安全性修复。
- 它和 rsext4 的日志/bitmap 问题不是同一层，应该单独审查。
- 这个修复直接对应 guest panic：
  `Unhandled Supervisor Page Fault ... do_poll ... fault_vaddr=VA:0xb884b96 (WRITE)`。

### 4. self-host integration branch

分支：`codex/quiet-rsext4-m6-logs`

用途：
- 保存 M6 self-host 编译验证所需的综合工作状态。
- 作为本地/开发验证分支，承载长链路调试、rootfs/QEMU 观察、阶段性修复组合。

拆分原因：
- 这个分支包含较多历史 self-host 改动，不适合直接作为一个大 PR。
- 它应该作为验证和归档分支；最终面向官方 main 的合入，应从上面的独立 PR
  分区逐个提交。

## Current validation trail

- Host-side `starry-kernel` cargo check 已通过。
- Host-side release `starryos` ELF 已能构建。
- Guest-side M6 已使用修复后的 rootfs 副本继续跑：
  - source sync 已生效。
  - build-std cache clean 已生效。
  - `core`、`compiler_builtins`、`alloc` 已推进过去。
  - 当前仍在 `[4] pass2 starryos` 的 crate graph 编译阶段，尚未到最终 ELF 链接收口。

## Review order

建议按以下顺序准备 PR：

1. rsext4 日志降噪。
2. rsext4 inode bitmap 正确性修复。
3. StarryOS `ppoll` 用户缓冲修复。
4. self-host integration 分支只作为验收说明和后续拆分来源，不建议直接提交为一个大 PR。
