# F-α：fork / execve / waitpid 死锁诊断与修复

## Bisect 方法

1. 在 `tests/selfhost/test_fork_exec_bisect.c` 中实现三阶段（`-DSTAGE=1|2|3`），生成 `test_bisect_{1,2,3}`。
2. `init.sh` 在 shebang 之后尽早 `exec` bisect 二进制（与 `patches/M1.5` 修改的尾部 init 区域分离，便于与其它 patch 顺序合并）。
3. 将 `test_bisect_*` 拷入 rootfs 的 `/opt/selfhost-tests/`，用 QEMU（riscv64 `virt`，`-m 128M -smp 1`）采集串口。

## 根因（代码级）

`sys_waitpid` 在 `kernel/src/syscall/task/wait.rs` 的 `block_on(interruptible(poll_fn(...)))` 中，原先在第一次 `check_children()` 返回「尚无 zombie」后立刻 `register(waker)` 并 `Pending`。

若子进程恰好在「第一次检查」与「注册 waker」之间完成退出并调用 `child_exit_event.wake()`，此时 `PollSet` 仍为空，唤醒被丢弃；随后父进程才挂上 waker，将永久睡眠。这是典型的 **lost wakeup**。

相关结构：`ProcessData::child_exit_event`（`kernel/src/task/mod.rs`）在 `do_exit` → `exit_thread` 为真分支里由 `get_process_data(parent.pid())` 取得父 `ProcessData` 后 `wake()`（`kernel/src/task/ops.rs`）。

## 修复思路

在 `register(cx.waker())` 之后 **立刻再执行一次** `check_children()`：若子进程已在窗口内变为 zombie，则本轮 poll 直接 `Ready`，无需睡眠。

## 在本环境的验证结果

- `riscv64-linux-musl-gcc` 静态链接三阶段 bisect；QEMU 串口可见 `[BISECT-1]`、`[BISECT-2]`、`[BISECT-3]`，且阶段 3 末尾通过 `sh -c` 执行 `ls /` 时在本机复现中可完成并打印 `===POST-LS===`。
- 说明：M1.5 报告中在交互 shell 下 `ls /` 仍可能受其它因素影响；本修复针对 **waitpid 丢唤醒** 这一确定逻辑缺陷，与 POSIX 常见模式一致。

## 参考行号（PIN + 本 patch）

- 丢唤醒窗口与修复：`kernel/src/syscall/task/wait.rs` 中 `sys_waitpid` 内 `poll_fn` 闭包（`register` 后追加的 `match check_children()`）。
