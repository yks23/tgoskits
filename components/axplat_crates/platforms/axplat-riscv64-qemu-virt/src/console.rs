use ax_kspin::SpinNoIrq;
use ax_lazyinit::LazyInit;
use ax_plat::console::ConsoleIf;
use uart_16550::{Config, Uart16550, backend::MmioBackend};

use crate::config::{devices::UART_PADDR, plat::PHYS_VIRT_OFFSET};

static UART: LazyInit<SpinNoIrq<Uart16550<MmioBackend>>> = LazyInit::new();

pub(crate) fn init_early() {
    UART.init_once({
        let mut uart =
            unsafe { Uart16550::new_mmio((UART_PADDR + PHYS_VIRT_OFFSET) as *mut u8, 1) }.unwrap();
        uart.init(Config::default())
            .expect("Failed to initialize UART");
        uart.test_loopback().expect("Failed to test UART loopback");
        SpinNoIrq::new(uart)
    });
}

struct ConsoleIfImpl;

#[impl_plat_interface]
impl ConsoleIf for ConsoleIfImpl {
    /// Writes bytes to the console from input u8 slice.
    fn write_bytes(bytes: &[u8]) {
        for &c in bytes {
            let mut uart = UART.lock();
            match c {
                b'\n' => uart.send_bytes_exact(b"\r\n"),
                c => uart.send_bytes_exact(&[c]),
            }
        }
    }

    /// Reads bytes from the console into the given mutable slice.
    /// Returns the number of bytes read.
    fn read_bytes(bytes: &mut [u8]) -> usize {
        let mut uart = UART.lock();
        uart.try_receive_bytes(bytes)
    }

    /// Returns the IRQ number for the console, if applicable.
    ///
    /// QEMU virt 的 16550 虽有 PLIC 号，但 Starry `/dev/console` 走 `LineDiscipline`
    /// 的 [`ProcessMode::External`] 时需要 **设备 IRQ 已挂 top-half** 才会在 `tty-reader`
    /// 任务里 `poll()` UART。当前内核不为 UART 注册 `ax_hal::irq::register` 处理函数，
    /// `register_irq_waker` 只 `set_enable` PLIC：中断到达后表项为空、硬件电平可能
    /// 无法清掉，RX 字节一直留在 FIFO，`tty-reader` 永远不被唤醒。
    ///
    /// 退回与 x86 COM1 相同的策略：`irq_num = None` → `ProcessMode::Manual`，在
    /// `read(0,…)` 路径里轮询 `console::read_bytes`，stdin 即可工作。
    #[cfg(feature = "irq")]
    fn irq_num() -> Option<usize> {
        None
    }
}
