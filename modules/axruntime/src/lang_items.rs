use core::panic::PanicInfo;

use lazyinit::LazyInit;
pub trait PanicHelper: Send + Sync {
    /// Looks up the symbol name and its base address by the given address.
    fn lookup_symbol<'a>(&self, addr: usize, buf: &'a mut [u8; 1024]) -> Option<(&'a str, usize)>;
}

static PANIC_HELPER: LazyInit<&'static dyn PanicHelper> = LazyInit::new();

/// Sets the panic helper.
pub fn set_panic_helper(helper: &'static dyn PanicHelper) {
    PANIC_HELPER.init_once(helper);
}

#[cfg(any(not(feature = "alloc"), target_arch = "loongarch64"))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    ax_println!("{}", info);
    // ax_println!("{}", axbacktrace::Backtrace::capture());
    axhal::power::system_off()
}

#[cfg(not(target_arch = "loongarch64"))]
mod unwind {
    use alloc::boxed::Box;
    use core::{ffi::c_void, sync::atomic::AtomicBool};

    use unwinding::abi::{_Unwind_Backtrace, _Unwind_GetIP, UnwindContext, UnwindReasonCode};

    use super::PanicInfo;

    static RECURSION: AtomicBool = AtomicBool::new(false);
    #[derive(Debug)]
    struct PanicGuard;

    impl PanicGuard {
        pub fn new() -> Self {
            Self
        }
    }

    impl Drop for PanicGuard {
        fn drop(&mut self) {}
    }

    #[panic_handler]
    fn panic_handler(info: &PanicInfo) -> ! {
        if let Some(p) = info.location() {
            ax_println!("line {}, file {}: {}", p.line(), p.file(), info.message());
        } else {
            ax_println!("no location information available");
        }
        if !RECURSION.swap(true, core::sync::atomic::Ordering::SeqCst) {
            if info.can_unwind() {
                let guard = Box::new(PanicGuard::new());
                print_stack_trace();
                let _res = unwinding::panic::begin_panic(guard);
                panic!("panic unreachable: {:?}", _res.0);
            }
        }
        axhal::power::system_off()
    }

    pub fn print_stack_trace() {
        ax_println!("Rust Panic Backtrace:");
        struct CallbackData {
            counter: usize,
            kernel_main: bool,
        }
        extern "C" fn callback(
            unwind_ctx: &UnwindContext<'_>,
            arg: *mut c_void,
        ) -> UnwindReasonCode {
            let mut name_buf = [0u8; 1024];
            let data = unsafe { &mut *(arg as *mut CallbackData) };
            if data.kernel_main {
                // If we are in kernel_main, we don't need to print the backtrace.
                return UnwindReasonCode::NORMAL_STOP;
            }
            data.counter += 1;
            let pc = _Unwind_GetIP(unwind_ctx);
            if pc > 0 {
                let res = super::PANIC_HELPER
                    .get()
                    .and_then(|helper| helper.lookup_symbol(pc, &mut name_buf));
                if let Some((name, addr)) = res {
                    if name.contains("main") {
                        data.kernel_main = true;
                    }
                    ax_println!(
                        "#{:<2} {:#018x} - {} + {:#x}",
                        data.counter,
                        pc,
                        name,
                        pc - addr
                    );
                } else {
                    ax_println!("#{:<2} {:#018x} - <unknown>", data.counter, pc);
                }
            }
            UnwindReasonCode::NO_REASON
        }
        let mut data = CallbackData {
            counter: 0,
            kernel_main: false,
        };
        _Unwind_Backtrace(callback, &mut data as *mut _ as _);
    }
}
