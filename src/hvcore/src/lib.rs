#![no_std]

extern crate alloc;

pub mod hypervisor;

pub use hypervisor::CPUID_EXIT_COUNT;
pub use hypervisor::DIAG_SCREEN_FN;
pub use hypervisor::LADDER_STEP;
pub use hypervisor::SharedHostData;
pub use hypervisor::UNKNOWN_EXIT_COUNT;
pub use hypervisor::UNKNOWN_EXIT_LAST;
pub use hypervisor::VMCB_INTERCEPT_EXCEPTION;
pub use hypervisor::VMCB_INTERCEPT_MISC1;
pub use hypervisor::VMCB_INTERCEPT_MISC2;
pub use hypervisor::VMCB_NP_ENABLE;
pub use hypervisor::VMCB_PA;
#[cfg(not(test))]
pub use hypervisor::allocator;
pub use hypervisor::debug_fb;
pub use hypervisor::gdt_tss::GdtTss;
pub use hypervisor::interrupt_handlers::InterruptDescriptorTable;
pub use hypervisor::paging_structures::PagingStructures;
pub use hypervisor::panic::panic_impl;
pub use hypervisor::platform_ops;
pub use hypervisor::virtualize_bsp_only;
pub use hypervisor::virtualize_system;
pub use hypervisor::vmcb_diagnostic_run;
