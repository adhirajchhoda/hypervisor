#[cfg(not(test))]
pub mod allocator;
mod amd;
mod apic_id;
pub mod debug_fb;
pub mod gdt_tss;
mod host;
mod intel;
pub mod interrupt_handlers;
pub mod paging_structures;
pub mod panic;
pub mod platform_ops;
mod registers;
mod segment;
mod serial_logger;
mod support;
mod switch_stack;
mod x86_instructions;

use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;
use x86::cpuid::cpuid;

use crate::{GdtTss, PagingStructures, hypervisor::registers::Registers};

use self::interrupt_handlers::InterruptDescriptorTable;

pub fn virtualize_system(shared_host: SharedHostData) {
    serial_logger::init(log::LevelFilter::Info);
    log::info!("Virtualizing the all processors");

    apic_id::init();
    let _ = SHARED_HOST_DATA.call_once(|| shared_host);

    platform_ops::get().run_on_aps(virtualize_current_processor);
    virtualize_current_processor();

    log::info!("Virtualized the all processors");
}

pub fn vmcb_diagnostic_run(shared_host: SharedHostData) -> ([u64; 16], [u64; 3]) {
    serial_logger::init(log::LevelFilter::Info);
    apic_id::init_bsp_only();
    let _ = SHARED_HOST_DATA.call_once(|| shared_host);

    x86_instructions::ensure_sse_enabled();

    if unsafe { x86::task::tr() }.bits() == 0 {
        let gdt = Box::leak(Box::new(GdtTss::new_from_current()));
        gdt.append_tss(x86::bits64::task::TaskStateSegment::new())
            .apply()
            .unwrap();
    }

    let mut registers = Registers::capture_current();

    registers.rip = diag_guest_stub as u64;

    use host::{Extension, Guest};
    let mut svm = amd::svm_ext_new();
    svm.enable();

    let mut guest = amd::Amd::guest_new(0);
    guest.activate();
    guest.diagnostic_init(&registers);
    let fields = guest.diagnostic_fields();
    let exit = guest.diagnostic_run_once();
    (fields, exit)
}

#[unsafe(naked)]
unsafe extern "C" fn diag_guest_stub() -> ! {
    core::arch::naked_asm!("xor eax, eax", "cpuid", "2: hlt", "jmp 2b",);
}

#[unsafe(naked)]
unsafe extern "C" fn isolation_guest_stub() -> ! {
    core::arch::naked_asm!("2:", "xor eax, eax", "cpuid", "jmp 2b",);
}

#[unsafe(naked)]
unsafe extern "C" fn guest_resume_stub() -> ! {
    core::arch::naked_asm!(
        "mov eax, 0x40000000",
        "cpuid",
        "cmp ebx, 0x65726142",
        "jne 2f",
        "cmp ecx, 0x6f736976",
        "jne 2f",

        "cli",
        "1: hlt",
        "jmp 1b",

        "2: mov al, 0xBB",
        "out 0x80, al",
        "cli",
        "3: hlt",
        "jmp 3b",
    );
}

pub fn virtualize_bsp_only(shared_host: SharedHostData) {
    serial_logger::init(log::LevelFilter::Info);
    log::info!("Virtualizing BSP only (diagnostic mode)");

    apic_id::init_bsp_only();
    let _ = SHARED_HOST_DATA.call_once(|| shared_host);

    virtualize_current_processor();

}

fn virtualize_current_processor() {

    x86_instructions::ensure_sse_enabled();

    if unsafe { x86::task::tr() }.bits() == 0 {
        let gdt = Box::leak(Box::new(GdtTss::new_from_current()));
        gdt.append_tss(x86::bits64::task::TaskStateSegment::new())
            .apply()
            .unwrap();
    }

    let registers = Registers::capture_current();

    if !is_our_hypervisor_present() {
        switch_stack::jump_with_new_stack(host::main, &registers);
    }

}

#[derive(Debug, Default)]
pub struct SharedHostData {

    pub pt: Option<PagingStructures>,

    pub idt: Option<InterruptDescriptorTable>,

    pub gdts: Option<Vec<GdtTss>>,
}

static SHARED_HOST_DATA: Once<SharedHostData> = Once::new();

pub const LADDER_STEP: u8 = 2;

pub static DIAG_SCREEN_FN: AtomicU64 = AtomicU64::new(0);

pub static CPUID_EXIT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static RDMSR_EXIT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static WRMSR_EXIT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static NPF_EXIT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static VMMCALL_EXIT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static SHUTDOWN_EXIT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static HLT_EXIT_COUNT: AtomicU64 = AtomicU64::new(0);

pub static VMCB_INTERCEPT_MISC1: AtomicU64 = AtomicU64::new(0);
pub static VMCB_INTERCEPT_MISC2: AtomicU64 = AtomicU64::new(0);
pub static VMCB_INTERCEPT_EXCEPTION: AtomicU64 = AtomicU64::new(0);
pub static VMCB_NP_ENABLE: AtomicU64 = AtomicU64::new(0);
pub static VMCB_PA: AtomicU64 = AtomicU64::new(0);

pub static UNKNOWN_EXIT_COUNT: AtomicU64 = AtomicU64::new(0);

pub static UNKNOWN_EXIT_LAST: AtomicU64 = AtomicU64::new(0);

pub(crate) const HV_CPUID_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x4000_0000;
pub(crate) const HV_CPUID_INTERFACE: u32 = 0x4000_0001;
pub(crate) const OUR_HV_VENDOR_NAME_EBX: u32 = u32::from_ne_bytes(*b"Bare");
pub(crate) const OUR_HV_VENDOR_NAME_ECX: u32 = u32::from_ne_bytes(*b"viso");
pub(crate) const OUR_HV_VENDOR_NAME_EDX: u32 = u32::from_ne_bytes(*b"r!  ");

fn is_our_hypervisor_present() -> bool {
    let regs = cpuid!(HV_CPUID_VENDOR_AND_MAX_FUNCTIONS);
    (regs.ebx == OUR_HV_VENDOR_NAME_EBX)
        && (regs.ecx == OUR_HV_VENDOR_NAME_ECX)
        && (regs.edx == OUR_HV_VENDOR_NAME_EDX)
}
