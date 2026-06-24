#![doc = include_str!("../../README.md")]
#![no_main]
#![no_std]

extern crate alloc;

mod ops;
mod println;

use alloc::{boxed::Box, vec::Vec};
use hv::GdtTss;
use uefi::{
    boot::{self, AllocateType, MemoryType},
    prelude::*,
    proto::{loaded_image::LoadedImage, pi::mp::MpServices},
};
use x86::bits64::task::TaskStateSegment;

#[entry]
fn main() -> Status {
    println!("Loading uefi_hv.efi");

    boot::set_watchdog_timer(0, 0x10000, None).ok();

    unsafe {
        disable_amd_watchdog();
    }

    match boot::allocate_pages(
        AllocateType::MaxAddress(0x7F_FFFF_FFFF),
        MemoryType::RUNTIME_SERVICES_DATA,
        hv::allocator::ALLOCATION_PAGES,
    ) {
        Ok(ptr) => hv::allocator::init(ptr.as_ptr()),
        Err(e) => {
            println!("Memory allocation failed: {e}");
            return e.status();
        }
    }

    hv::platform_ops::init(Box::new(ops::UefiOps));

    if let Err(e) = zap_relocation_table() {
        println!("zap_relocation_table failed: {e}");
        return e.status();
    }

    hv::platform_ops::get().run_on_all_processors(|| {
        let new_gdt = Box::leak(Box::new(GdtTss::new_from_current()));
        new_gdt.append_tss(TaskStateSegment::new()).apply().unwrap();
    });

    if !svm_preflight() {
        println!("SVM preflight FAILED — cannot virtualize. Check BIOS settings.");
        return Status::UNSUPPORTED;
    }

    unsafe {
        use core::arch::asm;
        let read_msr = |msr: u32| -> u64 {
            let lo: u32;
            let hi: u32;
            asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack));
            (hi as u64) << 32 | lo as u64
        };
        let hwcr = read_msr(0xC001_0015);
        let vm_cr = read_msr(0xC001_0114);
        let smm_base = read_msr(0xC001_0111);
        let smm_addr = read_msr(0xC001_0112);
        let smm_mask = read_msr(0xC001_0113);

        let smm_lock = (hwcr >> 0) & 1;
        let svm_dis = (vm_cr >> 4) & 1;
        let svm_lock = (vm_cr >> 3) & 1;
        let r_init = (vm_cr >> 1) & 1;

        println!("=== SMM/SVM Lock Diagnostics ===");
        println!("HWCR     = {hwcr:#018x}  SmmLock={smm_lock}");
        println!("VM_CR    = {vm_cr:#018x}  SvmDis={svm_dis} Lock={svm_lock} R_INIT={r_init}");
        println!("SMM_BASE = {smm_base:#018x}");
        println!("SmmAddr  = {smm_addr:#018x}  (TSEG base)");
        println!("SmmMask  = {smm_mask:#018x}  (TSEG mask)");
        println!("================================");
    }

    println!("Creating shared host data...");
    let shared_host = match create_shared_host_data() {
        Ok(sh) => {
            println!("Shared host data OK");
            sh
        }
        Err(e) => {
            println!("create_shared_host_data failed: {e}");
            return e.status();
        }
    };

    let cr0_val: u64;
    let cr4_val: u64;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0_val, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4_val, options(nomem, nostack, preserves_flags));
    }
    println!("CR0={cr0_val:#018x} CR4={cr4_val:#018x}");
    println!(
        "  CR0.TS={} CR0.EM={} CR4.OSFXSR={}",
        (cr0_val >> 3) & 1,
        (cr0_val >> 2) & 1,
        (cr4_val >> 9) & 1
    );

    let tr_sel = unsafe { x86::task::tr() };
    println!("TR selector={:#06x}", tr_sel.bits());
    if tr_sel.bits() != 0 {
        let mut gdtr = x86::dtables::DescriptorTablePointer::<u64>::default();
        unsafe { x86::dtables::sgdt(&mut gdtr) };
        let gdt_base = gdtr.base as *const u64;
        let idx = tr_sel.index() as usize;
        let desc_lo = unsafe { *gdt_base.add(idx) };
        let tr_type = (desc_lo >> 40) & 0xF;
        println!(
            "  GDT[{}] desc_lo={:#018x} type={:#x}",
            idx, desc_lo, tr_type
        );
    }

    {
        use uefi::proto::console::gop::GraphicsOutput;
        match boot::get_handle_for_protocol::<GraphicsOutput>() {
            Ok(h) => match boot::open_protocol_exclusive::<GraphicsOutput>(h) {
                Ok(mut gop) => {
                    let mode = gop.current_mode_info();
                    let (w, height) = mode.resolution();
                    let stride = mode.stride();
                    let base = gop.frame_buffer().as_mut_ptr() as u64;
                    hv::debug_fb::set_framebuffer(base, stride as u64, w as u64, height as u64);
                    println!("GOP fb base={base:#x} {w}x{height} stride={stride}");
                }
                Err(e) => println!("GOP open failed: {e} (no framebuffer debug)"),
            },
            Err(e) => println!("GOP handle not found: {e} (no framebuffer debug)"),
        }
    }

    if hv::LADDER_STEP == 0 {
        println!("LADDER_STEP=0 — HV DISABLED. Chainloading Windows raw (no VMRUN).");
        return Status::SUCCESS;
    }

    println!(
        "Virtualizing all processors (ladder step {}) ...",
        hv::LADDER_STEP
    );

    hv::DIAG_SCREEN_FN.store(
        diag_print_on_screen as *const () as u64,
        core::sync::atomic::Ordering::Release,
    );

    hv::virtualize_system(shared_host);
    println!("All processors virtualized — running as guest now");

    let cpuid_before = hv::CPUID_EXIT_COUNT.load(core::sync::atomic::Ordering::Acquire);
    let _ = x86::cpuid::cpuid!(0);
    let cpuid_after = hv::CPUID_EXIT_COUNT.load(core::sync::atomic::Ordering::Acquire);
    if cpuid_after > cpuid_before {
        println!("CPUID intercept verified — hypervisor is active");
    } else {
        println!("WARNING: CPUID intercept not firing");
    }

    println!("Hypervisor active — returning to shim");
    Status::SUCCESS
}

extern "C" fn diag_print_on_screen(
    exit_code: u64,
    exit_info1: u64,
    exit_info2: u64,
    guest_rip: u64,
) -> ! {
    println!();
    println!("========== GUEST VMEXIT ==========");
    println!("exit_code = {exit_code:#x}");
    println!("exit_info1 = {exit_info1:#x}");
    println!("exit_info2 = {exit_info2:#x}");
    println!("guest_rip  = {guest_rip:#x}");

    match exit_code {
        0x48 => println!("=> #DF (Double Fault)"),
        0x4e => println!("=> #PF (Page Fault), addr = {exit_info2:#x}"),
        0x4d => println!("=> #GP (General Protection), error = {exit_info1:#x}"),
        0x62 => println!("=> #VMEXIT(SMI) — SMI intercept fired!"),
        0x7f => println!("=> SHUTDOWN (Triple Fault)"),
        code if code >= 0x40 && code < 0x60 => println!("=> Exception vector {}", code - 0x40),
        _ => println!("=> (other)"),
    }
    println!("==================================");
    println!("Machine halted. Power off manually.");
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

fn svm_preflight() -> bool {
    use core::arch::asm;

    let cpuid_result = x86::cpuid::cpuid!(0x8000_0001);
    let svm_supported = (cpuid_result.ecx & (1 << 2)) != 0;
    println!(
        "CPUID 8000_0001h: ECX={:#010x} => SVM supported: {svm_supported}",
        cpuid_result.ecx
    );
    if !svm_supported {
        println!("ERROR: CPU does not support SVM (AMD-V)");
        return false;
    }

    let vm_cr_lo: u32;
    let vm_cr_hi: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") 0xC001_0114u32,
            out("eax") vm_cr_lo,
            out("edx") vm_cr_hi,
            options(nostack, preserves_flags),
        );
    }
    let vm_cr = (vm_cr_hi as u64) << 32 | vm_cr_lo as u64;
    let svmdis = (vm_cr & (1 << 4)) != 0;
    println!("MSR VM_CR (C001_0114h): {vm_cr:#018x} => SVMDIS: {svmdis}");
    if svmdis {
        println!("ERROR: SVM is disabled by BIOS lock bit. Enable SVM/AMD-V in BIOS.");
        return false;
    }

    let efer_lo: u32;
    let efer_hi: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") 0xC000_0080u32,
            out("eax") efer_lo,
            out("edx") efer_hi,
            options(nostack, preserves_flags),
        );
    }
    let efer = (efer_hi as u64) << 32 | efer_lo as u64;
    let svme_set = (efer & (1 << 12)) != 0;
    println!("MSR EFER: {efer:#018x} => SVME already set: {svme_set}");

    let svm_features = x86::cpuid::cpuid!(0x8000_000A);
    println!(
        "SVM rev: {} NASID: {} features EDX: {:#010x}",
        svm_features.eax & 0xFF,
        svm_features.ebx,
        svm_features.edx,
    );
    let npt_supported = (svm_features.edx & (1 << 0)) != 0;
    let nrip_supported = (svm_features.edx & (1 << 3)) != 0;
    println!("  NPT (nested paging): {npt_supported}");
    println!("  NRIP save: {nrip_supported}");
    if !npt_supported {
        println!("ERROR: CPU does not support Nested Page Tables — required");
        return false;
    }

    match boot::get_handle_for_protocol::<MpServices>() {
        Ok(handle) => match boot::open_protocol_exclusive::<MpServices>(handle) {
            Ok(mp) => {
                let info = mp.get_number_of_processors().unwrap();
                println!("Processors: {} total, {} enabled", info.total, info.enabled);
            }
            Err(e) => println!("MpServices open failed: {e}"),
        },
        Err(e) => println!("MpServices not found: {e} (single-core path will be used)"),
    }

    println!("SVM preflight PASSED");
    true
}

fn create_shared_host_data() -> uefi::Result<hv::SharedHostData> {
    use hv::InterruptDescriptorTable;

    let idt = InterruptDescriptorTable::clone_from_current();
    Ok(hv::SharedHostData {
        pt: None,
        idt: Some(idt),
        gdts: None,
    })
}

fn zap_relocation_table() -> uefi::Result<()> {
    const NT_RELOCATION_DIRECTORY_RVA: u64 = 0x128;
    const NT_RELOCATION_DIRECTORY_SIZE: u64 = 0x12c;

    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;
    let (image_base, _image_size) = loaded_image.info();
    let image_base = image_base as u64;

    unsafe {
        *((image_base + NT_RELOCATION_DIRECTORY_RVA) as *mut u32) = 0;
        *((image_base + NT_RELOCATION_DIRECTORY_SIZE) as *mut u32) = 0;
    }
    Ok(())
}

unsafe fn disable_amd_watchdog() {
    use core::arch::asm;

    let mut mmio_raw: u32 = 0;
    for i in 0u8..4 {
        let idx = 0x24u8 + i;
        asm!("out dx, al", in("dx") 0xCD6u16, in("al") idx, options(nomem, nostack));
        let byte: u8;
        asm!("in al, dx", in("dx") 0xCD7u16, out("al") byte, options(nomem, nostack));
        mmio_raw |= (byte as u32) << (i * 8);
    }
    let acpi_mmio = (mmio_raw & 0xFFFF_E000) as u64;
    println!("AMD PM MMIO raw={mmio_raw:#010x} base={acpi_mmio:#x}");

    asm!("out dx, al", in("dx") 0xCD6u16, in("al") 0x00u8, options(nomem, nostack));
    let decode_en: u8;
    asm!("in al, dx", in("dx") 0xCD7u16, out("al") decode_en, options(nomem, nostack));
    if decode_en & (1 << 7) == 0 {
        let new_val = decode_en | (1 << 7);
        asm!("out dx, al", in("dx") 0xCD6u16, in("al") 0x00u8, options(nomem, nostack));
        asm!("out dx, al", in("dx") 0xCD7u16, in("al") new_val, options(nomem, nostack));
        println!("  WDT decode enabled (was {decode_en:#04x} -> {new_val:#04x})");
    }

    let wdt_addrs: [u64; 3] = [
        if acpi_mmio != 0 { acpi_mmio + 0xB00 } else { 0 },
        0xFED8_0B00,
        0xFEB0_0000,
    ];

    for wdt_base in wdt_addrs {
        if wdt_base == 0 {
            continue;
        }

        if wdt_base == 0xFED8_0B00 && acpi_mmio == 0xFED8_0000 {
            continue;
        }

        let wdt_ctrl = wdt_base as *mut u32;
        let wdt_count = (wdt_base + 4) as *mut u32;
        let ctrl_val = core::ptr::read_volatile(wdt_ctrl);
        let cnt_val = core::ptr::read_volatile(wdt_count);
        println!("WDT@{wdt_base:#x}: ctrl={ctrl_val:#010x} count={cnt_val:#010x}");

        let stopped = ctrl_val & !(1 << 1);
        core::ptr::write_volatile(wdt_ctrl, stopped);

        core::ptr::write_volatile(wdt_ctrl, 0);

        let after = core::ptr::read_volatile(wdt_ctrl);
        println!("  after disable: ctrl={after:#010x}");
    }
}

#[cfg(not(any(test, doc)))]
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {

    let _ =
        core::fmt::Write::write_fmt(&mut UefiConsoleSink, format_args!("\n!!! PANIC: {info}\n"));
    hv::panic_impl(info)
}

struct UefiConsoleSink;
impl core::fmt::Write for UefiConsoleSink {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        system::with_stdout(|stdout| {
            let _ = core::fmt::Write::write_str(stdout, s);
        });
        Ok(())
    }
}
