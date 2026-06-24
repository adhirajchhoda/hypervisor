use core::{
    arch::{asm, global_asm},
    ptr::addr_of,
    sync::atomic::{AtomicU8, Ordering},
};

use alloc::boxed::Box;
use bit_field::BitField;
use derive_more::Debug;
use spin::{Lazy, RwLock};
use x86::{
    bits64::{paging::BASE_PAGE_SHIFT, rflags::RFlags},
    cpuid::cpuid,
    segmentation::{cs, ds, es, ss},
};

use crate::hypervisor::{
    HV_CPUID_INTERFACE, HV_CPUID_VENDOR_AND_MAX_FUNCTIONS, OUR_HV_VENDOR_NAME_EBX,
    OUR_HV_VENDOR_NAME_ECX, OUR_HV_VENDOR_NAME_EDX, SHARED_HOST_DATA, apic_id,
    host::{Guest, InstructionInfo, VmExitReason},
    platform_ops,
    registers::Registers,
    support::zeroed_box,
    x86_instructions::{cr0, cr3, cr4, lidt, rdmsr, sgdt, sidt, wrmsr},
};

use super::npts::NestedPageTables;

#[derive(Debug)]
pub(crate) struct SvmGuest {
    id: usize,
    registers: Registers,
    vmcb: Vmcb,
    vmcb_pa: u64,
    host_vmcb: Vmcb,
    host_vmcb_pa: u64,
    #[debug(skip)]
    host_state: HostStateArea,
    activity_state: &'static AtomicU8,
}

impl Guest for SvmGuest {
    fn new(id: usize) -> Self {
        let mut vm = Self {
            id,
            registers: Registers::default(),
            vmcb: Vmcb::default(),
            vmcb_pa: 0,
            host_vmcb: Vmcb::default(),
            host_vmcb_pa: 0,
            host_state: HostStateArea::default(),
            activity_state: &SHARED_GUEST_DATA.activity_states[id],
        };

        vm.vmcb_pa = platform_ops::get().pa(addr_of!(*vm.vmcb.as_ref()) as _);
        vm.host_vmcb_pa = platform_ops::get().pa(addr_of!(*vm.host_vmcb.as_ref()) as _);

        vm
    }
    fn activate(&mut self) {
        const SVM_MSR_VM_HSAVE_PA: u32 = 0xc001_0117;

        let pa = platform_ops::get().pa(addr_of!(*self.host_state.as_ref()) as _);
        assert!(
            pa & 0xfff == 0,
            "VM_HSAVE_PA must be 4KB-aligned, got {pa:#x}"
        );
        wrmsr(SVM_MSR_VM_HSAVE_PA, pa);
    }

    fn initialize(&mut self, registers: &Registers) {
        self.registers = *registers;
        self.initialize_control();
        self.initialize_guest();
        self.initialize_host();
        self.validate_vmcb();
    }

    fn run(&mut self) -> VmExitReason {
        #[allow(dead_code)]
        const VMEXIT_SMI: u64 = 0x62;
        const VMEXIT_INTR: u64 = 0x60;
        const VMEXIT_NMI: u64 = 0x61;
        const VMEXIT_INIT: u64 = 0x63;
        const VMEXIT_PAUSE: u64 = 0x77;
        const VMEXIT_EXCEPTION_DB: u64 = 0x41;
        const VMEXIT_EXCEPTION_SX: u64 = 0x5e;
        const VMEXIT_HLT: u64 = 0x78;
        const VMEXIT_MWAIT: u64 = 0x8b;
        const VMEXIT_MWAIT_COND: u64 = 0x8c;
        const VMEXIT_IOIO: u64 = 0x7b;
        const VMEXIT_CPUID: u64 = 0x72;
        const VMEXIT_RDMSR: u64 = 0x7c;
        const VMEXIT_WRMSR: u64 = 0x7d;
        const VMEXIT_SHUTDOWN: u64 = 0x7f;
        const VMEXIT_VMMCALL: u64 = 0x81;
        const VMEXIT_NPF: u64 = 0x400;

        self.vmcb.state_save_area.rax = self.registers.rax;
        self.vmcb.state_save_area.rip = self.registers.rip;
        self.vmcb.state_save_area.rsp = self.registers.rsp;
        self.vmcb.state_save_area.rflags = self.registers.rflags;

        log::trace!("Entering the guest");

        unsafe { run_svm_guest(&mut self.registers, self.vmcb_pa, self.host_vmcb_pa) };

        log::trace!("Exited the guest");

        self.registers.rax = self.vmcb.state_save_area.rax;
        self.registers.rip = self.vmcb.state_save_area.rip;
        self.registers.rsp = self.vmcb.state_save_area.rsp;
        self.registers.rflags = self.vmcb.state_save_area.rflags;

        self.vmcb.control_area.tlb_control = TlbControl::DoNotFlush as _;

        self.vmcb.control_area.vmcb_clean = 0;

        let exit_code = self.vmcb.control_area.exit_code;

        crate::hypervisor::debug_fb::heartbeat();

        match exit_code {
            VMEXIT_CPUID => {
                crate::hypervisor::CPUID_EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
                self.handle_cpuid();
                VmExitReason::Smi
            }
            VMEXIT_RDMSR => {
                crate::hypervisor::RDMSR_EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
                VmExitReason::Rdmsr(InstructionInfo {
                    next_rip: self.vmcb.control_area.nrip,
                })
            }
            VMEXIT_WRMSR => {
                crate::hypervisor::WRMSR_EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
                VmExitReason::Wrmsr(InstructionInfo {
                    next_rip: self.vmcb.control_area.nrip,
                })
            }
            VMEXIT_VMMCALL => {
                crate::hypervisor::VMMCALL_EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
                self.handle_vmmcall();
                VmExitReason::Smi
            }
            VMEXIT_HLT => {
                crate::hypervisor::HLT_EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
                let nrip = self.vmcb.control_area.nrip;
                if nrip != 0 && nrip > self.registers.rip {
                    self.registers.rip = nrip;
                } else {
                    self.registers.rip += 1;
                }
                VmExitReason::Smi
            }
            VMEXIT_MWAIT | VMEXIT_MWAIT_COND => {
                crate::hypervisor::HLT_EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
                let nrip = self.vmcb.control_area.nrip;
                if nrip != 0 && nrip > self.registers.rip {
                    self.registers.rip = nrip;
                } else {
                    self.registers.rip += 3;
                }
                VmExitReason::Smi
            }
            VMEXIT_IOIO => {
                let info1 = self.vmcb.control_area.exit_info1;
                let is_in = (info1 & 1) != 0;
                let size = ((info1 >> 4) & 0x7) as u8;
                let port = ((info1 >> 16) & 0xFFFF) as u16;

                let is_string = (info1 & (1 << 16)) != 0;
                let is_rep = (info1 & (1 << 3)) != 0;
                if !is_string && !is_rep {
                    if is_in {
                        let val: u32 = unsafe {
                            match size {
                                0 => {
                                    let v: u8;
                                    asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack));
                                    v as u32
                                }
                                1 => {
                                    let v: u16;
                                    asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack));
                                    v as u32
                                }
                                _ => {
                                    let v: u32;
                                    asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack));
                                    v
                                }
                            }
                        };
                        self.registers.rax =
                            (self.registers.rax & !((1u64 << (8 << size)) - 1)) | val as u64;
                    } else {
                        let val = self.registers.rax as u32;
                        unsafe {
                            match size {
                                0 => {
                                    asm!("out dx, al", in("dx") port, in("al") val as u8, options(nomem, nostack))
                                }
                                1 => {
                                    asm!("out dx, ax", in("dx") port, in("ax") val as u16, options(nomem, nostack))
                                }
                                _ => {
                                    asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack))
                                }
                            }
                        };
                    }
                }
                let nrip = self.vmcb.control_area.nrip;
                if nrip != 0 && nrip > self.registers.rip {
                    self.registers.rip = nrip;
                } else {
                    self.registers.rip = self.vmcb.control_area.exit_info2;
                }
                VmExitReason::Smi
            }
            VMEXIT_NPF => {
                crate::hypervisor::NPF_EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
                self.handle_nested_page_fault();
                VmExitReason::NestedPageFault
            }
            VMEXIT_EXCEPTION_DB => {
                self.handle_debug_exception();
                VmExitReason::Smi
            }
            VMEXIT_INTR => VmExitReason::Smi,
            VMEXIT_NMI => {
                const EVENTINJ_VALID: u64 = 1 << 31;
                const EVENTINJ_TYPE_NMI: u64 = 2 << 8;
                const EVENTINJ_VECTOR_NMI: u64 = 2;
                self.vmcb.control_area.event_inj =
                    EVENTINJ_VALID | EVENTINJ_TYPE_NMI | EVENTINJ_VECTOR_NMI;
                VmExitReason::Smi
            }
            VMEXIT_INIT => {
                if self.id != 0 {
                    self.handle_security_exception();
                }
                VmExitReason::Smi
            }
            VMEXIT_PAUSE => {
                self.vmcb.control_area.pause_filter_count = PAUSE_FILTER_RELOAD;
                VmExitReason::Smi
            }
            VMEXIT_SHUTDOWN => {
                let exit_info1 = self.vmcb.control_area.exit_info1;
                let exit_info2 = self.vmcb.control_area.exit_info2;
                let guest_rip = self.vmcb.state_save_area.rip;

                unsafe {
                    serial_out_str(b"\r\nSHUTDOWN(triple fault) rip=");
                    serial_out_hex(guest_rip);
                    serial_out_str(b" info1=");
                    serial_out_hex(exit_info1);
                    serial_out_str(b" info2=");
                    serial_out_hex(exit_info2);
                    serial_out_str(b"\r\n");
                }

                use crate::hypervisor::debug_fb;
                debug_fb::paint_code(exit_code);
                debug_fb::paint_code(guest_rip & 0xFFFF);
                debug_fb::paint_code((guest_rip >> 16) & 0xFFFF);
                debug_fb::paint_code((guest_rip >> 32) & 0xFFFF);
                debug_fb::paint_code(exit_info1 & 0xFFFF);
                debug_fb::paint_code(exit_info2 & 0xFFFF);
                unsafe {
                    x86::irq::disable();
                }
                loop {
                    unsafe { x86::halt() }
                }
            }
            _ => {
                use crate::hypervisor::{UNKNOWN_EXIT_COUNT, UNKNOWN_EXIT_LAST};
                UNKNOWN_EXIT_COUNT.fetch_add(1, Ordering::Relaxed);
                UNKNOWN_EXIT_LAST.store(exit_code as u64, Ordering::Relaxed);

                crate::hypervisor::debug_fb::paint_code(exit_code);

                unsafe {
                    serial_out_str(b"\r\n!VMEXIT ec=");
                    serial_out_hex(exit_code);
                    serial_out_str(b" rip=");
                    serial_out_hex(self.vmcb.state_save_area.rip);
                    serial_out_str(b"\r\n");

                    asm!("out 0x80, al", in("al") exit_code as u8, options(nomem, nostack));
                }

                let nrip = self.vmcb.control_area.nrip;
                if nrip != 0 && nrip > self.registers.rip {
                    self.registers.rip = nrip;
                }
                self.vmcb.control_area.vmcb_clean = 0;

                VmExitReason::Smi
            }
        }
    }

    fn regs(&mut self) -> &mut Registers {
        &mut self.registers
    }

    fn diagnostic_init(&mut self, registers: &Registers) {
        self.registers = *registers;
        self.initialize_control();
        self.initialize_guest();
    }

    fn diagnostic_run_once(&mut self) -> [u64; 3] {
        unsafe { asm!("cli", options(nostack, preserves_flags)) };

        vmsave(self.host_vmcb_pa);

        let tr_attrib = self.host_vmcb.state_save_area.tr_attrib;
        let tr_type = tr_attrib & 0xF;
        if tr_type == 0x9 {
            self.host_vmcb.state_save_area.tr_attrib = (tr_attrib & !0xF) | 0xB;
        } else if tr_type == 0x1 {
            self.host_vmcb.state_save_area.tr_attrib = (tr_attrib & !0xF) | 0x3;
        }

        self.vmcb.state_save_area.rax = self.registers.rax;
        self.vmcb.state_save_area.rip = self.registers.rip;
        self.vmcb.state_save_area.rsp = self.registers.rsp;
        self.vmcb.state_save_area.rflags = self.registers.rflags;

        unsafe { run_svm_guest(&mut self.registers, self.vmcb_pa, self.host_vmcb_pa) };

        unsafe { asm!("sti", options(nostack, preserves_flags)) };

        [
            self.vmcb.control_area.exit_code,
            self.vmcb.control_area.exit_info1,
            self.vmcb.control_area.exit_info2,
        ]
    }

    fn diagnostic_fields(&self) -> [u64; 16] {
        let sa = &self.vmcb.state_save_area;
        let ca = &self.vmcb.control_area;
        [
            sa.efer,
            sa.cr0,
            sa.cr3,
            sa.cr4,
            sa.cs_attrib as u64,
            sa.ss_attrib as u64,
            sa.tr_attrib as u64,
            ca.ncr3,
            self.vmcb_pa,
            ca.iopm_base_pa,
            ca.msrpm_base_pa,
            sa.rip,
            sa.rsp,
            sa.cpl as u64,
            sa.dr6,
            sa.dr7,
        ]
    }
}

const PAUSE_FILTER_RELOAD: u16 = 128;

impl SvmGuest {
    fn handle_security_exception(&mut self) {
        if self.id == 0 {
            unsafe {
                asm!("out 0x80, al", in("al") 0x5Eu8, options(nomem, nostack));
                x86::irq::disable();
            }
            loop {
                unsafe { x86::halt() }
            }
        }
        self.handle_init_signal();
        self.handle_sipi(self.wait_for_sipi());
    }

    fn handle_init_signal(&mut self) {
        const EFER_SVME: u64 = 1 << 12;

        if self.id == 0 {
            unsafe {
                asm!("out 0x80, al", in("al") 0x5Fu8, options(nomem, nostack));
                x86::irq::disable();
            }
            loop {
                unsafe { x86::halt() }
            }
        }

        assert!(
            self.activity_state
                .swap(GuestActivityState::WaitForSipi as u8, Ordering::Relaxed)
                == GuestActivityState::Active as u8
        );

        log::debug!("INIT");

        let previous_cr0 = self.vmcb.state_save_area.cr0;
        let new_cr0 = (1u64 << 4)
            | ((previous_cr0.get_bit(29) as u64) << 29)
            | ((previous_cr0.get_bit(30) as u64) << 30);
        self.vmcb.state_save_area.cr0 = new_cr0;
        self.vmcb.state_save_area.cr2 = 0;
        self.vmcb.state_save_area.cr3 = 0;
        self.vmcb.state_save_area.cr4 = 0;
        self.vmcb.state_save_area.rflags = RFlags::FLAGS_A1.bits();
        self.registers.rflags = RFlags::FLAGS_A1.bits();
        self.vmcb.state_save_area.efer = EFER_SVME;
        self.vmcb.state_save_area.rip = 0xfff0;
        self.registers.rip = 0xfff0;
        self.vmcb.state_save_area.cs_selector = 0xf000;
        self.vmcb.state_save_area.cs_base = 0xffff0000;
        self.vmcb.state_save_area.cs_limit = 0xffff;
        self.vmcb.state_save_area.cs_attrib = 0x9b;
        self.vmcb.state_save_area.ds_selector = 0;
        self.vmcb.state_save_area.ds_base = 0;
        self.vmcb.state_save_area.ds_limit = 0xffff;
        self.vmcb.state_save_area.ds_attrib = 0x93;
        self.vmcb.state_save_area.es_selector = 0;
        self.vmcb.state_save_area.es_base = 0;
        self.vmcb.state_save_area.es_limit = 0xffff;
        self.vmcb.state_save_area.es_attrib = 0x93;
        self.vmcb.state_save_area.fs_selector = 0;
        self.vmcb.state_save_area.fs_base = 0;
        self.vmcb.state_save_area.fs_limit = 0xffff;
        self.vmcb.state_save_area.fs_attrib = 0x93;
        self.vmcb.state_save_area.gs_selector = 0;
        self.vmcb.state_save_area.gs_base = 0;
        self.vmcb.state_save_area.gs_limit = 0xffff;
        self.vmcb.state_save_area.gs_attrib = 0x93;
        self.vmcb.state_save_area.ss_selector = 0;
        self.vmcb.state_save_area.ss_base = 0;
        self.vmcb.state_save_area.ss_limit = 0xffff;
        self.vmcb.state_save_area.ss_attrib = 0x93;
        self.vmcb.state_save_area.gdtr_base = 0;
        self.vmcb.state_save_area.gdtr_limit = 0xffff;
        self.vmcb.state_save_area.idtr_base = 0;
        self.vmcb.state_save_area.idtr_limit = 0xffff;
        self.vmcb.state_save_area.ldtr_selector = 0;
        self.vmcb.state_save_area.ldtr_base = 0;
        self.vmcb.state_save_area.ldtr_limit = 0xffff;
        self.vmcb.state_save_area.ldtr_attrib = 0x82;
        self.vmcb.state_save_area.tr_selector = 0;
        self.vmcb.state_save_area.tr_base = 0;
        self.vmcb.state_save_area.tr_limit = 0xffff;
        self.vmcb.state_save_area.tr_attrib = 0x8b;
        self.vmcb.state_save_area.cpl = 0;
        self.registers.rax = 0;
        self.registers.rdx = cpuid!(0x1).eax as _;
        self.registers.rbx = 0;
        self.registers.rcx = 0;
        self.registers.rbp = 0;
        self.vmcb.state_save_area.rsp = 0;
        self.registers.rsp = 0;
        self.registers.rdi = 0;
        self.registers.rsi = 0;
        self.registers.r8 = 0;
        self.registers.r9 = 0;
        self.registers.r10 = 0;
        self.registers.r11 = 0;
        self.registers.r12 = 0;
        self.registers.r13 = 0;
        self.registers.r14 = 0;
        self.registers.r15 = 0;
        unsafe {
            x86::debugregs::dr0_write(0);
            x86::debugregs::dr1_write(0);
            x86::debugregs::dr2_write(0);
            x86::debugregs::dr3_write(0);
        };
        self.vmcb.state_save_area.dr6 = 0xffff0ff0;
        self.vmcb.state_save_area.dr7 = 0x400;

        self.vmcb.control_area.tlb_control = TlbControl::FlushAll as _;
        self.vmcb.control_area.vmcb_clean = 0;
    }

    fn wait_for_sipi(&self) -> u8 {
        assert!(self.id != 0);

        while self.activity_state.load(Ordering::Relaxed) == GuestActivityState::WaitForSipi as u8 {
            core::hint::spin_loop();
        }

        self.activity_state
            .swap(GuestActivityState::Active as u8, Ordering::Relaxed)
    }

    fn handle_sipi(&mut self, vector: u8) {
        assert!(self.id != 0);
        assert!(self.activity_state.load(Ordering::Relaxed) == GuestActivityState::Active as u8);
        log::debug!("SIPI vector {vector:#x?}");

        self.vmcb.state_save_area.cs_selector = (vector as u16) << 8;
        self.vmcb.state_save_area.cs_base = (vector as u64) << 12;
        self.vmcb.state_save_area.rip = 0;
        self.registers.rip = 0;
    }

    fn intercept_apic_write(&mut self, enable: bool) {
        let apic_base_raw = rdmsr(x86::msr::IA32_APIC_BASE);
        let apic_base = apic_base_raw & !0xfff;
        let pt_index = apic_base.get_bits(12..=20) as usize;

        let mut npt = SHARED_GUEST_DATA.npt.write();
        let pt = npt.apic_pt();
        pt.0.entries[pt_index].set_writable(!enable);

        self.vmcb.control_area.tlb_control = TlbControl::FlushAll as _;
    }

    fn handle_nested_page_fault(&mut self) {
        let faulting_gpa = self.vmcb.control_area.exit_info2;

        let apic_base = rdmsr(x86::msr::IA32_APIC_BASE) & !0xfff;
        if (faulting_gpa & !0xfff) == apic_base {
            self.handle_apic_npf();
            return;
        }

        unsafe {
            asm!("out 0x80, al", in("al") faulting_gpa as u8, options(nomem, nostack));
            x86::irq::disable();
        }
        loop {
            unsafe { x86::halt() }
        }
    }

    fn handle_debug_exception(&mut self) {
        const EVENTINJ_VALID: u64 = 1 << 31;
        const EVENTINJ_TYPE_EXCEPTION: u64 = 3 << 8;
        const EVENTINJ_VECTOR_DB: u64 = 1;
        self.vmcb.control_area.event_inj =
            EVENTINJ_VALID | EVENTINJ_TYPE_EXCEPTION | EVENTINJ_VECTOR_DB;
    }

    fn handle_vmmcall(&mut self) {
        let nrip = self.vmcb.control_area.nrip;
        if nrip != 0 && nrip > self.registers.rip {
            self.registers.rip = nrip;
        } else {
            self.registers.rip = self.registers.rip.wrapping_add(3);
        }
    }

    fn handle_apic_npf(&mut self) {
        if self.id == apic_id::PROCESSOR_COUNT.load(Ordering::Relaxed) - 1 {
            log::debug!("Stopping APIC write interception");
            self.intercept_apic_write(false);

            return;
        }

        let instructions = unsafe {
            core::slice::from_raw_parts(
                self.vmcb.control_area.guest_instruction_bytes.as_ptr(),
                self.vmcb.control_area.num_of_bytes_fetched as _,
            )
        };

        let (value, instr_len) = if instructions
            .starts_with(&[0xc7, 0x80, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        {
            (0u32, 10u64)
        } else {
            match instructions {
                [0x45, 0x89, 0x65, 0x00, ..] => (self.registers.r12 as _, 4),
                [0x41, 0x89, 0x14, 0x00, ..] => (self.registers.rdx as _, 4),
                [
                    0xc7,
                    0x81,
                    0xb0,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    ..,
                ] => (0, 10),
                [0xa3, 0x00, 0x03, 0xe0, 0xfe, 0x00, 0x00, 0x00, 0x00, ..] => {
                    (self.registers.rax as _, 9)
                }
                [0xa3, 0x10, 0x03, 0xe0, 0xfe, 0x00, 0x00, 0x00, 0x00, ..] => {
                    (self.registers.rax as _, 9)
                }
                [0x89, 0x90, 0x00, 0x03, 0x00, 0x00, ..] => (self.registers.rdx as _, 6),
                [0x89, 0x88, 0x10, 0x03, 0x00, 0x00, ..] => (self.registers.rcx as _, 6),
                _ => {
                    unsafe {
                        asm!("out 0x80, al", in("al") 0xF1u8, options(nomem, nostack));
                        x86::irq::disable();
                    }
                    loop {
                        unsafe { x86::halt() }
                    }
                }
            }
        };

        self.registers.rip += instr_len;

        let message_type = value.get_bits(8..=10);
        let faulting_gpa = self.vmcb.control_area.exit_info2;
        let apic_register = faulting_gpa & 0xfff;
        if apic_register != 0xb0 && self.id == 0 {
            log::trace!("APIC reg:{apic_register:#x} <= {value:#x}");
        }

        if message_type != 0b110 || apic_register != 0x300 {
            let apic_reg = faulting_gpa as *mut u32;
            unsafe { apic_reg.write_volatile(value) };
            return;
        }

        assert!(!value.get_bit(11), "Destination Mode must be 'Physical'");
        assert!(
            value.get_bits(18..=19) == 0b00,
            "Destination Shorthand must be 'Destination'"
        );

        let icr_high_addr = (faulting_gpa & !0xfff) | 0x310;
        let icr_high_value = unsafe { *(icr_high_addr as *mut u32) };

        let vector = value.get_bits(0..=7) as u8;
        let apic_id = icr_high_value.get_bits(24..=31) as u8;
        let processor_id = apic_id::processor_id_from(apic_id).unwrap();
        log::debug!("SIPI to {apic_id} with vector {vector:#x?}");
        assert!(vector != GuestActivityState::WaitForSipi as u8);

        let activity_state = &SHARED_GUEST_DATA.activity_states[processor_id];
        let _ = activity_state.compare_exchange(
            GuestActivityState::WaitForSipi as u8,
            vector,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    fn handle_cpuid(&mut self) {
        let leaf = self.registers.rax as u32;
        let sub_leaf = self.registers.rcx as u32;

        if leaf == HV_CPUID_VENDOR_AND_MAX_FUNCTIONS {
            self.registers.rax = HV_CPUID_INTERFACE as u64;
            self.registers.rbx = OUR_HV_VENDOR_NAME_EBX as u64;
            self.registers.rcx = OUR_HV_VENDOR_NAME_ECX as u64;
            self.registers.rdx = OUR_HV_VENDOR_NAME_EDX as u64;
        } else if leaf == HV_CPUID_INTERFACE {
            self.registers.rax = 0;
            self.registers.rbx = 0;
            self.registers.rcx = 0;
            self.registers.rdx = 0;
        } else {
            let result = cpuid!(leaf, sub_leaf);
            let mut ecx = result.ecx;

            if leaf == 1 {
                ecx.set_bit(31, true);
            }

            self.registers.rax = result.eax as u64;
            self.registers.rbx = result.ebx as u64;
            self.registers.rcx = ecx as u64;
            self.registers.rdx = result.edx as u64;
        }

        self.registers.rip = self.vmcb.control_area.nrip;
    }

    fn initialize_control(&mut self) {
        const SVM_INTERCEPT_MISC1_INTR: u32 = 1 << 0;
        const SVM_INTERCEPT_MISC1_NMI: u32 = 1 << 1;
        const SVM_INTERCEPT_MISC1_INIT: u32 = 1 << 3;
        const SVM_INTERCEPT_MISC1_CPUID: u32 = 1 << 18;
        const SVM_INTERCEPT_MISC1_PAUSE: u32 = 1 << 23;
        const SVM_INTERCEPT_MISC1_HLT: u32 = 1 << 24;
        const SVM_INTERCEPT_MISC1_MSR_PROT: u32 = 1 << 28;
        const SVM_INTERCEPT_MISC1_SHUTDOWN: u32 = 1 << 31;
        const SVM_INTERCEPT_MISC2_VMRUN: u32 = 1 << 0;
        const SVM_INTERCEPT_MISC2_VMMCALL: u32 = 1 << 1;
        const SVM_INTERCEPT_MISC2_MWAIT_UNCOND: u32 = 1 << 11;
        const SVM_INTERCEPT_MISC2_MWAIT_COND: u32 = 1 << 12;
        const SVM_NP_ENABLE_NP_ENABLE: u64 = 1 << 0;

        use crate::hypervisor::LADDER_STEP;
        let mut misc1 = 0u32;
        let misc2 = SVM_INTERCEPT_MISC2_VMRUN
            | SVM_INTERCEPT_MISC2_VMMCALL
            | SVM_INTERCEPT_MISC2_MWAIT_UNCOND
            | SVM_INTERCEPT_MISC2_MWAIT_COND;

        misc1 |= SVM_INTERCEPT_MISC1_HLT;

        misc1 |= SVM_INTERCEPT_MISC1_PAUSE;

        misc1 |= SVM_INTERCEPT_MISC1_CPUID | SVM_INTERCEPT_MISC1_SHUTDOWN;

        misc1 |= SVM_INTERCEPT_MISC1_INIT;

        if LADDER_STEP >= 4 {
            misc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
        }
        self.vmcb.control_area.intercept_misc1 = misc1;
        self.vmcb.control_area.intercept_misc2 = misc2;

        self.vmcb.control_area.pause_filter_count = PAUSE_FILTER_RELOAD;

        let shared = &*SHARED_GUEST_DATA;
        self.vmcb.control_area.iopm_base_pa =
            platform_ops::get().pa(addr_of!(*shared.iopm.as_ref()) as *const _ as _);
        self.vmcb.control_area.msrpm_base_pa =
            platform_ops::get().pa(addr_of!(*shared.msrpm.as_ref()) as *const _ as _);

        self.vmcb.control_area.guest_asid = 1;
        self.vmcb.control_area.tlb_control = TlbControl::FlushAll as _;

        self.vmcb.control_area.vintr = 1u64 << 24;

        if LADDER_STEP >= 2 {
            self.vmcb.control_area.np_enable = SVM_NP_ENABLE_NP_ENABLE;
            let mut npt = SHARED_GUEST_DATA.npt.write();

            if self.id == 0 {
                npt.split_apic_page();
            }

            let pml4_va = addr_of!(npt.pml4) as *const _ as *const core::ffi::c_void;
            self.vmcb.control_area.ncr3 = platform_ops::get().pa(pml4_va);
            drop(npt);

            if self.id == 0 {
                self.intercept_apic_write(true);
            }
        } else {
            self.vmcb.control_area.np_enable = 0;
        }

        self.vmcb.control_area.intercept_exception = 0;

        if self.id == 0 {
            use crate::hypervisor::{
                VMCB_INTERCEPT_EXCEPTION, VMCB_INTERCEPT_MISC1, VMCB_INTERCEPT_MISC2,
                VMCB_NP_ENABLE, VMCB_PA,
            };
            VMCB_INTERCEPT_MISC1.store(
                self.vmcb.control_area.intercept_misc1 as u64,
                Ordering::Release,
            );
            VMCB_INTERCEPT_MISC2.store(
                self.vmcb.control_area.intercept_misc2 as u64,
                Ordering::Release,
            );
            VMCB_INTERCEPT_EXCEPTION.store(
                self.vmcb.control_area.intercept_exception as u64,
                Ordering::Release,
            );
            VMCB_NP_ENABLE.store(self.vmcb.control_area.np_enable as u64, Ordering::Release);
            VMCB_PA.store(self.vmcb_pa, Ordering::Release);
        }
    }

    fn initialize_guest(&mut self) {
        const EFER_SVME: u64 = 1 << 12;

        const EFER_NXE: u64 = 1 << 11;

        let idtr = sidt();
        let gdtr = sgdt();
        let guest_gdt = gdtr.base as u64;

        self.vmcb.state_save_area.es_selector = es().bits();
        self.vmcb.state_save_area.cs_selector = cs().bits();
        self.vmcb.state_save_area.ss_selector = ss().bits();
        self.vmcb.state_save_area.ds_selector = ds().bits();
        self.vmcb.state_save_area.es_attrib = get_segment_access_right(guest_gdt, es().bits());
        self.vmcb.state_save_area.cs_attrib = get_segment_access_right(guest_gdt, cs().bits());
        self.vmcb.state_save_area.ss_attrib = get_segment_access_right(guest_gdt, ss().bits());
        self.vmcb.state_save_area.ds_attrib = get_segment_access_right(guest_gdt, ds().bits());
        self.vmcb.state_save_area.es_limit = get_segment_limit(guest_gdt, es().bits());
        self.vmcb.state_save_area.cs_limit = get_segment_limit(guest_gdt, cs().bits());
        self.vmcb.state_save_area.ss_limit = get_segment_limit(guest_gdt, ss().bits());
        self.vmcb.state_save_area.ds_limit = get_segment_limit(guest_gdt, ds().bits());
        self.vmcb.state_save_area.es_base = get_segment_base(guest_gdt, es().bits());
        self.vmcb.state_save_area.cs_base = get_segment_base(guest_gdt, cs().bits());
        self.vmcb.state_save_area.ss_base = get_segment_base(guest_gdt, ss().bits());
        self.vmcb.state_save_area.ds_base = get_segment_base(guest_gdt, ds().bits());
        self.vmcb.state_save_area.gdtr_base = gdtr.base as _;
        self.vmcb.state_save_area.gdtr_limit = u32::from(gdtr.limit);
        self.vmcb.state_save_area.idtr_base = idtr.base as _;
        self.vmcb.state_save_area.idtr_limit = u32::from(idtr.limit);
        self.vmcb.state_save_area.efer = rdmsr(x86::msr::IA32_EFER) | EFER_SVME | EFER_NXE;
        self.vmcb.state_save_area.cr0 = cr0().bits() as _;
        self.vmcb.state_save_area.cr3 = cr3();
        self.vmcb.state_save_area.cr4 = cr4().bits() as _;
        self.vmcb.state_save_area.rip = self.registers.rip;
        self.vmcb.state_save_area.rsp = self.registers.rsp;

        self.vmcb.state_save_area.rflags = self.registers.rflags | 0x200;
        self.vmcb.state_save_area.rax = self.registers.rax;
        self.vmcb.state_save_area.gpat = rdmsr(x86::msr::IA32_PAT);

        self.vmcb.state_save_area.cpl = ((self.vmcb.state_save_area.cs_attrib >> 5) & 3) as u8;

        vmsave(self.vmcb_pa);

        let tr_attrib = self.vmcb.state_save_area.tr_attrib;
        let tr_type = tr_attrib & 0xF;
        if tr_type == 0x9 {
            self.vmcb.state_save_area.tr_attrib = (tr_attrib & !0xF) | 0xB;
        } else if tr_type == 0x1 {
            self.vmcb.state_save_area.tr_attrib = (tr_attrib & !0xF) | 0x3;
        }

        self.vmcb.state_save_area.dr6 = 0xFFFF_0FF0;
        self.vmcb.state_save_area.dr7 = 0x0000_0400;
    }

    fn validate_vmcb(&self) {
        let efer = self.vmcb.state_save_area.efer;
        let cr0 = self.vmcb.state_save_area.cr0;
        let cr4 = self.vmcb.state_save_area.cr4;
        let cs_attrib = self.vmcb.state_save_area.cs_attrib;

        assert!(efer & (1 << 12) != 0, "VMCB: EFER.SVME must be 1");

        let cr0_cd = (cr0 >> 30) & 1;
        let cr0_nw = (cr0 >> 29) & 1;
        assert!(
            !(cr0_cd == 0 && cr0_nw == 1),
            "VMCB: CR0.CD=0 with CR0.NW=1 is illegal"
        );

        let lme = (efer >> 8) & 1;
        let pg = (cr0 >> 31) & 1;
        let pae = (cr4 >> 5) & 1;
        let pe = cr0 & 1;

        if lme == 1 && pg == 1 {
            assert!(pe == 1, "VMCB: long mode requires CR0.PE=1");
            assert!(pae == 1, "VMCB: long mode requires CR4.PAE=1");

            let cs_l = (cs_attrib >> 9) & 1;
            let cs_d = (cs_attrib >> 10) & 1;
            assert!(
                !(cs_l == 1 && cs_d == 1),
                "VMCB: CS.L=1 and CS.D=1 is illegal in long mode \
                 (cs_attrib={cs_attrib:#06x})"
            );
        }

        assert!(
            self.vmcb_pa & 0xfff == 0,
            "VMCB PA must be 4KB-aligned, got {:#x}",
            self.vmcb_pa
        );

        let tr_attrib = self.vmcb.state_save_area.tr_attrib;
        let tr_type = tr_attrib & 0xF;
        let tr_present = (tr_attrib >> 7) & 1;
        assert!(
            tr_present == 1,
            "VMCB: TR must be present (tr_attrib={tr_attrib:#06x})"
        );
        assert!(
            tr_type == 0x3 || tr_type == 0xB,
            "VMCB: TR.type must be 0x3 or 0xB for busy TSS, got {tr_type:#x} (tr_attrib={tr_attrib:#06x})"
        );

        let ncr3 = self.vmcb.control_area.ncr3;
        assert!(
            ncr3 & 0xFFF == 0,
            "VMCB: ncr3 must be page-aligned, got {ncr3:#x}"
        );

        let iopm = self.vmcb.control_area.iopm_base_pa;
        let msrpm = self.vmcb.control_area.msrpm_base_pa;
        assert!(iopm != 0, "VMCB: iopm_base_pa must not be zero");
        assert!(msrpm != 0, "VMCB: msrpm_base_pa must not be zero");
        assert!(
            iopm & 0xFFF == 0,
            "VMCB: iopm_base_pa must be page-aligned, got {iopm:#x}"
        );
        assert!(
            msrpm & 0xFFF == 0,
            "VMCB: msrpm_base_pa must be page-aligned, got {msrpm:#x}"
        );

        log::info!(
            "VMCB validated: EFER={efer:#x} CR0={cr0:#x} CR4={cr4:#x} \
             CS.attrib={cs_attrib:#06x} TR.attrib={:#06x} ncr3={:#x} \
             CPL={} DR6={:#x} DR7={:#x} VMCB_PA={:#x} \
             IOPM={:#x} MSRPM={:#x}",
            self.vmcb.state_save_area.tr_attrib,
            self.vmcb.control_area.ncr3,
            self.vmcb.state_save_area.cpl,
            self.vmcb.state_save_area.dr6,
            self.vmcb.state_save_area.dr7,
            self.vmcb_pa,
            iopm,
            msrpm,
        );
    }

    fn initialize_host(&mut self) {
        let shared_host = SHARED_HOST_DATA.get().unwrap();

        if let Some(host_gdt_and_tss) = &shared_host.gdts {
            host_gdt_and_tss[self.id].apply().unwrap();
        }

        if let Some(host_idt) = &shared_host.idt {
            lidt(&host_idt.idtr());
        }

        vmsave(self.host_vmcb_pa);

        let tr_attrib = self.host_vmcb.state_save_area.tr_attrib;
        let tr_type = tr_attrib & 0xF;
        if tr_type == 0x9 {
            self.host_vmcb.state_save_area.tr_attrib = (tr_attrib & !0xF) | 0xB;
        } else if tr_type == 0x1 {
            self.host_vmcb.state_save_area.tr_attrib = (tr_attrib & !0xF) | 0x3;
        }
    }
}

#[expect(dead_code)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum TlbControl {
    DoNotFlush = 0x0,
    FlushAll = 0x1,
    FlushGuests = 0x3,
    FlushGuestsNonGlobal = 0x7,
}

#[derive(Debug, derive_deref::Deref, derive_deref::DerefMut)]
struct Vmcb {
    ptr: Box<VmcbRaw>,
}

impl Default for Vmcb {
    fn default() -> Self {
        Self {
            ptr: zeroed_box::<VmcbRaw>(),
        }
    }
}

#[derive(Debug)]
#[repr(C, align(4096))]
struct VmcbRaw {
    control_area: ControlArea,
    state_save_area: StateSaveArea,
}
const _: () = assert!(core::mem::size_of::<VmcbRaw>() == 0x1000);

#[derive(Debug)]
#[repr(C)]
struct ControlArea {
    intercept_cr_read: u16,
    intercept_cr_write: u16,
    intercept_dr_read: u16,
    intercept_dr_write: u16,
    intercept_exception: u32,
    intercept_misc1: u32,
    intercept_misc2: u32,
    intercept_misc3: u32,
    #[debug(skip)]
    _padding1: [u8; 0x03c - 0x018],
    pause_filter_threshold: u16,
    pause_filter_count: u16,
    iopm_base_pa: u64,
    msrpm_base_pa: u64,
    tsc_offset: u64,
    guest_asid: u32,
    tlb_control: u32,
    vintr: u64,
    interrupt_shadow: u64,
    exit_code: u64,
    exit_info1: u64,
    exit_info2: u64,
    exit_int_info: u64,
    np_enable: u64,
    avic_apic_bar: u64,
    guest_pa_pf_ghcb: u64,
    event_inj: u64,
    ncr3: u64,
    lbr_virtualization_enable: u64,
    vmcb_clean: u32,
    _reserved: u32,
    nrip: u64,
    num_of_bytes_fetched: u8,
    guest_instruction_bytes: [u8; 15],
    avic_apic_backing_page_pointer: u64,
    #[debug(skip)]
    _padding2: u64,
    avic_logical_table_pointer: u64,
    avic_physical_table_pointer: u64,
    #[debug(skip)]
    _padding3: u64,
    vmcb_save_state_pointer: u64,
    #[debug(skip)]
    _padding4: [u8; 0x3e0 - 0x110],
    reserved_for_host: [u8; 0x20],
}
const _: () = assert!(core::mem::size_of::<ControlArea>() == 0x400);

#[derive(Debug)]
#[repr(C)]
struct StateSaveArea {
    es_selector: u16,
    es_attrib: u16,
    es_limit: u32,
    es_base: u64,
    cs_selector: u16,
    cs_attrib: u16,
    cs_limit: u32,
    cs_base: u64,
    ss_selector: u16,
    ss_attrib: u16,
    ss_limit: u32,
    ss_base: u64,
    ds_selector: u16,
    ds_attrib: u16,
    ds_limit: u32,
    ds_base: u64,
    fs_selector: u16,
    fs_attrib: u16,
    fs_limit: u32,
    fs_base: u64,
    gs_selector: u16,
    gs_attrib: u16,
    gs_limit: u32,
    gs_base: u64,
    gdtr_selector: u16,
    gdtr_attrib: u16,
    gdtr_limit: u32,
    gdtr_base: u64,
    ldtr_selector: u16,
    ldtr_attrib: u16,
    ldtr_limit: u32,
    ldtr_base: u64,
    idtr_selector: u16,
    idtr_attrib: u16,
    idtr_limit: u32,
    idtr_base: u64,
    tr_selector: u16,
    tr_attrib: u16,
    tr_limit: u32,
    tr_base: u64,
    #[debug(skip)]
    _padding1: [u8; 0x0cb - 0x0a0],
    cpl: u8,
    #[debug(skip)]
    _padding2: u32,
    efer: u64,
    #[debug(skip)]
    _padding3: [u8; 0x148 - 0x0d8],
    cr4: u64,
    cr3: u64,
    cr0: u64,
    dr7: u64,
    dr6: u64,
    rflags: u64,
    rip: u64,
    #[debug(skip)]
    _padding4: [u8; 0x1d8 - 0x180],
    rsp: u64,
    s_cet: u64,
    ssp: u64,
    isst_addr: u64,
    rax: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    sf_mask: u64,
    kernel_gs_base: u64,
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
    cr2: u64,
    #[debug(skip)]
    _padding5: [u8; 0x268 - 0x248],
    gpat: u64,
    dbg_ctl: u64,
    br_from: u64,
    br_to: u64,
    last_excep_from: u64,
    last_excep_to: u64,
    #[debug(skip)]
    _padding6: [u8; 0x2df - 0x298],
    spec_ctl: u64,
}
const _: () = assert!(core::mem::size_of::<StateSaveArea>() == 0x2e8);

#[derive(derive_deref::Deref, derive_deref::DerefMut)]
struct HostStateArea {
    ptr: Box<HostStateAreaRaw>,
}

impl Default for HostStateArea {
    fn default() -> Self {
        Self {
            ptr: zeroed_box::<HostStateAreaRaw>(),
        }
    }
}

#[repr(C, align(4096))]
struct HostStateAreaRaw([u8; 0x1000]);
const _: () = assert!(core::mem::size_of::<HostStateAreaRaw>() == 0x1000);

impl Default for HostStateAreaRaw {
    fn default() -> Self {
        Self([0; 4096])
    }
}

unsafe extern "C" {

    unsafe fn run_svm_guest(registers: &mut Registers, vmcb_pa: u64, host_vmcb_pa: u64);
}
global_asm!(include_str!("../capture_registers.inc"));
global_asm!(include_str!("run_guest.S"));

unsafe fn serial_out_byte(b: u8) {
    asm!("out dx, al", in("dx") 0x3F8u16, in("al") b, options(nomem, nostack));
}

unsafe fn serial_out_str(s: &[u8]) {
    for &b in s {
        serial_out_byte(b);
    }
}

unsafe fn serial_out_hex(v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    serial_out_str(b"0x");
    for i in (0..16).rev() {
        serial_out_byte(HEX[((v >> (i * 4)) & 0xF) as usize]);
    }
}

fn vmsave(vmcb_pa: u64) {
    unsafe {
        asm!(
            "vmsave rax",
            in("rax") vmcb_pa, options(nostack, preserves_flags),
        )
    };
}

fn get_segment_base(table_base: u64, selector: u16) -> u64 {
    let sel = x86::segmentation::SegmentSelector::from_raw(selector);
    if sel.index() == 0 && (sel.bits() >> 2) == 0 {
        return 0;
    }
    let descriptor_value = get_segment_descriptor_value(table_base, selector);

    let base_low = (descriptor_value >> 16) & 0xffff;
    let base_mid = (descriptor_value >> 32) & 0xff;
    let base_high = (descriptor_value >> 56) & 0xff;
    base_low | (base_mid << 16) | (base_high << 24)
}

fn get_segment_access_right(table_base: u64, selector: u16) -> u16 {
    let descriptor_value = get_segment_descriptor_value(table_base, selector);

    let ar = (descriptor_value >> 40) as u16;
    let upper_ar = (ar >> 4) & 0b1111_0000_0000;
    let lower_ar = ar & 0b1111_1111;
    lower_ar | upper_ar
}

fn get_segment_descriptor_value(table_base: u64, selector: u16) -> u64 {
    let sel = x86::segmentation::SegmentSelector::from_raw(selector);
    let descriptor_addr = table_base + u64::from(sel.index() * 8);
    let ptr = descriptor_addr as *const u64;
    unsafe { *ptr }
}

fn get_segment_limit(table_base: u64, selector: u16) -> u32 {
    let sel = x86::segmentation::SegmentSelector::from_raw(selector);
    if sel.index() == 0 && (sel.bits() >> 2) == 0 {
        return 0;
    }
    let descriptor_value = get_segment_descriptor_value(table_base, selector);
    let limit_low = descriptor_value & 0xffff;
    let limit_high = (descriptor_value >> (32 + 16)) & 0xF;
    let mut limit = limit_low | (limit_high << 16);
    if ((descriptor_value >> (32 + 23)) & 0x01) != 0 {
        limit = ((limit + 1) << BASE_PAGE_SHIFT) - 1;
    }
    limit as u32
}

#[repr(C, align(4096))]
struct Iopm([u8; 3 * 4096]);

#[repr(C, align(4096))]
struct Msrpm([u8; 2 * 4096]);

struct SharedGuestData {
    npt: RwLock<NestedPageTables>,
    activity_states: [AtomicU8; 0xff],
    iopm: Box<Iopm>,
    msrpm: Box<Msrpm>,
}

impl SharedGuestData {
    fn new() -> Self {
        let mut npt = NestedPageTables::new();
        npt.build_identity();

        let mut msrpm = zeroed_box::<Msrpm>();

        msrpm.0[2080] |= 0b11;

        Self {
            npt: RwLock::new(npt),
            activity_states: core::array::from_fn(|_| {
                AtomicU8::new(GuestActivityState::Active as u8)
            }),
            iopm: zeroed_box::<Iopm>(),
            msrpm,
        }
    }
}

static SHARED_GUEST_DATA: Lazy<SharedGuestData> = Lazy::new(SharedGuestData::new);

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum GuestActivityState {
    Active = 0,
    WaitForSipi = u8::MAX,
}
