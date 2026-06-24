use alloc::boxed::Box;
use derive_more::Debug;

use crate::hypervisor::{
    host::Extension,
    intel::guest::{get_adjusted_cr0, get_adjusted_cr4},
    platform_ops,
    support::zeroed_box,
    x86_instructions::{cr0, cr0_write, cr4, cr4_write, rdmsr, wrmsr},
};

#[derive(Default)]
pub(crate) struct Vmx {
    vmxon_region: Vmxon,
}

impl Extension for Vmx {
    fn enable(&mut self) {

        cr0_write(get_adjusted_cr0(cr0()));
        cr4_write(get_adjusted_cr4(cr4()));
        Self::update_feature_control_msr();

        vmxon(&mut self.vmxon_region);
    }
}

impl Vmx {

    fn update_feature_control_msr() {
        const IA32_FEATURE_CONTROL_LOCK_BIT_FLAG: u64 = 1 << 0;
        const IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_FLAG: u64 = 1 << 2;

        let feature_control = rdmsr(x86::msr::IA32_FEATURE_CONTROL);
        if (feature_control & IA32_FEATURE_CONTROL_LOCK_BIT_FLAG) == 0 {
            wrmsr(
                x86::msr::IA32_FEATURE_CONTROL,
                feature_control
                    | IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_FLAG
                    | IA32_FEATURE_CONTROL_LOCK_BIT_FLAG,
            );
        }
    }
}

#[derive(derive_deref::Deref, derive_deref::DerefMut)]
struct Vmxon {
    ptr: Box<VmxonRaw>,
}

impl Default for Vmxon {
    fn default() -> Self {

        let mut vmxon = zeroed_box::<VmxonRaw>();

        vmxon.revision_id = rdmsr(x86::msr::IA32_VMX_BASIC) as _;

        Self { ptr: vmxon }
    }
}

#[derive(Debug)]
#[repr(C, align(4096))]
struct VmxonRaw {
    revision_id: u32,
    #[debug(skip)]
    data: [u8; 4092],
}

fn vmxon(vmxon_region: &mut VmxonRaw) {
    let va = vmxon_region as *const _;
    let pa = platform_ops::get().pa(va as *const _);
    unsafe { x86::bits64::vmx::vmxon(pa).unwrap() };
}
