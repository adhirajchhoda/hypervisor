use crate::hypervisor::{
    host::Extension,
    x86_instructions::{rdmsr, wrmsr},
};

#[derive(Default)]
pub(crate) struct Svm;

impl Extension for Svm {
    fn enable(&mut self) {
        const EFER_SVME: u64 = 1 << 12;

        wrmsr(x86::msr::IA32_EFER, rdmsr(x86::msr::IA32_EFER) | EFER_SVME);
    }
}
