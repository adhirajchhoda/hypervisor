use super::host::Architecture;

mod guest;
mod npts;
mod svm;

pub(crate) struct Amd;

impl Amd {
    pub(crate) fn guest_new(id: usize) -> guest::SvmGuest {
        <guest::SvmGuest as super::host::Guest>::new(id)
    }
}

pub(crate) fn svm_ext_new() -> svm::Svm {
    svm::Svm::default()
}

impl Architecture for Amd {
    type VirtualizationExtension = svm::Svm;
    type Guest = guest::SvmGuest;
}
