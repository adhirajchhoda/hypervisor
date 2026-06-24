use alloc::boxed::Box;
use bit_field::BitField;
use x86::bits64::paging::BASE_PAGE_SHIFT;

use crate::hypervisor::{
    paging_structures::{Entry, PagingStructuresRaw, Pt, build_identity_internal},
    platform_ops,
    support::zeroed_box,
    x86_instructions::rdmsr,
};

#[derive(Debug, derive_deref::Deref, derive_deref::DerefMut)]
pub(crate) struct NestedPageTables {
    ptr: Box<PagingStructuresRaw>,
}

impl NestedPageTables {
    pub(crate) fn new() -> Self {
        Self {
            ptr: zeroed_box::<PagingStructuresRaw>(),
        }
    }

    pub(crate) fn build_identity(&mut self) {
        build_identity_internal(self.as_mut(), true);
    }

    pub(crate) fn apic_pt(&mut self) -> &mut Pt {
        &mut self.pt_apic
    }

    pub(crate) fn split_apic_page(&mut self) {
        let apic_base_raw = rdmsr(x86::msr::IA32_APIC_BASE);
        assert!(!apic_base_raw.get_bit(10), "x2APIC is enabled");
        assert!(apic_base_raw.get_bit(11), "APIC is disabled");
        let apic_base = apic_base_raw & !0xfff;

        let pdpt_index = apic_base.get_bits(30..=38) as usize;
        let pd_index = apic_base.get_bits(21..=29) as usize;
        let raw = self.ptr.as_mut();
        let pde = &mut raw.pd[pdpt_index].0.entries[pd_index];
        split_2mb(pde, &mut raw.pt_apic);
    }

}

fn split_2mb(pde: &mut Entry, pt: &mut Pt) {
    assert!(pde.present());
    assert!(pde.large());

    let writable = pde.writable();
    let user = pde.user();
    let mut pfn = pde.pfn();
    for pte in &mut pt.0.entries {
        assert!(!pte.present());
        pte.set_present(true);
        pte.set_writable(writable);
        pte.set_user(user);
        pte.set_large(false);
        pte.set_pfn(pfn);
        pfn += 1;
    }

    let pt_pa = platform_ops::get().pa(pt as *mut _ as _);
    pde.set_pfn(pt_pa >> BASE_PAGE_SHIFT);
    pde.set_large(false);
}

