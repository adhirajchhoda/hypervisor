use alloc::{boxed::Box, vec::Vec};
use core::arch::asm;
use x86::{
    bits64::task::TaskStateSegment,
    dtables::{DescriptorTablePointer, lgdt},
    segmentation::{
        BuildDescriptor, Descriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentSelector, cs,
    },
    task::{load_tr, tr},
};

use super::segment::SegmentDescriptor;

type Gdtr = DescriptorTablePointer<u64>;

#[derive(Clone, Debug, derive_deref::Deref, derive_deref::DerefMut)]
pub struct GdtTss {
    ptr: Box<GdtTssRaw>,
}

impl GdtTss {
    pub fn new_from_current() -> Self {
        Self {
            ptr: Box::new(GdtTssRaw::new_from_current()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GdtTssRaw {
    pub gdt: Vec<u64>,
    pub cs: SegmentSelector,
    pub tss: Option<TaskStateSegment>,
    pub tr: Option<SegmentSelector>,
}

#[derive(thiserror::Error, Clone, Copy, Debug)]
pub enum GdtTssError {
    #[error("TSS already in use in the current GDT")]
    TssAlreadyInUse,
}

impl GdtTssRaw {
    pub fn new_from_current() -> Self {
        let gdtr = Self::sgdt();

        let gdt =
            unsafe { core::slice::from_raw_parts(gdtr.base, usize::from(gdtr.limit + 1) / 8) }
                .to_vec();

        let tr = unsafe { tr() };
        let tr = if tr.bits() == 0 { None } else { Some(tr) };

        let tss = if let Some(tr) = tr {
            let sg = SegmentDescriptor::try_from_gdtr(&gdtr, tr).unwrap();
            let tss = sg.base() as *mut TaskStateSegment;
            Some(unsafe { *tss })
        } else {
            None
        };

        let cs = cs();
        Self { gdt, cs, tss, tr }
    }

    pub fn append_tss(&mut self, tss: TaskStateSegment) -> &Self {
        if self.tss.is_some() || self.tr.is_some() {
            return self;
        }

        let index = self.gdt.len() as u16;
        self.tr = Some(SegmentSelector::new(index, x86::Ring::Ring0));
        self.tss = Some(tss);

        let tss = self.tss.as_ref().unwrap();
        let tss_base = tss as *const _ as u64;
        self.gdt.push(Self::task_segment_descriptor(tss).as_u64());
        self.gdt.push(tss_base >> 32);

        self
    }

    pub fn rebase_tss(&mut self) {
        let Some(tr) = self.tr else { return };
        let Some(ref tss) = self.tss else { return };
        let base = tss as *const _ as u64;
        let idx = tr.index() as usize;

        let desc_lo = self.gdt[idx];
        let desc_lo = desc_lo & !0xFF00_00FF_FFFF_0000u64;
        let desc_lo = desc_lo
            | ((base & 0xFFFF) << 16)
            | (((base >> 16) & 0xFF) << 32)
            | (((base >> 24) & 0xFF) << 56);
        self.gdt[idx] = desc_lo;
        self.gdt[idx + 1] = base >> 32;
    }

    pub fn apply(&self) -> Result<(), GdtTssError> {
        let gdtr = Gdtr::new_from_slice(&self.gdt);
        unsafe { lgdt(&gdtr) };

        if let Some(tr) = self.tr {
            unsafe {

                let desc_ptr = gdtr.base.add(tr.index() as usize) as *mut u64;
                desc_ptr.write_volatile(desc_ptr.read_volatile() & !(1u64 << 41));
                load_tr(tr);
            }
        }

        Ok(())
    }

    pub fn apply_with_segment_reload(&self) -> Result<(), GdtTssError> {
        self.apply()?;
        unsafe {
            asm!(
                "push {cs_sel}",
                "lea {tmp}, [rip + 2f]",
                "push {tmp}",
                "retfq",
                "2:",
                "xor {tmp:e}, {tmp:e}",
                "mov ss, {tmp:x}",
                "mov ds, {tmp:x}",
                "mov es, {tmp:x}",
                cs_sel = in(reg) u64::from(self.cs.bits()),
                tmp = lateout(reg) _,
            );
        }
        Ok(())
    }

    fn task_segment_descriptor(tss: &TaskStateSegment) -> Descriptor {
        let base = tss as *const _ as _;
        let limit = core::mem::size_of_val(tss) as u64 - 1;
        <DescriptorBuilder as GateDescriptorBuilder<u32>>::tss_descriptor(base, limit, true)
            .present()
            .dpl(x86::Ring::Ring0)
            .finish()
    }

    fn sgdt() -> Gdtr {
        let mut gdtr = Gdtr::default();
        unsafe { x86::dtables::sgdt(&mut gdtr) };
        gdtr
    }
}
