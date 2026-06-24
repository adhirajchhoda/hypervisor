use bit_field::BitField;
use x86::{
    dtables::DescriptorTablePointer,
    segmentation::{SegmentSelector, SystemDescriptorTypes64},
};

#[derive(thiserror::Error, Debug)]
pub(crate) enum SegmentError {
    #[error("`{selector}` points to the null descriptor")]
    NullDescriptor { selector: SegmentSelector },

    #[error("`{selector}` points to LDT where parsing is unimplemented")]
    LdtAccess { selector: SegmentSelector },

    #[error("`{index}` points to outside GDT")]
    OutOfGdtAccess { index: usize },

    #[error("`{index}` points to `{entry}`, which is invalid as a descriptor")]
    InvalidGdtEntry { index: usize, entry: u64 },
}

pub(crate) struct SegmentDescriptor {
    low64: SegmentDescriptorRaw,
    upper_base: Option<u32>,
}

impl SegmentDescriptor {
    pub(crate) fn try_from_gdtr(
        gdtr: &DescriptorTablePointer<u64>,
        selector: SegmentSelector,
    ) -> Result<Self, SegmentError> {
        if selector.contains(SegmentSelector::TI_LDT) {
            return Err(SegmentError::LdtAccess { selector });
        }

        let index = selector.index() as usize;
        if index == 0 {
            return Err(SegmentError::NullDescriptor { selector });
        }

        let gdt = unsafe {
            core::slice::from_raw_parts(gdtr.base.cast::<u64>(), usize::from(gdtr.limit + 1) / 8)
        };

        let raw = gdt
            .get(index)
            .ok_or(SegmentError::OutOfGdtAccess { index })?;

        let low64 = SegmentDescriptorRaw::from(*raw);
        let upper_base = if low64.is_16byte() {
            let index: usize = index + 1;

            let raw = gdt
                .get(index)
                .ok_or(SegmentError::OutOfGdtAccess { index })?;

            let Ok(upper_base) = u32::try_from(*raw) else {
                return Err(SegmentError::InvalidGdtEntry { index, entry: *raw });
            };

            Some(upper_base)
        } else {
            None
        };
        Ok(Self { low64, upper_base })
    }

    pub(crate) fn base(&self) -> u64 {
        if let Some(upper_base) = self.upper_base {
            self.low64.base() as u64 | (u64::from(upper_base) << 32)
        } else {
            self.low64.base() as _
        }
    }
}

struct SegmentDescriptorRaw {
    raw: u64,
}

impl SegmentDescriptorRaw {

    fn is_16byte(&self) -> bool {
        let high32 = self.raw.get_bits(32..);
        let system = high32.get_bit(12);
        let type_ = high32.get_bits(8..=11) as u8;
        !system
            && (type_ == SystemDescriptorTypes64::TssAvailable as u8
                || type_ == SystemDescriptorTypes64::TssBusy as u8)
    }

    fn base(&self) -> u32 {
        let low32 = self.raw.get_bits(..=31);
        let high32 = self.raw.get_bits(32..);

        let base_high = high32.get_bits(24..=31) << 24;
        let base_middle = high32.get_bits(0..=7) << 16;
        let base_low = low32.get_bits(16..=31);
        u32::try_from(base_high | base_middle | base_low).unwrap()
    }
}

impl From<u64> for SegmentDescriptorRaw {
    fn from(raw: u64) -> Self {
        Self { raw }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ctor::ctor]
    fn init() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Warn)
            .init();
    }

    #[test]
    fn base() {
        log::trace!("Example use of the logger in test...");

        let gdt = [
            0x0000000000000000u64,
            0x0000000000000000,
            0x00209b0000000000,
            0x0040930000000000,
            0x00cffb000000ffff,
            0x00cff3000000ffff,
            0x0020fb0000000000,
            0x0000000000000000,
            0x71008be7b0000067,
            0x00000000fffff805,
            0x0040f30000003c00,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ];

        let cs = SegmentSelector::from_raw(0x10);
        let ss = SegmentSelector::from_raw(0x18);
        let ds = SegmentSelector::from_raw(0x2b);
        let tr = SegmentSelector::from_raw(0x40);
        let fs = SegmentSelector::from_raw(0x53);

        let gdtr = DescriptorTablePointer::<u64>::new_from_slice(&gdt);

        assert_eq!(
            SegmentDescriptor::try_from_gdtr(&gdtr, cs).unwrap().base(),
            0
        );
        assert_eq!(
            SegmentDescriptor::try_from_gdtr(&gdtr, ss).unwrap().base(),
            0
        );
        assert_eq!(
            SegmentDescriptor::try_from_gdtr(&gdtr, ds).unwrap().base(),
            0
        );
        assert_eq!(
            SegmentDescriptor::try_from_gdtr(&gdtr, tr).unwrap().base(),
            0xfffff80571e7b000
        );
        assert_eq!(
            SegmentDescriptor::try_from_gdtr(&gdtr, fs).unwrap().base(),
            0
        );
    }
}
