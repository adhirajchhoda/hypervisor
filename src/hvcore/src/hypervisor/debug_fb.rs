use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static FB_BASE: AtomicU64 = AtomicU64::new(0);

static FB_STRIDE: AtomicU64 = AtomicU64::new(0);
static FB_WIDTH: AtomicU64 = AtomicU64::new(0);
static FB_HEIGHT: AtomicU64 = AtomicU64::new(0);

static HEARTBEAT_TICK: AtomicU64 = AtomicU64::new(0);

static CODE_ROW: AtomicUsize = AtomicUsize::new(0);

const HEARTBEAT_X: u64 = 0;
const HEARTBEAT_Y: u64 = 0;
const HEARTBEAT_W: u64 = 128;
const HEARTBEAT_H: u64 = 16;

const CODE_X: u64 = 0;
const CODE_TOP_Y: u64 = 20;
const CODE_BITS: u64 = 16;
const CODE_CELL_W: u64 = 12;
const CODE_CELL_H: u64 = 12;
const CODE_ROWS: usize = 12;

pub fn set_framebuffer(base: u64, stride_px: u64, width: u64, height: u64) {
    FB_STRIDE.store(stride_px, Ordering::Release);
    FB_WIDTH.store(width, Ordering::Release);
    FB_HEIGHT.store(height, Ordering::Release);

    FB_BASE.store(base, Ordering::Release);
}

#[inline]
fn fb_ready() -> Option<(u64, u64)> {
    let base = FB_BASE.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }
    Some((base, FB_STRIDE.load(Ordering::Acquire)))
}

#[inline]
unsafe fn put_pixel(base: u64, stride: u64, x: u64, y: u64, color: u32) {

    let off = (y * stride + x) * 4;
    unsafe { core::ptr::write_volatile((base + off) as *mut u32, color) };
}

unsafe fn fill_rect(base: u64, stride: u64, x0: u64, y0: u64, w: u64, h: u64, color: u32) {
    let width = FB_WIDTH.load(Ordering::Acquire);
    let height = FB_HEIGHT.load(Ordering::Acquire);
    let mut y = y0;
    while y < y0 + h && y < height {
        let mut x = x0;
        while x < x0 + w && x < width {
            unsafe { put_pixel(base, stride, x, y, color) };
            x += 1;
        }
        y += 1;
    }
}

pub fn heartbeat() {
    let Some((base, stride)) = fb_ready() else {
        return;
    };
    let tick = HEARTBEAT_TICK.fetch_add(1, Ordering::Relaxed);

    const PALETTE: [u32; 6] = [
        0x00FF_0000,
        0x0000_FF00,
        0x0000_00FF,
        0x00FF_FF00,
        0x0000_FFFF,
        0x00FF_FFFF,
    ];
    let color = PALETTE[(tick as usize) % PALETTE.len()];
    unsafe {
        fill_rect(
            base,
            stride,
            HEARTBEAT_X,
            HEARTBEAT_Y,
            HEARTBEAT_W,
            HEARTBEAT_H,
            color,
        )
    };
}

pub fn paint_code(code: u64) {
    let Some((base, stride)) = fb_ready() else {
        return;
    };
    let row = CODE_ROW.fetch_add(1, Ordering::Relaxed) % CODE_ROWS;
    let y0 = CODE_TOP_Y + (row as u64) * CODE_CELL_H;

    const ON: u32 = 0x00FF_FFFF;
    const OFF: u32 = 0x0020_2060;

    let mut bit = 0u64;
    while bit < CODE_BITS {

        let shifted = CODE_BITS - 1 - bit;
        let set = (code >> shifted) & 1 == 1;
        let x0 = CODE_X + bit * CODE_CELL_W;
        let color = if set { ON } else { OFF };
        unsafe {
            fill_rect(
                base,
                stride,
                x0,
                y0,
                CODE_CELL_W - 1,
                CODE_CELL_H - 1,
                color,
            )
        };
        bit += 1;
    }
}
