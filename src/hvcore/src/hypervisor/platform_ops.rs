use alloc::{boxed::Box, sync::Arc};
use spin::Once;

pub trait PlatformOps {

    fn run_on_all_processors(&self, callback: fn());

    fn run_on_aps(&self, callback: fn());

    fn pa(&self, va: *const core::ffi::c_void) -> u64;
}

pub fn init(ops: Box<dyn PlatformOps>) {
    #[allow(clippy::arc_with_non_send_sync)]
    let ops = Arc::new(ops);
    PLATFORM_OPS.call_once(|| Ops { ops });
}

pub fn get() -> Arc<Box<dyn PlatformOps>> {
    PLATFORM_OPS.get().unwrap().ops.clone()
}

struct Ops {
    ops: Arc<Box<dyn PlatformOps>>,
}
unsafe impl Send for Ops {}
unsafe impl Sync for Ops {}

static PLATFORM_OPS: Once<Ops> = Once::new();
