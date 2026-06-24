#![doc = "EFI application shim: loads the hypervisor driver, then chainloads Windows."]
#![no_main]
#![no_std]

mod println;

use core::mem::MaybeUninit;
use uefi::{
    CStr16,
    boot::{self, LoadImageSource},
    prelude::*,
    proto::{
        BootPolicy,
        device_path::{DevicePath, build::DevicePathBuilder},
        loaded_image::LoadedImage,
    },
};

#[entry]
fn main() -> Status {
    println!("boot_shim: starting");

    boot::set_watchdog_timer(0, 0x10000, None).ok();

    println!("boot_shim: loading hypervisor driver...");
    if let Err(msg) = load_and_start(cstr16!("\\EFI\\barevisor\\hv_driver.efi")) {
        println!("boot_shim: hypervisor load failed: {msg}");
        println!("boot_shim: continuing to Windows without hypervisor");
    } else {
        println!("boot_shim: hypervisor loaded and active");
    }

    println!("boot_shim: chainloading Windows Boot Manager...");
    if let Err(msg) = load_and_start(cstr16!("\\EFI\\Microsoft\\Boot\\bootmgfw.efi")) {
        println!("boot_shim: Windows chainload failed: {msg}");
        println!("boot_shim: halting");
        loop {
            unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
        }
    }

    Status::SUCCESS
}

fn load_and_start(path: &CStr16) -> Result<(), &'static str> {
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|_| "open LoadedImage failed")?;
    let device_handle = loaded_image
        .device()
        .ok_or("LoadedImage has no device handle")?;

    let device_path = boot::open_protocol_exclusive::<DevicePath>(device_handle)
        .map_err(|_| "open DevicePath failed")?;

    let mut buf = [MaybeUninit::uninit(); 512];
    let mut builder = DevicePathBuilder::with_buf(&mut buf);
    for node in device_path.node_iter() {
        builder = builder.push(&node).map_err(|_| "DevicePath push failed")?;
    }

    drop(device_path);
    drop(loaded_image);

    let file_node = uefi::proto::device_path::build::media::FilePath { path_name: path };
    builder = builder
        .push(&file_node)
        .map_err(|_| "FilePath push failed")?;
    let full_path = builder
        .finalize()
        .map_err(|_| "DevicePath finalize failed")?;

    let image_handle = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: full_path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )
    .map_err(|_| "LoadImage failed")?;

    boot::start_image(image_handle).map_err(|_| "StartImage failed")?;

    Ok(())
}

#[cfg(not(any(test, doc)))]
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("\n!!! PANIC: {info}");
    loop {
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
