use core::fmt::Write;

use uefi::system;

#[macro_export]
macro_rules! println {
    () => {
        ($crate::print!("\n"));
    };

    ($($arg:tt)*) => {
        ($crate::print!("{}\n", format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        ($crate::println::print(format_args!($($arg)*)))
    };
}

#[doc(hidden)]
pub(crate) fn print(args: core::fmt::Arguments<'_>) {
    system::with_stdout(|stdout| {
        stdout.write_fmt(args).unwrap();
    });
}
