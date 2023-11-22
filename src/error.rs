use std::{process::exit, fmt::{Debug, Display}};

pub trait ExitError<T> {
    fn expect_or_exit(self, msg: &str) -> T;
}

impl<T, E: Debug + Display> ExitError<T> for Result<T, E> {
    fn expect_or_exit(self, msg: &str) -> T {
        if cfg!(debug_assertions) {
            self.unwrap()
        } else {
            self.unwrap_or_else(|e| {
                if msg.is_empty() {
                    exit_println(&e.to_string())
                } else {
                    exit_println(msg)
                }
            })
        }
    }
}

pub fn exit_println(msg: &str) -> ! {
    eprintln!("{}", msg);
    exit(1)
}