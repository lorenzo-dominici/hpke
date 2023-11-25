//! This module offers simple utilities for error handling and repoting.

use std::{process::exit, fmt::{Debug, Display}};

/// This trait aims to offer a rapid and clean exit from the execution in case of unwanted scenarios.
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

/// This funciton offers a clean error reporting technique before terminating the execution of the program.
///   
/// # Parameters
/// - `msg` : The message that will be printed in the error stream.
pub fn exit_println(msg: &str) -> ! {
    eprintln!("{}", msg);
    exit(1)
}