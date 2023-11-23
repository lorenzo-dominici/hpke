use hpke_cl::{*, error::*};
use std::env;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();

    match args.len() {
        0 => print_version(),
        1 => match args[0].as_str() {
            "--version" | "-v" => print_version(),
            "--help" | "-h" => print_help(),
            _ => exit_println("Error: option not found"),
        },
        2.. => match args.remove(0).as_str() {
            "test" => if args.len() != 2 {
                encrypt(args[0].as_str(), args[1].as_str());
            } else {
                exit_println("Error: wrong number of arguments");
            },
            "encrypt" => if args.len() != 2 {
                encrypt(args[0].as_str(), args[1].as_str());
            } else {
                exit_println("Error: wrong number of arguments");
            },
            "decrypt" => if args.len() != 2 {
                decrypt(args[0].as_str(), args[1].as_str());
            } else {
                exit_println("Error: wrong number of arguments");
            },
            _ => exit_println("Error: command not found"),
        },
        _ => exit_println("Error: I don't know what you did, but you fucked up!"),
    };
}

fn print_version() {
    println!("hpke {}", option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"))
}

fn print_help() {
    let msg = 
"HPKE command line tool

Usage: hpke [OPTION] [COMMAND]

Options:
    -h, --help                  Print help
    -v, --version               Print version info

Commands:
    test <CONFIG> <DATA>        Test parameters in CONFIG with data in DATA
    encrypt <CONFIG> <DATA>     Encrypt plain-text in DATA with values in CONFIG
    decrypt <CONFIG> <DATA>     Dencrypt cypher-text in DATA with values in CONFIG
";
    println!("{}", msg);
}