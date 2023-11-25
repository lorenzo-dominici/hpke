use hpke_cl::{*, error::*};
use std::env;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();

    let str_out = match args.len() {
        0 => version(),
        1 => match args[0].as_str() {
            "--version" | "-v" => version(),
            "--help" | "-h" => help(),
            _ => exit_println("Error: option not found"),
        },
        2.. => match args.remove(0).as_str() {
            "test" => if args.len() == 3 {
                test(args[0].as_str(), args[1].as_str(), args[2].as_str())
            } else {
                exit_println("Error: wrong number of arguments");
            },
            "encrypt" => if args.len() == 2 {
                encrypt(args[0].as_str(), args[1].as_str())
            } else {
                exit_println("Error: wrong number of arguments");
            },
            "decrypt" => if args.len() == 2 {
                decrypt(args[0].as_str(), args[1].as_str())
            } else {
                exit_println("Error: wrong number of arguments");
            },
            _ => exit_println("Error: command not found"),
        },
        _ => exit_println("Error: I don't know what you did, but you fucked up!"),
    };
    
    print!("{}", str_out);
}

fn version() -> String {
    format!("hpke_cl {}\n", option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"))
}

fn help() -> String {
"HPKE command line tool

Usage: hpke [OPTION] [COMMAND]

Options:
    -h, --help                  Print help
    -v, --version               Print version info

Commands:
    test <CONFIG> <DATA>        Test parameters in CONFIG with data in DATA
    encrypt <CONFIG> <DATA>     Encrypt plain-text in DATA with values in CONFIG
    decrypt <CONFIG> <DATA>     Dencrypt cypher-text in DATA with values in CONFIG
".to_string()
}