use hpke_cl::*;
use std::env;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();

    match args.len() {
        0 => print_version(),
        1 => match args[0].as_str() {
            "--version" | "-v" => print_version(),
            "--help" | "-h" => print_help(),
            _ => print_error("Error: option not found!"),
        },
        2.. => match args.remove(0).as_str() {
            "test" => test(args),
            "encrypt" => if args.len() != 2 {
                encrypt(args[0].as_str(), args[1].as_str());
            } else {
                print_error("Error: wrong number of arguments!");
            },
            "decrypt" => if args.len() != 2 {
                decrypt(args[0].as_str(), args[1].as_str());
            } else {
                print_error("Error: wrong number of arguments!");
            },
            _ => print_error("Error: command not found!"),
        },
        _ => print_error("Error: I don't know what you did, but you fucked up!"),
    };
}

fn print_error(msg: &str) {
    println!("\x1b[0;31m{}\x1b[0m", msg);
}

fn print_version() {
    println!("hpke {}", option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"))
}

fn print_help() {
    let msg = 
"HPKE command line tool

Usage: hpke [OPTION] [COMMAND]

Options:
    -h, --help              Print help
    -v, --version           Print version info

Commands:
    encrypt <CONFIG> <DATA>    Encrypt plain-text in DATA with values in CONFIG
    decrypt <CONFIG> <DATA>    Dencrypt cypher-text in DATA with values in CONFIG
";
    println!("{}", msg);
}