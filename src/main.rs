#![feature(env)]
#![feature(path)]

extern crate "password-cli" as cli;

use std::path::Path;
use cli::{read_file, download_file, print_passwords, parse_json, decode_buffer};
use std::env;
use std::ascii::AsciiExt;
use std::mem;

fn main() {
    let mut args = env::args();
    
    let _ = args.next();
    let mut filename;
    let mut password;

    match args.next() {
        Some(str) => { filename = str; },
        None      => { panic!("No filename given!"); }
    }

    match args.next() {
        Some(str) => { password = str; },
        None      => { panic!("No password given!"); }
    }
    
    //let buffer = read_file(Path::new(&filename)).unwrap();
    let buffer = download_file("https://marcusklaas.nl/passwords/encrypted/passwords.txt");
    let data = decode_buffer(&buffer, password).unwrap();
    let json = parse_json(&data);

    let data_slice: &[u8] = &data;
    let data_string: &str = unsafe { mem::transmute(data_slice) };

    //println!("{}", data_string);
    
    let search_terms: Vec<_> = args.map(|str| { str.to_ascii_lowercase() }).collect();

    print_passwords(json, &search_terms);
}
