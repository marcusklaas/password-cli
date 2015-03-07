#![feature(path)]

extern crate "password-cli" as cli;

use cli::{read_file, download_file, print_password_list, PasswordLibrary, PasswordEntry, decode_buffer, test_entry};
use std::env::{self, home_dir};
use std::ascii::AsciiExt;
use std::old_io::stdio::stdin;

static PASSWORD_DIRECTORY: &'static str = ".passwerdz";
static PASSWORD_FILENAME: &'static str = "lib.aes256";

/*
 * FLOW: (later -- not current state)
 *
 * check if we have recent update of library, if not: try get it from server and save to disk
 * try to read library from disk
 * ask user to enter master password via raw stdin (not echoed to stdout)
 * try to decrypt library
 * loop
 *   ask user to enter search terms via normal stdin
 *   if number of matches on title is one exactly
 *     copy password to clipboard
 *   else
 *     display titles of matches
 */

fn main() {
    let mut args = env::args();
    let _ = args.next();

    let library_path = match home_dir() {
        Some(mut path) => {
            path.push(PASSWORD_DIRECTORY);
            path.push(PASSWORD_FILENAME);
            path
        },
        None       => panic!("Couldn't get local path")
    };
    
    let buffer = read_file(&library_path).unwrap();

    print!("Enter the master password: ");

    let mut stdin = stdin();
    let mut password = stdin.read_line().unwrap();
    password.pop(); // TODO: this uses old_io still, replace ASAP!
    
    //let buffer = download_file("https://marcusklaas.nl/passwords/encrypted/passwords.txt").unwrap();
    let data = decode_buffer(&buffer, password).unwrap();
    let json = PasswordLibrary::from_json_bytes(&data).unwrap();

    let search_terms: Vec<_> = args.map(|str| { str.to_ascii_lowercase() }).collect();
    let matches: Vec<&PasswordEntry> = json.get_entries().iter().filter(|entry| test_entry(search_terms.iter(), entry)).collect();

    if matches.len() == 1 {
        assert!(matches[0].write_to_clipboard());
    }
    else {
        print_password_list(matches.iter().map(|&x| x));
        print!("Enter index: ");
        let num: usize = stdin.read_line().unwrap().trim().parse().unwrap();
        assert!(matches[num - 1].write_to_clipboard());
    }
}
