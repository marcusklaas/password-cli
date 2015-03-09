#![feature(path)]
#![feature(io)]

extern crate "password-cli" as cli;

use cli::{read_file, print_password_list, PasswordLibrary, PasswordEntry, decode_buffer, test_entry, library_is_fresh, refresh_library};
use std::env::{self, home_dir};
use std::ascii::AsciiExt;
use std::io::{BufRead, stdin};

static PASSWORD_DIRECTORY: &'static str = ".passwerdz";
static PASSWORD_FILENAME:  &'static str = "lib.aes256";
static URL_FILENAME:       &'static str = "url.txt";
static MAX_AGE_MILLISECONDS:        u64 = 7 * 24 * 60 * 60 * 1000;
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

    let (library_path, url_path) = match home_dir() {
        Some(mut path) => {
            path.push(PASSWORD_DIRECTORY);
                        
            let url_path = path.join(URL_FILENAME);
            
            path.push(PASSWORD_FILENAME);
            
            (path, url_path)
        },
        None       => panic!("Couldn't get local path")
    };

    if ! library_is_fresh(&library_path, MAX_AGE_MILLISECONDS).expect("checking library freshness") {
        println!("Downloading new password library...");
        
        refresh_library(&library_path, &url_path).expect("refreshing lib");
    }
    
    let buffer = read_file(&library_path).ok().expect("reading buffer");

    println!("Enter the master password: ");

    let stdio = stdin();
    let mut stdin = stdio.lock();
    let mut password = String::new();

    stdin.read_line(&mut password).ok().expect("reading line from stdion");
    password.pop();
    
    let data = decode_buffer(&buffer, password).expect("decoding buffer");
    let json = PasswordLibrary::from_json_bytes(&data).ok().expect("reading json");

    let search_terms: Vec<_> = args.map(|str| { str.to_ascii_lowercase() }).collect();
    let matches: Vec<&PasswordEntry> = json.get_entries().iter().filter(|entry| test_entry(search_terms.iter(), entry)).collect();

    if matches.len() == 1 {
        assert!(matches[0].write_to_clipboard());
    }
    else {
        print_password_list(matches.iter().map(|&x| x));
        println!("Enter index: ");

        let mut index = String::new();

        stdin.read_line(&mut index).ok().expect("reading index");
        
        let num: usize = index.trim().parse().unwrap();
        assert!(matches[num - 1].write_to_clipboard());
    }
}
