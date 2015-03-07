#![feature(core)]
#![feature(io)]
#![feature(path)]
#![feature(collections)]

extern crate "rustc-serialize" as rustc_serialize;
extern crate crypto;
extern crate clipboard;
extern crate hyper;

use hyper::client::Client;
use hyper::header::Connection;
use hyper::header::ConnectionOption;

use crypto::aes::{cbc_decryptor, KeySize};
use crypto::symmetriccipher::SymmetricCipherError;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, WriteBuffer, ReadBuffer, BufferResult};
use crypto::blockmodes::PkcsPadding;

use crypto::digest::Digest;
use crypto::md5::Md5;

use rustc_serialize::base64::{FromBase64};
use rustc_serialize::json::{self, decode, DecodeResult};

use std::path::Path;
use std::io::{self, Read};
use std::fs::File;
use std::ascii::AsciiExt;

#[derive(RustcDecodable, RustcEncodable)]
pub struct PasswordEntry {
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub comment: String
}

impl PasswordEntry {
    pub fn write_to_clipboard(&self) -> bool {
        clipboard::write(&self.password).is_ok()
    }

    pub fn get_title<'a>(&'a self) -> &'a str {
        &self.title
    }
}

#[derive(RustcDecodable, RustcEncodable)]
pub struct PasswordLibrary {
    pub modified: u64,
    pub list: Vec<PasswordEntry>
}

impl PasswordLibrary {
    pub fn from_json_bytes(bytes: &[u8]) -> DecodeResult<PasswordLibrary> {
        let string = String::from_utf8_lossy(bytes);
    
        json::decode(&*string)
    }

    pub fn get_entries<'a>(&'a self) -> &'a[PasswordEntry] {
        &self.list
    }
}

pub fn print_password_list<'a, I>(list: I) where I: Iterator<Item=&'a PasswordEntry> {
    println!("+-{0:-<5}-+-{0:-<30}-+-{0:-<35}-+-{0:-<35}-+", "");
    println!("| {0: ^5} | {1: ^30} | {2: ^35} | {3: ^35} |", "id", "title", "username", "url");
    println!("+-{0:-<5}-+-{0:-<30}-+-{0:-<35}-+-{0:-<35}-+", "");
    
    for (i, entry) in list.enumerate() {
        println!("| {: >5} | {: <30} | {: <35} | {: <35} |", i + 1, entry.title, entry.username, entry.url);
    }

    println!("+-{0:-<5}-+-{0:-<30}-+-{0:-<35}-+-{0:-<35}-+", "");
}

// Decrypts a given block of AES256-CBC data using a 32 byte key and 16 byte
// initialization vector. Returns error on incorrect passwords 
fn decrypt_block(block: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Option<Vec<u8>> {    
    let mut decryptor = cbc_decryptor(KeySize::KeySize256, key.as_slice(), iv.as_slice(), PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut read_buffer = RefReadBuffer::new(block);
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    macro_rules! do_while_match (($b: block, $e: pat) => (while let $e = $b {}));

    do_while_match!({
        let result = match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(x)   => x,
            Err(..) => return None
        };
        
        final_result.push_all(write_buffer.take_read_buffer().take_remaining());
        result
    }, BufferResult::BufferOverflow);

    Some(final_result)
}

fn derive_key(salted_password: &[u8]) -> (Box<[u8; 32]>, Box<[u8; 16]>) {
    let mut last_hash = Vec::new();
    let mut hasher = Md5::new();
    let mut key = Box::new([0u8; 32]);
    let mut iv = Box::new([0u8; 16]);

    for i in 0..2 {
        let slice = &mut(*key)[16 * i.. 16 * (i + 1)];
        
        last_hash.push_all(salted_password);
        hasher.input(&last_hash);
        hasher.result(slice);
        hasher.reset();
        last_hash.clear();
        last_hash.push_all(slice);
    }

    last_hash.push_all(salted_password);
    hasher.input(&last_hash);
    hasher.result(&mut *iv);

    (key, iv)
}

pub fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = try!(File::open(path));
    let mut buffer = Vec::new();
    
    try!(file.read_to_end(&mut buffer));

    Ok(buffer)
}

pub fn decode_buffer(buffer: &[u8], password: String) -> Option<Vec<u8>> {
    let bytes = match buffer.as_slice().from_base64() {
        Ok(x)   => x,
        Err(..) => return None
    };
    
    let salt = &bytes[8..16];
    let mut salted_password = password.into_bytes();
    salted_password.push_all(salt);

    let (key, iv) = derive_key(&salted_password);

    decrypt_block(&bytes[16..], &key, &iv)
}

pub fn download_file(url: &str) -> Option<Vec<u8>> {
    Client::new()
        .get(url)
        .header(Connection(vec![ConnectionOption::Close]))
        .send()
        .ok()
        .and_then(|mut response| {
            let mut buffer = Vec::new();
            
            match response.read_to_end(&mut buffer) {
                Ok(..)  => Some(buffer),
                Err(..) => None
            }
        })
}

pub fn test_entry<I>(needles: I, haystack: &PasswordEntry) -> bool
                        where I: Iterator, <I as Iterator>::Item: Str {
    test_match(needles, &haystack.get_title())
}

// expects the needles to be in lowercase already
fn test_match<I>(needles: I, haystack: &str) -> bool
                    where I: Iterator, <I as Iterator>::Item: Str {
    let lower = haystack.to_ascii_lowercase();
    
    needles.map(|needle| lower.contains(&needle.as_slice())).fold(true, |a, b| { a && b })
}

#[cfg(test)]
mod test {
    use super::{test_match, derive_key};

    #[test]
    pub fn key_derivation() {
        let input: &[u8] = &[99, 111, 111, 108, 70, 111, 120, 104, 111, 108, 101, 115, 49, 50, 119, 97, 116, 101, 114, 115, 181, 138, 204, 219, 241, 200, 166, 229];
        let expected_key: [u8; 32] = [37, 185, 158, 246, 99, 13, 114, 43, 244, 181, 210, 162, 153, 245, 60, 166, 139, 117, 60, 11, 26, 17, 113, 150, 229, 17, 239, 94, 76, 140, 73, 70];
        let expected_iv: [u8; 16] = [99, 251, 72, 212, 242, 59, 128, 184, 140, 87, 142, 238, 94, 138, 133, 223];

        let (key, iv) = derive_key(input);

        assert_eq!(expected_key, *key);
        assert_eq!(expected_iv, *iv);
    }

    #[test]
    pub fn title_matching() {
        assert!(test_match(&[format!("nana")], "banana"));
        assert!(test_match(&[format!("nana"), format!("i li"), format!("i like bananas")], "i like banAnas"));
        assert!(test_match(&[], "test"));

        assert!( ! test_match(&[format!("test")], "tes"));
    }
}
