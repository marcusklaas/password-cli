#![feature(core)]
#![feature(path)]
#![feature(fs)]
#![feature(io)]
#![feature(collections)]

extern crate "rustc-serialize" as serialize;
extern crate crypto;
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

use serialize::base64::FromBase64;
use serialize::json::Json;

use std::mem::transmute;
use std::path::Path;
use std::io::Read;
use std::fs::File;
use std::ascii::AsciiExt;

// Decrypts a given block of AES256-CBC data using a 32 byte key and 16 byte
// initialization vector. Returns error on incorrect passwords 
fn decrypt_block(block: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, SymmetricCipherError> {    
    let mut decryptor = cbc_decryptor(KeySize::KeySize256, key.as_slice(), iv.as_slice(), PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut read_buffer = RefReadBuffer::new(block);
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    macro_rules! do_while_match (($b: block, $e: pat) => (while let $e = $b {}));

    do_while_match!({
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.push_all(write_buffer.take_read_buffer().take_remaining());
        result
    }, BufferResult::BufferOverflow);

    Ok(final_result)
}

// FIXME: this could be made way nicer
fn derive_key(salted_password: &[u8]) -> (Box<[u8; 32]>, Box<[u8; 16]>) {
    let rounds = 3;
    let mut result = Vec::new();
    let mut last_hash = Vec::new();
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 16];

    hasher.input(salted_password);
    hasher.result(&mut buffer);
    result.push_all(&buffer);
    last_hash.push_all(&buffer);

    for _ in 0..rounds {
        last_hash.push_all(salted_password);
        
        hasher.reset();
        hasher.input(&last_hash);
        hasher.result(&mut buffer);

        last_hash.clear();
        last_hash.push_all(&buffer);
        result.push_all(&buffer);
    }

    let mut key = Box::new([0u8; 32]);
    let mut iv = Box::new([0u8; 16]);

    for i in 0..32 {
        key[i] = result[i];
    }

    for i in 32..48 {
        iv[i - 32] = result[i];
    }

    (key, iv)
}

pub fn read_file(path: &Path) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer);

    buffer
}

pub fn decode_buffer(buffer: &[u8], password: String) -> Option<Vec<u8>> {
    let bytes = buffer.as_slice().from_base64().unwrap();
    let salt = &bytes[8..16];
    let mut salted_password = password.into_bytes();
    salted_password.push_all(salt);

    let (key, iv) = derive_key(&salted_password);

    let decrypted = decrypt_block(&bytes[16..], &key, &iv).unwrap();
    
    Some(decrypted)
}

pub fn download_file(url: &str) -> Vec<u8> {
    // Create a client.
    let mut client = Client::new();

    // Creating an outgoing request.
    let mut res = client.get(url)
        // set a header
        .header(Connection(vec![ConnectionOption::Close]))
        // let 'er go!
        .send().unwrap();

    // Read the Response.

    // FIXME: this should use new Read trait at some point
    //let mut buffer = Vec::new();
    res.read_to_end().unwrap()
}

pub fn parse_json(data: &[u8]) -> Json {
    let string: &str = unsafe { transmute(data) };
    
    Json::from_str(string).unwrap()
}

pub fn print_passwords(json: Json, needle: &[String]) {
    let list = json.find("list").unwrap();

    let vec = match list {
        &Json::Array(ref vec) => vec,
        _                     => panic!("List isn't an array!")
    };

    for item in vec.iter() {
        let title = match item.find("title").unwrap() {
            &Json::String(ref str) => str,
            _                      => panic!("Title isn't a string!")
        };

        let user = match item.find("username").unwrap() {
            &Json::String(ref str) => str,
            _                      => panic!("Username isn't a string!")
        };

        let password = match item.find("password").unwrap() {
            &Json::String(ref str) => str,
            _                      => panic!("Password isn't a string!")
        };

        if test_match(needle, title) {
            println!("{: <30} | {: <30} | {: <}", title, user, password);
        }
    }
}

fn test_match(needle: &[String], haystack: &str) -> bool {
    let lower = haystack.to_ascii_lowercase();
    
    needle.iter().map(|str| lower.contains(&str)).fold(true, |a, b| { a && b })
}
