#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
use std::net::UdpSocket;
mod dlc;

use std::ptr;

use crate::dlc::{
    pcre2_code_free_8, pcre2_compile_8, pcre2_get_ovector_pointer_8, pcre2_match_8,
    pcre2_match_data_create_from_pattern_8, pcre2_match_data_free_8, PCRE2_UCP, PCRE2_UTF,
};

fn main() {
    let subject = "\"a;jhgoqoghqoj0329 u0tyu10hg0h9Y0Y9827342482y(Y0y(G)_)lajf;lqjfgqhgpqjopjqa=)*(^!@#$%^&*())9999999\"";

    let mut result = String::new();
    for c in String::from(subject).chars() {
        let s = String::from(c);
        let res = check(&s);
        result += res;
    }

    // println!("{}", result);
    let target = select(result);

    // println!("{}", target);
    let result_str = &target[4..14];
    
    let bind_addr = String::from("127.0.0.1:12346");
    let target_addr = String::from("127.0.0.1:10000");

    let miner = UdpSocket::bind(bind_addr.clone()) .expect(&format!("Unable to parse socket address {}", bind_addr));

    miner.send_to(&result_str.as_bytes(), target_addr).unwrap();

    println!("{}", result_str);
}

fn check(subject: &str) -> &str {
    let mut error_code = 0;
    let mut error_offset = 0;
    let pattern = r"[\w\W]";
    let code = unsafe {
        pcre2_compile_8(
            pattern.as_ptr(),
            pattern.len(),
            PCRE2_UCP | PCRE2_UTF,
            &mut error_code,
            &mut error_offset,
            ptr::null_mut(),
        )
    };
    if code.is_null() {
        panic!(
            "compilation failed; error code: {:?}, offset: {:?}",
            error_code, error_offset
        );
    }

    let match_data = unsafe { pcre2_match_data_create_from_pattern_8(code, ptr::null_mut()) };
    if match_data.is_null() {
        unsafe {
            pcre2_code_free_8(code);
        }
        panic!("could not allocate match_data");
    }

    let ovector = unsafe { pcre2_get_ovector_pointer_8(match_data) };
    if ovector.is_null() {
        unsafe {
            pcre2_match_data_free_8(match_data);
            pcre2_code_free_8(code);
        }
        panic!("could not get ovector");
    }

    let rc = unsafe {
        pcre2_match_8(
            code,
            subject.as_ptr(),
            subject.len(),
            0,
            0,
            match_data,
            ptr::null_mut(),
        )
    };
    if rc <= 0 {
        unsafe {
            pcre2_match_data_free_8(match_data);
            pcre2_code_free_8(code);
        }
        panic!("error executing match");
    }

    let (s, e) = unsafe { (*ovector.offset(0), *ovector.offset(1)) };
    unsafe {
        pcre2_match_data_free_8(match_data);
        pcre2_code_free_8(code);
    }

    &subject[s..e]
}

fn select(subject: String) -> String {
    let number_len = 4;
    let result_len = 10;
    let none_empty_len = 1;

    let mut left = String::new();
    let mut result = String::new();
    let mut right = String::new();

    for c in subject.chars() {
        if c > '0' && c < '9' {
            if left.len() < number_len {
                left += &String::from(c);
            }
            continue;
        }

        if c == ' ' {
            continue;
        }

        if result.len() < result_len {
            result += &String::from(c);
        } else {
            if right.len() < none_empty_len {
                right += &String::from(c);
            }
        }
    }

    let mut target = String::new();

    target += &left;
    target += &result;
    target += &right;

    target
}
