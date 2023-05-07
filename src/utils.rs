use crate::INDEX_64;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn char64(x: char) -> isize {
    let code = x as isize;

    if code < 0 || code as usize > INDEX_64.len() {
        return -1;
    }

    return INDEX_64[code as usize] as isize;
}

pub fn get_byte_from_char(c: char) -> isize {
    let b = c as isize;

    if b > 127 {
        return -128 + (b % 128);
    } else {
        return b;
    }
}

pub fn get_byte_from_number(b: isize) -> isize {
    if b > 127 {
        return -128 + (b % 128);
    } else {
        return b;
    }
}

pub fn generate_random_numbers<'a>() -> Vec<isize> {
    let now = SystemTime::now();

    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or(Default::default());

    let seed = since_epoch.as_secs() as isize + since_epoch.subsec_nanos() as isize;
    let mut numbers: Vec<isize> = Vec::with_capacity(16);
    let mut prev = seed;

    for _ in 0..16 {
        let next = (prev * 1103515245 + 12345) % (2_i64.pow(31)) as isize;
        let random_number = (next % 21) - 10;
        numbers.push(random_number as isize);
        prev = next;
    }

    numbers
}
