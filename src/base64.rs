use crate::{BASE64_CODE, INDEX_64};

pub fn encode_base64(value: Vec<isize>, len: usize) -> Result<String, String> {
    if len <= 0 || len > value.len() {
        return Err("Invalid len".into());
    }

    let mut off = 0;

    let mut rs = String::new();

    let mut c1;
    let mut c2;

    while off < len {
        c1 = value[off] & 0xff;
        off += 1;

        rs.push(BASE64_CODE[(c1 as usize >> 2) & 0x3f]);

        c1 = (c1 & 0x03) << 4;

        if off >= len {
            rs.push(BASE64_CODE[c1 as usize & 0x3f]);

            break;
        }

        c2 = value[off] & 0xff;
        c1 |= (c2 >> 4) & 0x0f;
        off += 1;

        rs.push(BASE64_CODE[c1 as usize & 0x3f]);

        c1 = (c2 & 0x0f) << 2;

        if off >= len {
            rs.push(BASE64_CODE[c1 as usize & 0x3f]);

            break;
        }

        c2 = value[off] & 0xff;
        c1 |= (c2 >> 6) & 0x03;
        off += 1;

        rs.push(BASE64_CODE[c1 as usize & 0x3f]);
        rs.push(BASE64_CODE[c2 as usize & 0x3f]);
    }

    Ok(rs)
}

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

pub fn decode_base64(s: String, maxlen: usize) -> Result<Vec<isize>, String> {
    if maxlen <= 0 {
        return Err("Invalid maxlen".into());
    }

    let mut rs = String::new();
    let mut off = 0;
    let slen = s.len();
    let mut olen = 0;

    let mut c1;
    let mut c2;
    let mut c3;
    let mut c4;
    let mut o;

    // TODO: remove unsafe blocks here
    while off < slen - 1 && olen < maxlen {
        // TODO: remove this unwrap
        c1 = char64(s.chars().nth(off).unwrap());
        off += 1;
        c2 = char64(s.chars().nth(off).unwrap());
        off += 1;

        if c1 == -1 || c2 == -1 {
            break;
        }

        o = get_byte_from_number(c1 << 2);
        o |= (c2 & 0x30) >> 4;

        unsafe {
            rs.push(char::from_u32_unchecked(o as u32));
        }

        olen += 1;
        if olen >= maxlen || off >= slen {
            break;
        }

        c3 = char64(s.chars().nth(off).unwrap());
        off += 1;

        if c3 == -1 {
            break;
        }

        o = get_byte_from_number((c2 & 0x0f) << 4);
        o |= (c3 & 0x3c) >> 2;

        unsafe {
            rs.push(char::from_u32_unchecked(o as u32));
        }

        olen += 1;
        if olen >= maxlen || off >= slen {
            break;
        }

        c4 = char64(s.chars().nth(off).unwrap());
        off += 1;

        o = get_byte_from_number((c3 & 0x03) << 6);
        o |= c4;

        unsafe {
            rs.push(char::from_u32_unchecked(o as u32));
        }

        olen += 1;
    }

    let mut ret: Vec<isize> = Vec::new();

    off = 0;

    while off < olen {
        ret.push(get_byte_from_char(rs.chars().nth(off).unwrap()));

        off += 1;
    }

    Ok(ret)
}
