use crate::{
    utils::{char64, get_byte_from_char, get_byte_from_number},
    BASE64_CODE,
};

pub fn encode_base64<'a>(value: Vec<isize>, len: usize) -> Result<String, &'a str> {
    if len <= 0 || len > value.len() {
        return Err("Invalid len");
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

pub fn decode_base64<'a>(s: String, maxlen: usize) -> Result<Vec<isize>, &'a str> {
    if maxlen <= 0 {
        return Err("Invalid maxlen");
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

    while off < slen - 1 && olen < maxlen {
        match s.chars().nth(off) {
            Some(x) => c1 = char64(x),
            None => {
                let err = format!("Invalid input: {}", s);

                return Err(Box::leak(err.into_boxed_str()));
            }
        }
        off += 1;

        match s.chars().nth(off) {
            Some(x) => c2 = char64(x),
            None => {
                let err = format!("Invalid input: {}", s);

                return Err(Box::leak(err.into_boxed_str()));
            }
        }
        off += 1;

        if c1 == -1 || c2 == -1 {
            break;
        }

        o = get_byte_from_number(c1 << 2);
        o |= (c2 & 0x30) >> 4;

        match char::from_u32(o as u8 as u32) {
            Some(x) => rs.push(x),
            None => {
                let err = format!("Invalid byte: {}", o);

                return Err(Box::leak(err.into_boxed_str()));
            }
        }

        olen += 1;
        if olen >= maxlen || off >= slen {
            break;
        }

        match s.chars().nth(off) {
            Some(x) => c3 = char64(x),
            None => {
                let err = format!("Invalid input: {}", s);

                return Err(Box::leak(err.into_boxed_str()));
            }
        }
        off += 1;

        if c3 == -1 {
            break;
        }

        o = get_byte_from_number((c2 & 0x0f) << 4);
        o |= (c3 & 0x3c) >> 2;

        match char::from_u32(o as u8 as u32) {
            Some(x) => rs.push(x),
            None => {
                let err = format!("Invalid byte: {}", o);

                return Err(Box::leak(err.into_boxed_str()));
            }
        }

        olen += 1;
        if olen >= maxlen || off >= slen {
            break;
        }

        match s.chars().nth(off) {
            Some(x) => c4 = char64(x),
            None => {
                let err = format!("Invalid input: {}", s);

                return Err(Box::leak(err.into_boxed_str()));
            }
        }
        off += 1;

        o = get_byte_from_number((c3 & 0x03) << 6);
        o |= c4;

        match char::from_u32(o as u8 as u32) {
            Some(x) => rs.push(x),
            None => {
                let err = format!("Invalid byte: {}", o);

                return Err(Box::leak(err.into_boxed_str()));
            }
        }

        olen += 1;
    }

    let mut ret: Vec<isize> = Vec::new();

    off = 0;

    while off < olen {
        match rs.chars().nth(off) {
            Some(x) => ret.push(get_byte_from_char(x)),
            None => {
                let err = format!("Invalid result: {}", rs);

                return Err(Box::leak(err.into_boxed_str()));
            }
        }

        off += 1;
    }

    Ok(ret)
}
