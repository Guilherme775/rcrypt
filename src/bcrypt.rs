use crate::{
    base64::{decode_base64, encode_base64},
    utils::{generate_random_numbers, get_byte_from_char, get_byte_from_number},
    BCRYPT_SALT_LEN, BF_CRYPT_CIPHERTEXT, BLOWFISH_NUM_ROUNDS, P_ORIG, S_ORIG,
};

#[allow(non_snake_case)]
pub struct BCrypt {
    pub P: Vec<isize>,
    pub S: Vec<isize>,
}

impl BCrypt {
    fn new() -> Self {
        Self {
            P: vec![],
            S: vec![],
        }
    }

    fn init_key(&mut self) -> () {
        self.P = P_ORIG.clone().to_vec();
        self.S = S_ORIG.clone().to_vec();
    }

    fn encipher(&mut self, mut lr: Vec<isize>, off: usize) -> Vec<isize> {
        let mut i;
        let mut n;
        let mut l = lr[off];
        let mut r = lr[off + 1];

        l ^= self.P[0];

        i = 0;

        while i <= BLOWFISH_NUM_ROUNDS - 2 {
            // Feistel substitution on left word
            n = self.S[(l >> 24) as usize & 0xff];
            n = n
                .checked_add(self.S[0x100 | ((l >> 16) as usize & 0xff)])
                .unwrap_or(0);
            n ^= self.S[0x200 | ((l >> 8) as usize & 0xff)];
            n = n
                .checked_add(self.S[0x300 | (l & 0xff) as usize])
                .unwrap_or(0);

            i = i + 1;

            r ^= n ^ self.P[i];

            // Feistel substitution on right word
            n = self.S[(r >> 24) as usize & 0xff];
            n = n
                .checked_add(self.S[0x100 | ((r >> 16) as usize & 0xff)])
                .unwrap_or(0);
            n ^= self.S[0x200 | ((r >> 8) as usize & 0xff)];
            n = n
                .checked_add(self.S[0x300 | (r & 0xff) as usize])
                .unwrap_or(0);

            i = i + 1;

            l ^= n ^ self.P[i];
        }

        lr[off] = r ^ self.P[BLOWFISH_NUM_ROUNDS + 1];
        lr[off + 1] = l;

        lr
    }

    fn streamtoword(data: Vec<isize>, mut offp: Vec<usize>) -> (isize, Vec<usize>) {
        let mut i = 0;
        let mut word = 0;
        let mut off = offp[0];

        while i < 4 {
            word = (word << 8) | (data[off] & 0xff);
            off = (off + 1) % data.len();

            i = i + 1;
        }

        offp[0] = off;

        return (word, offp);
    }

    fn key(&mut self, key: Vec<isize>) {
        let mut i;
        let mut koffp = vec![0];
        let mut lr = vec![0, 0];
        let plen = self.P.len();
        let slen = self.S.len();

        i = 0;

        while i < plen {
            let (word, offp) = BCrypt::streamtoword(key.clone(), koffp);

            self.P[i] = self.P[i] ^ word;
            koffp = offp;

            i = i + 1;
        }

        i = 0;

        while i < plen {
            lr = self.encipher(lr.clone(), 0);
            self.P[i] = lr[0];
            self.P[i + 1] = lr[1];

            i = i + 2;
        }

        i = 0;

        while i < slen {
            lr = self.encipher(lr, 0);
            self.S[i] = lr[0];
            self.S[i + 1] = lr[1];

            i = i + 2;
        }
    }

    fn ekskey(&mut self, data: Vec<isize>, key: Vec<isize>) {
        let mut i;
        let mut koffp = vec![0];
        let mut doffp = vec![0];
        let mut lr = vec![0, 0];
        let plen = self.P.len();
        let slen = self.S.len();

        i = 0;

        while i < plen {
            let (word, offp) = BCrypt::streamtoword(key.clone(), koffp);

            self.P[i] = self.P[i] ^ word;
            koffp = offp;

            i = i + 1;
        }

        i = 0;

        while i < plen {
            let (word, offp) = BCrypt::streamtoword(data.clone(), doffp.clone());

            lr[0] ^= word;
            doffp = offp;

            let (word, offp) = BCrypt::streamtoword(data.clone(), doffp.clone());

            lr[1] ^= word;
            doffp = offp;

            lr = self.encipher(lr, 0);

            self.P[i] = lr[0];
            self.P[i + 1] = lr[1];

            i = i + 2;
        }

        i = 0;

        while i < slen {
            let (word, offp) = BCrypt::streamtoword(data.clone(), doffp.clone());

            lr[0] ^= word;
            doffp = offp;

            let (word, offp) = BCrypt::streamtoword(data.clone(), doffp.clone());

            lr[1] ^= word;
            doffp = offp;

            lr = self.encipher(lr, 0);

            self.S[i] = lr[0];
            self.S[i + 1] = lr[1];

            i = i + 2;
        }
    }

    fn crypt_raw<'a>(
        &mut self,
        password: Vec<isize>,
        salt: Vec<isize>,
        log_rounds: usize,
        data: Vec<isize>,
    ) -> Result<Vec<isize>, &'a str> {
        let mut i;
        let mut j;
        let mut cdata = data;
        let clen = cdata.len();
        let mut ret: Vec<isize> = vec![];

        let rounds = 1 << log_rounds;

        if log_rounds < 4 || log_rounds > 30 {
            return Err("Bad number of rounds");
        }

        if salt.len() != BCRYPT_SALT_LEN as usize {
            return Err("Bad salt length");
        }

        self.init_key();
        self.ekskey(salt.clone(), password.clone());

        i = 0;

        while i != rounds {
            self.key(password.clone());
            self.key(salt.clone());

            i = i + 1;
        }

        i = 0;
        j = 0;

        while i < 64 {
            while j < (clen >> 1) {
                cdata = self.encipher(cdata.clone(), j << 1);

                j = j + 1;
            }

            i = i + 1;
        }

        i = 0;

        while i < clen {
            ret.push(get_byte_from_number((cdata[i] >> 24) & 0xff));
            ret.push(get_byte_from_number((cdata[i] >> 16) & 0xff));
            ret.push(get_byte_from_number((cdata[i] >> 8) & 0xff));
            ret.push(get_byte_from_number(cdata[i] & 0xff));

            i = i + 1;
        }

        Ok(ret)
    }

    fn password_to_bytes<'a>(password: String) -> Result<Vec<isize>, &'a str> {
        let mut passwordb: Vec<isize> = vec![];

        for c in password.chars() {
            let code = c as isize;

            if code < 128 {
                passwordb.push(code);
            } else if code > 127 && code < 2048 {
                passwordb.push((code >> 6) | 192);
                passwordb.push((code & 63) | 128);
            } else if code >= 55296 && code <= 56319 {
                let next_code = password.chars().nth(1).unwrap_or('\0') as isize;

                if next_code < 56320 || next_code > 57343 {
                    return Err("utf-16 Decoding error: trail surrogate not in the range of 0xdc00 through 0xdfff");
                }

                let decoded = ((code - 55296) << 10) + (next_code - 56320) + 65536;
                passwordb.push((decoded >> 18) | 240);
                passwordb.push(((decoded >> 12) & 63) | 128);
                passwordb.push(((decoded >> 6) & 63) | 128);
                passwordb.push((decoded & 63) | 128);
            } else {
                passwordb.push((code >> 12) | 224);
                passwordb.push(((code >> 6) & 63) | 128);
                passwordb.push((code & 63) | 128);
            }
        }

        Ok(passwordb)
    }

    pub fn hashpw<'a>(password: String, salt: String) -> Result<String, &'a str> {
        let mut bcrypt = BCrypt::new();
        let real_salt: String;
        let passwordb: Vec<isize>;
        let saltb: Vec<isize>;
        let hashed: Vec<isize>;
        let mut minor: char = '0';
        let rounds: usize;
        let off;
        let mut result: String = "".into();

        if salt.chars().nth(0) != Some('$') || salt.chars().nth(1) != Some('2') {
            return Err("Invalid salt version");
        }

        if salt.chars().nth(2) == Some('$') {
            off = 3;
        } else {
            match salt.chars().nth(2) {
                Some(c) => {
                    minor = c;

                    if minor != 'a' || salt.chars().nth(3) != Some('$') {
                        return Err("Invalid salt revision");
                    }

                    off = 4;
                }
                None => return Err("Invalid salt revision"),
            }
        }

        if salt.chars().nth(off + 2) > Some('$') {
            return Err("Missing salt rounds");
        }

        match salt[off..off + 2].parse::<usize>() {
            Ok(x) => rounds = x,
            Err(_) => return Err("Missing salt rounds"),
        }

        real_salt = salt[off + 3..off + 25].to_owned();
        let password_ = format!("{}{}", password, if minor >= 'a' { "\0" } else { "" });

        match BCrypt::password_to_bytes(password_) {
            Ok(x) => passwordb = x,
            Err(err) => return Err(err),
        }

        match decode_base64(real_salt, BCRYPT_SALT_LEN as usize) {
            Ok(x) => saltb = x,
            Err(err) => return Err(err),
        }

        match bcrypt.crypt_raw(
            passwordb,
            saltb.clone(),
            rounds,
            BF_CRYPT_CIPHERTEXT.to_vec().clone(),
        ) {
            Ok(x) => hashed = x,
            Err(err) => return Err(err),
        }

        result.push_str("$2");

        if minor >= 'a' {
            result.push(minor);
        }

        result.push('$');

        if rounds < 10 {
            result.push('0');
        }

        if rounds > 30 {
            return Err("Rounds exceeds maximum (30)");
        }

        result.push_str(rounds.to_string().as_str());
        result.push('$');

        match encode_base64(saltb.clone(), saltb.len()) {
            Ok(x) => result.push_str(x.as_str()),
            Err(err) => return Err(err),
        }

        match encode_base64(hashed, BF_CRYPT_CIPHERTEXT.to_vec().clone().len() * 4 - 1) {
            Ok(x) => result.push_str(x.as_str()),
            Err(err) => return Err(err),
        }

        Ok(result)
    }

    pub fn gensalt<'a>(rounds: u32) -> Result<String, &'a str> {
        if rounds < 4 || rounds > 30 {
            return Err("Rounds excededs maximum (30)!");
        }

        let mut output: String = "".into();

        output.push_str("$2a$");

        if rounds < 10 {
            output.push('0');
        }

        output.push_str(rounds.to_string().as_str());
        output.push('$');

        match encode_base64(generate_random_numbers(), BCRYPT_SALT_LEN as usize) {
            Ok(x) => output.push_str(x.as_str()),
            Err(err) => return Err(err),
        }

        Ok(output)
    }

    pub fn checkpw(plaintext: String, hashed: String) -> bool {
        let off;

        if hashed.chars().nth(0) != Some('$') || hashed.chars().nth(1) != Some('2') {
            return false;
        }

        if hashed.chars().nth(2) == Some('$') {
            off = 3;
        } else {
            match hashed.chars().nth(2) {
                Some(minor) => {
                    if (minor != 'a' && minor != 'b') || hashed.chars().nth(3) != Some('$') {
                        return false;
                    }

                    off = 4;
                }
                None => return false,
            }
        }

        let salt = hashed[..off + 25].to_owned();

        match BCrypt::hashpw(plaintext, salt) {
            Ok(try_pass) => {
                let mut ret = 0;

                let mut i = 0;

                while i < hashed.len() {
                    match (hashed.chars().nth(i), try_pass.chars().nth(i)) {
                        (Some(x), Some(y)) => ret |= get_byte_from_char(x) ^ get_byte_from_char(y),
                        _ => return false,
                    }

                    i = i + 1;
                }

                return ret == 0;
            }
            Err(_) => return false,
        }
    }
}
