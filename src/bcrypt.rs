use crate::{BLOWFISH_NUM_ROUNDS, P_ORIG, S_ORIG};

#[warn(dead_code)]
#[allow(non_snake_case)]
pub struct BCrypt {
    pub P: Vec<usize>,
    pub S: Vec<usize>,
}

impl BCrypt {
    pub fn init_key() -> Self {
        Self {
            P: P_ORIG.clone().to_vec(),
            S: S_ORIG.clone().to_vec(),
        }
    }

    pub fn encipher(&mut self, mut lr: Vec<usize>, off: usize) {
        let mut i = 0;
        let mut n;
        let mut l = lr[off];
        let mut r = lr[off + 1];

        l ^= self.P[0];

        while i <= BLOWFISH_NUM_ROUNDS - 2 {
            // Feistel substitution on left word
            n = self.S[(l >> 24) & 0xff];
            n += self.S[0x100 | ((l >> 16) & 0xff)];
            n ^= self.S[0x200 | ((l >> 8) & 0xff)];
            n += self.S[0x300 | (l & 0xff)];

            i = i + 1;

            r ^= n ^ self.P[i];

            // Feistel substitution on right word
            n = self.S[(r >> 24) & 0xff];
            n += self.S[0x100 | ((r >> 16) & 0xff)];
            n ^= self.S[0x200 | ((r >> 8) & 0xff)];
            n += self.S[0x300 | (r & 0xff)];

            i = i + 1;

            l ^= n ^ self.P[i];
        }

        lr[off] = r ^ self.P[BLOWFISH_NUM_ROUNDS + 1];
        lr[off + 1] = l;
    }

    pub fn streamtoword(data: Vec<isize>, mut offp: Vec<usize>) -> isize {
        let mut i = 0;
        let mut word = 0;
        let mut off = offp[0];

        while i < 4 {
            word = (word << 8) | (data[off] & 0xff);
            off = (off + 1) % data.len();

            i = i + 1;
        }

        offp[0] = off;

        return word;
    }
}
