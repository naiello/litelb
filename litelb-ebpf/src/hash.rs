use core::{hash::Hasher, ops::BitXor};

// Adapted from `rustc`, but without `std` dependency.
// https://doc.rust-lang.org/stable/src/proc_macro/bridge/fxhash.rs.html
pub struct FxHasher {
    hash: usize,
}

impl Default for FxHasher {
    #[inline]
    fn default() -> Self {
        FxHasher { hash: 0 }
    }
}

const K: usize = 0x517cc1b727220a95;

impl FxHasher {
    fn add(&mut self, i: usize) {
        self.hash = self.hash.rotate_left(5).bitxor(i).wrapping_mul(K);
    }
}

impl Hasher for FxHasher {
    fn write(&mut self, mut bytes: &[u8]) {
        let read_usize = |bytes: &[u8]| u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        let mut hash = FxHasher { hash: self.hash };
        while bytes.len() >= size_of::<usize>() {
            hash.add(read_usize(bytes) as usize);
            bytes = &bytes[size_of::<usize>()..];
        }
        if (size_of::<usize>() > 4) && (bytes.len() >= 4) {
            hash.add(u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize);
            bytes = &bytes[4..];
        }
        if (size_of::<usize>() > 2) && bytes.len() >= 2 {
            hash.add(u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize);
            bytes = &bytes[2..];
        }
        if (size_of::<usize>() > 1) && bytes.len() >= 1 {
            hash.add(bytes[0] as usize);
        }
        self.hash = hash.hash;
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as usize);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(i as usize);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as usize);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i as usize);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash as u64
    }
}
