use aes::cipher::{KeyIvInit, StreamCipher};

type Aes128Ctr32LE = ctr::Ctr32LE<aes::Aes128>;

use rand::{Error as RandError, RngCore, SeedableRng};

/// An RNG whose stream is an AES-CTR keystream
pub struct Aes128Rng(Aes128Ctr32LE);

impl RngCore for Aes128Rng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.apply_keystream(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for Aes128Rng {
    type Seed = [u8; 32];

    /// The RNG is the keystream of AES-CTR(key=seed, iv=00...0), using 64-bit counters
    fn from_seed(seed: Self::Seed) -> Aes128Rng {
        //let iv = GenericArray::from_slice(b"very secret key.");
        let seed_seed = &seed[0..16];
        let seed_iv = &seed[16..32];
        let stream = Aes128Ctr32LE::new(seed_seed.into(), seed_iv.into());
        Aes128Rng(stream)
    }
}

const N_256: usize = 48;
pub struct MyRngSeed(pub [u8; N_256]);
pub struct MyRng(MyRngSeed);

impl Default for MyRngSeed {
    fn default() -> MyRngSeed {
        MyRngSeed([0u8; N_256])
    }
}

impl AsMut<[u8]> for MyRngSeed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

type Aes256Ctr32LE = ctr::Ctr32LE<aes::Aes256>;

/// An RNG whose stream is an AES-CTR keystream
pub struct Aes256Rng(Aes256Ctr32LE);

impl RngCore for Aes256Rng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.apply_keystream(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for Aes256Rng {
    type Seed = MyRngSeed;

    /// The RNG is the keystream of AES-CTR(key=seed, iv=00...0), using 64-bit counters
    fn from_seed(seed: Self::Seed) -> Aes256Rng {
        //let iv = GenericArray::from_slice(b"very secret key.");
        let seed_seed = &seed.0[0..32];
        let seed_iv = &seed.0[32..48];
        let stream = Aes256Ctr32LE::new(seed_seed.into(), seed_iv.into());
        Aes256Rng(stream)
    }
}
