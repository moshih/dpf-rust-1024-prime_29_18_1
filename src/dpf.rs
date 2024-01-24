#[allow(dead_code)]
use rand::thread_rng;
use rand::Rng;

use crate::noise;
use crate::ntt;
use crate::params::*;

use crate::ntt::{barrett_reduce, mul_mod_mont};
use crate::snip::gen_rand_coeff_seeds;
use aes::cipher::{KeyIvInit, StreamCipher};

#[inline(always)]
pub fn b_s(server: usize) -> usize {
    return B_SLICE * server;
}

#[inline(always)]
pub fn s_s(server: usize) -> usize {
    return S_SLICE * server;
}

pub fn fill_rand_aes128_nr(input: &mut [u8], len: usize) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    thread_rng().fill(&mut key);
    thread_rng().fill(&mut iv);
    let mut cipher = Aes128Ctr64LE::new(&key.into(), &iv.into());
    cipher.apply_keystream(&mut input[0..len]);
}

pub fn fill_rand3_by_seed_aes128_nr(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    input3: &mut [u8],
    len1: usize,
    len2: usize,
    len3: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

    let mut cipher = Aes128Ctr64LE::new(key.into(), iv.into());
    cipher.apply_keystream(&mut input1[0..len1]);
    cipher.apply_keystream(&mut input2[0..len2]);
    cipher.apply_keystream(&mut input3[0..len3]);
}

pub fn fill_rand4_by_seed_aes128_nr(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    input3: &mut [u8],
    input4: &mut [u8],
    len1: usize,
    len2: usize,
    len3: usize,
    len4: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

    let mut cipher = Aes128Ctr64LE::new(key.into(), iv.into());
    cipher.apply_keystream(&mut input1[0..len1]);
    cipher.apply_keystream(&mut input2[0..len2]);
    cipher.apply_keystream(&mut input3[0..len3]);
    cipher.apply_keystream(&mut input4[0..len4]);
}

#[allow(dead_code)]
pub fn fill_rand6_by_seed_aes128_nr(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    input3: &mut [u8],
    input4: &mut [u8],
    input5: &mut [u8],
    input6: &mut [u8],
    len1: usize,
    len2: usize,
    len3: usize,
    len4: usize,
    len5: usize,
    len6: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

    let mut cipher = Aes128Ctr64LE::new(key.into(), iv.into());
    cipher.apply_keystream(&mut input1[0..len1]);
    cipher.apply_keystream(&mut input2[0..len2]);
    cipher.apply_keystream(&mut input3[0..len3]);
    cipher.apply_keystream(&mut input4[0..len4]);
    cipher.apply_keystream(&mut input5[0..len5]);
    cipher.apply_keystream(&mut input6[0..len6]);
}

pub fn fill_rand_aes128_modq(input: &mut [u8], len_32: usize) -> &mut [i32] {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    thread_rng().fill(&mut key);
    thread_rng().fill(&mut iv);
    let mut cipher = Aes128Ctr64LE::new(&key.into(), &iv.into());
    cipher.apply_keystream(&mut input[0..E_BYTES * len_32]);

    let output: &mut [i32] = bytemuck::cast_slice_mut(input);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..len_32 {
        while (output[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output[i] = temp_value as i32;
        }
        output[i] = barrett_reduce(output[i]);
    }

    return output;
}

pub fn fill_rand_aes128_modq_nr(input: &mut [u8], len: usize) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    thread_rng().fill(&mut key);
    thread_rng().fill(&mut iv);
    let mut cipher = Aes128Ctr64LE::new(&key.into(), &iv.into());
    cipher.apply_keystream(&mut input[0..len]);

    let output: &mut [i32] = bytemuck::cast_slice_mut(input);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len / E_BYTES) {
        while (output[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output[i] = temp_value as i32;
        }
        output[i] = output[i] % Q;
    }
}

pub fn fill_rand_aes128_modq_nr_2_by_seed(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    len1: usize,
    len2: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());
    cipher.apply_keystream(&mut input1[0..len1]);
    cipher.apply_keystream(&mut input2[0..len2]);

    let output1: &mut [i32] = bytemuck::cast_slice_mut(input1);
    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len1 / E_BYTES) {
        while (output1[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output1[i] = temp_value as i32;
        }
        output1[i] = output1[i] % Q;
    }

    for i in 0..(len2 / E_BYTES) {
        while (output2[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output2[i] = temp_value as i32;
        }
        output2[i] = output2[i] % Q;
    }
}

pub fn fill_rand_aes128_modq_nr_3_by_seed(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    input3: &mut [u8],
    len1: usize,
    len2: usize,
    len3: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());
    cipher.apply_keystream(&mut input1[0..len1]);
    cipher.apply_keystream(&mut input2[0..len2]);
    cipher.apply_keystream(&mut input3[0..len3]);

    let output1: &mut [i32] = bytemuck::cast_slice_mut(input1);
    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);
    let output3: &mut [i32] = bytemuck::cast_slice_mut(input3);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len1 / E_BYTES) {
        while (output1[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output1[i] = temp_value as i32;
        }
        output1[i] = output1[i] % Q;
    }

    for i in 0..(len2 / E_BYTES) {
        while (output2[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output2[i] = temp_value as i32;
        }
        output2[i] = output2[i] % Q;
    }

    for i in 0..(len3 / E_BYTES) {
        while (output3[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output3[i] = temp_value as i32;
        }
        output3[i] = output3[i] % Q;
    }
}

pub fn fill_rand_aes128_modq_nr_6_by_seed(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    input3: &mut [u8],
    input4: &mut [u8],
    input5: &mut [u8],
    input6: &mut [u8],
    len1: usize,
    len2: usize,
    len3: usize,
    len4: usize,
    len5: usize,
    len6: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());
    cipher.apply_keystream(&mut input1[0..len1]);
    cipher.apply_keystream(&mut input2[0..len2]);
    cipher.apply_keystream(&mut input3[0..len3]);
    cipher.apply_keystream(&mut input4[0..len4]);
    cipher.apply_keystream(&mut input5[0..len5]);
    cipher.apply_keystream(&mut input6[0..len6]);

    let output1: &mut [i32] = bytemuck::cast_slice_mut(input1);
    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);
    let output3: &mut [i32] = bytemuck::cast_slice_mut(input3);
    let output4: &mut [i32] = bytemuck::cast_slice_mut(input4);
    let output5: &mut [i32] = bytemuck::cast_slice_mut(input5);
    let output6: &mut [i32] = bytemuck::cast_slice_mut(input6);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len1 / E_BYTES) {
        while (output1[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output1[i] = temp_value as i32;
        }
        output1[i] = output1[i] % Q;
    }

    for i in 0..(len2 / E_BYTES) {
        while (output2[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output2[i] = temp_value as i32;
        }
        output2[i] = output2[i] % Q;
    }

    for i in 0..(len3 / E_BYTES) {
        while (output3[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output3[i] = temp_value as i32;
        }
        output3[i] = output3[i] % Q;
    }

    for i in 0..(len4 / E_BYTES) {
        while (output4[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output4[i] = temp_value as i32;
        }
        output4[i] = output4[i] % Q;
    }

    for i in 0..(len5 / E_BYTES) {
        while (output5[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output5[i] = temp_value as i32;
        }
        output5[i] = output5[i] % Q;
    }

    for i in 0..(len6 / E_BYTES) {
        while (output6[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output6[i] = temp_value as i32;
        }
        output6[i] = output6[i] % Q;
    }
}

/*
This function generated the array of seeds by individual seeds
Runs faster than generating all from a single seed
 */
pub fn fill_rand_aes128_modq_nr_2_by_seed_sq(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    len1: usize,
    len2: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());
    cipher.apply_keystream(&mut input1[0..len1]);
    //cipher.apply_keystream(&mut input2[0.. len2]);

    let output1: &mut [i32] = bytemuck::cast_slice_mut(input1);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len1 / E_BYTES) {
        while (output1[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output1[i] = temp_value as i32;
        }
        output1[i] = output1[i] % Q;
    }

    let num_seeds = len2 / (E_BYTES * N_PARAM);
    let mut temp_seeds = vec![0u8; SEED_IV_LEN * num_seeds];

    cipher.apply_keystream(&mut temp_seeds);
    //println!("temp_seeds: {:?}", &temp_seeds[0..16]);
    //println!("--temp_seeds: {:?}", &temp_seeds[16..32]);

    let iterations: usize = len2 / (E_BYTES * N_PARAM);
    for iter in 0..iterations {
        let mut seed_cipher = Aes128Ctr64LE::new(
            (&temp_seeds[32 * iter..32 * iter + 16]).into(),
            (&temp_seeds[32 * iter + 16..32 * iter + 32]).into(),
        );
        seed_cipher
            .apply_keystream(&mut input2[E_BYTES * N_PARAM * iter..E_BYTES * N_PARAM * (iter + 1)]);
    }
    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);

    for i in 0..(len2 / E_BYTES) {
        if i % (N_PARAM) == 0 {
            //if temp[0]|temp[1]|temp[2]|temp[3] != 0 {
            temp = [0; E_BYTES];
            //}
            cipher = Aes128Ctr64LE::new(
                (&temp_seeds[32 * (i >> N_PARAM_LOG2) + 16..32 * (i >> N_PARAM_LOG2) + 32]).into(),
                (&temp_seeds[32 * (i >> N_PARAM_LOG2)..32 * (i >> N_PARAM_LOG2) + 16]).into(),
            );
            //cipher =  Aes128Ctr64LE::new((&temp_seeds[16..32]).into(), (&temp_seeds[0..16]).into());
            //cipher.seek(0u32);
        }

        while (output2[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            //if temp[0]|temp[1]|temp[2]|temp[3] == 0 {
            //    cipher =  Aes128Ctr64LE::new((&temp_seeds[32*(i>>9)+16..32*(i>>9)+32]).into(), (&temp_seeds[32*(i>>9)..32*(i>>9)+16]).into());
            //}
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output2[i] = temp_value as i32;
        }

        output2[i] = output2[i] % Q;
    }
}

/*
This function gets only the seed from the queried index of the array of seeds (for the s vector)
 */
pub fn fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    len1: usize,
    len2: usize,
    seed_index: usize,
    num_seeds: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());
    cipher.apply_keystream(&mut input1[0..len1]);
    //cipher.apply_keystream(&mut input2[0.. len2]);

    let output1: &mut [i32] = bytemuck::cast_slice_mut(input1);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len1 / E_BYTES) {
        while (output1[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output1[i] = temp_value as i32;
        }
        output1[i] = output1[i] % Q;
    }

    temp = [0u8; E_BYTES];
    let mut temp_seeds = vec![0u8; SEED_IV_LEN * num_seeds];
    cipher.apply_keystream(&mut temp_seeds);
    //println!("num_seeds is {}", num_seeds);
    //println!("seed_index is {}", seed_index);
    {
        let mut seed_cipher = Aes128Ctr64LE::new(
            (&temp_seeds[32 * seed_index..32 * seed_index + 16]).into(),
            (&temp_seeds[32 * seed_index + 16..32 * seed_index + 32]).into(),
        );
        seed_cipher.apply_keystream(&mut input2[0..E_BYTES * N_PARAM]);
    }
    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);

    cipher = Aes128Ctr64LE::new(
        (&temp_seeds[32 * seed_index + 16..32 * seed_index + 32]).into(),
        (&temp_seeds[32 * seed_index..32 * seed_index + 16]).into(),
    );
    //cipher =  Aes128Ctr64LE::new((&temp_seeds[16..32]).into(), (&temp_seeds[0..16]).into());

    //cipher.seek(0u32);
    for i in 0..(len2 / E_BYTES) {
        while (output2[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output2[i] = temp_value as i32;
        }

        output2[i] = output2[i] % Q;
    }
}

pub fn fill_rand_aes128_modq_nr_1_by_seed(key: &[u8], iv: &[u8], input2: &mut [u8], len2: usize) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());

    cipher.apply_keystream(&mut input2[0..len2]);

    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len2 / E_BYTES) {
        if i % (N_PARAM) == 0 {
            //if temp[0]|temp[1]|temp[2]|temp[3] != 0 {
            temp = [0; E_BYTES];
            //}
            cipher = Aes128Ctr64LE::new((&iv[0..16]).into(), (&key[0..16]).into());
            //cipher =  Aes128Ctr64LE::new((&temp_seeds[16..32]).into(), (&temp_seeds[0..16]).into());
            //cipher.seek(0u32);
        }

        while (output2[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            //if temp[0]|temp[1]|temp[2]|temp[3] == 0 {
            //    cipher =  Aes128Ctr64LE::new((&temp_seeds[32*(i>>9)+16..32*(i>>9)+32]).into(), (&temp_seeds[32*(i>>9)..32*(i>>9)+16]).into());
            //}
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output2[i] = temp_value as i32;
        }

        output2[i] = output2[i] % Q;
    }
}

/*
This function generated the array of seeds by individual seeds
Runs faster than generating all from a single seed
 */
pub fn fill_rand_aes128_modq_nr_1_by_seed_sq(
    key: &[u8],
    iv: &[u8],
    input2: &mut [u8],
    len2: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());

    let mut temp_seeds = vec![0u8; SEED_IV_LEN * len2 / (E_BYTES * N_PARAM)];
    cipher.apply_keystream(&mut temp_seeds);
    //println!("temp_seeds: {:?}", &temp_seeds[0..16]);
    //println!("--temp_seeds: {:?}", &temp_seeds[16..32]);

    let iterations: usize = len2 / (E_BYTES * N_PARAM);
    for iter in 0..iterations {
        let mut seed_cipher = Aes128Ctr64LE::new(
            (&temp_seeds[32 * iter..32 * iter + 16]).into(),
            (&temp_seeds[32 * iter + 16..32 * iter + 32]).into(),
        );
        seed_cipher
            .apply_keystream(&mut input2[E_BYTES * N_PARAM * iter..E_BYTES * N_PARAM * (iter + 1)]);
    }
    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len2 / E_BYTES) {
        if i % (N_PARAM) == 0 {
            temp = [0; E_BYTES];
            //}
            cipher = Aes128Ctr64LE::new(
                (&temp_seeds[32 * (i >> N_PARAM_LOG2) + 16..32 * (i >> N_PARAM_LOG2) + 32]).into(),
                (&temp_seeds[32 * (i >> N_PARAM_LOG2)..32 * (i >> N_PARAM_LOG2) + 16]).into(),
            );
        }

        while (output2[i] as u32) > MAX_RAND {
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output2[i] = temp_value as i32;
        }

        output2[i] = output2[i] % Q;
    }
}

/*
This function generated the array of seeds by individual seeds
Runs faster than generating all from a singel seed
 */
pub fn fill_rand_aes128_modq_nr_1_by_seed_sq_getsub(
    key: &[u8],
    iv: &[u8],
    input2: &mut [u8],
    len2: usize,
    seed_index: usize,
    num_seeds: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());

    let mut temp_seeds = vec![0u8; SEED_IV_LEN * num_seeds];
    cipher.apply_keystream(&mut temp_seeds);
    //println!("temp_seeds: {:?}", &temp_seeds[0..16]);
    //println!("--temp_seeds: {:?}", &temp_seeds[16..32]);

    let mut seed_cipher = Aes128Ctr64LE::new(
        (&temp_seeds[32 * seed_index..32 * seed_index + 16]).into(),
        (&temp_seeds[32 * seed_index + 16..32 * seed_index + 32]).into(),
    );
    seed_cipher.apply_keystream(&mut input2[0..E_BYTES * N_PARAM]);

    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    cipher = Aes128Ctr64LE::new(
        (&temp_seeds[32 * seed_index + 16..32 * seed_index + 32]).into(),
        (&temp_seeds[32 * seed_index..32 * seed_index + 16]).into(),
    );

    for i in 0..(len2 / E_BYTES) {
        while (output2[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            //if temp[0]|temp[1]|temp[2]|temp[3] == 0 {
            //    cipher =  Aes128Ctr64LE::new((&temp_seeds[32*(i>>9)+16..32*(i>>9)+32]).into(), (&temp_seeds[32*(i>>9)..32*(i>>9)+16]).into());
            //}
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output2[i] = temp_value as i32;
        }

        output2[i] = output2[i] % Q;
    }
}

/*
This function generated the array of seeds by for each block
Then indivitial (poly) seeds are generated by the block seed
Runs faster than generating all from a single seed

assumes that len2 is a multiple of NUM_BLOCK
 */
pub fn fill_rand_aes128_modq_nr_2_by_seed_sq_block(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    len1: usize,
    len2: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());
    cipher.apply_keystream(&mut input1[0..len1]);

    let output1: &mut [i32] = bytemuck::cast_slice_mut(input1);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len1 / E_BYTES) {
        while (output1[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output1[i] = temp_value as i32;
        }
        output1[i] = output1[i] % Q;
    }

    //////////////////////////////////////////////////////
    let mut temp_block_seeds = vec![0u8; SEED_IV_LEN * NUM_BLOCK];
    cipher.apply_keystream(&mut temp_block_seeds);

    let gen_per_block: usize = len2 / NUM_BLOCK;
    //println!("we want t get {} bytes per block", gen_per_block);
    //println!("should be {}", (4*S_SLICE));
    for blk_i in 0..NUM_BLOCK {
        fill_rand_aes128_modq_nr_1_by_seed_sq(
            &temp_block_seeds[SEED_IV_LEN * blk_i..SEED_IV_LEN * blk_i + 16],
            &temp_block_seeds[SEED_IV_LEN * blk_i + 16..SEED_IV_LEN * blk_i + 32],
            &mut input2[gen_per_block * blk_i..gen_per_block * (blk_i + 1)],
            gen_per_block,
        );
    }
}

/*
This function generated the array of seeds by for each block
Then indivitial (poly) seeds are generated by the block seed
Runs faster than generating all from a single seed

assumes that len2 is a multiple of NUM_BLOCK
 */
pub fn fill_rand_aes128_modq_nr_2_by_seed_sq_block_getsub(
    key: &[u8],
    iv: &[u8],
    input1: &mut [u8],
    input2: &mut [u8],
    len1: usize,
    _len2: usize,
    seed_index: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());
    cipher.apply_keystream(&mut input1[0..len1]);
    //cipher.apply_keystream(&mut input2[0.. len2]);

    let output1: &mut [i32] = bytemuck::cast_slice_mut(input1);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len1 / E_BYTES) {
        while (output1[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0)
                | ((temp[1] as u32) << 8)
                | ((temp[2] as u32) << 16)
                | ((temp[3] as u32) << 24);
            temp_value = temp_value % QU;
            output1[i] = temp_value as i32;
        }
        output1[i] = output1[i] % Q;
    }

    //////////////////////////////////////////////////////
    let mut temp_block_seeds = vec![0u8; SEED_IV_LEN * NUM_BLOCK];
    cipher.apply_keystream(&mut temp_block_seeds);

    let q_blk: usize = seed_index / N_PARAM;
    let q_blk_index: usize = seed_index - q_blk * N_PARAM;

    //println!("q_blk is {}", q_blk);
    //println!("q_blk_index is {}", q_blk_index);
    fill_rand_aes128_modq_nr_1_by_seed_sq_getsub(
        &temp_block_seeds[SEED_IV_LEN * q_blk..SEED_IV_LEN * q_blk + 16],
        &temp_block_seeds[SEED_IV_LEN * q_blk + 16..SEED_IV_LEN * q_blk + 32],
        input2,
        E_BYTES * N_PARAM,
        q_blk_index,
        N_PARAM,
    );
}

pub fn g_func(a_vec: &[i32], s_vec: &[i32], output: &mut [i32]) {
    //ntt::vec_mul_ntru_i32(a_vec, s_vec, output);
    ntt::poly_basemul(output, a_vec, s_vec);
    ntt::poly_invntt(output);
}

pub fn g_func_index(a_vec: &[i32], s_vec: &[i32], output: &mut [i32], ly: usize) {
    //ntt::vec_mul_ntru_i32(a_vec, s_vec, output);
    ntt::poly_basemul_index(output, a_vec, s_vec, ly);
    ntt::poly_invntt_index(output, ly);
}

pub fn g_func_noise(a_vec: &[i32], s_vec: &[i32], output: &mut [i32]) {
    //ntt::vec_mul_ntru_i32(a_vec, s_vec, output);
    ntt::poly_basemul(output, a_vec, s_vec);
    ntt::poly_invntt(output);

    noise::add_noise(output);
    //noise::add_pos_noise(output);
}

pub fn g_func_noise_output(
    a_vec: &[i32],
    s_vec: &[i32],
    output: &mut [i32],
    noise_output: &mut [i32],
) {
    //ntt::vec_mul_ntru_i32(a_vec, s_vec, output);
    ntt::poly_basemul(output, a_vec, s_vec);
    ntt::poly_invntt(output);

    //noise::add_noise_output(output, noise_output);
    noise::add_pos_noise_output(output, noise_output);
}

pub fn g_func_noise_output_sign(
    a_vec: &[i32],
    s_vec: &[i32],
    output: &mut [i32],
    noise_output: &mut [i32],
    noise_sign_i8: &mut [i8],
) {
    //ntt::vec_mul_ntru_i32(a_vec, s_vec, output);
    ntt::poly_basemul(output, a_vec, s_vec);
    ntt::poly_invntt(output);

    noise::add_noise_output_sign(output, noise_output, noise_sign_i8);
    //noise::add_noise_output(output, noise_output);
    //noise::add_pos_noise_output(output, noise_output);
}

#[allow(dead_code)]
pub fn g_func_index_noise(a_vec: &[i32], s_vec: &[i32], output: &mut [i32], ly: usize) {
    //ntt::vec_mul_ntru_i32(a_vec, s_vec, output);
    ntt::poly_basemul_index(output, a_vec, s_vec, ly);
    ntt::poly_invntt_index(output, ly);

    //output[ly] += noise::lwe_add_sample_noise_8_1();
    output[ly] += noise::lwe_add_pos_sample_noise_8_1();
}

/*
pub fn g_func_ntru(a_vec:&[u32], s_vec:&[u32], output:&mut [u32]) {
    ntt::vec_mul_ntru(a_vec, s_vec, output);
}
*/

pub fn dpf_gen_lwe_seed_base(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vecs_u8: &mut [u8],
    s_vecs_1d_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    seeds: &mut [u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    if m >= Q {
        println!("m is too large! {} >= {}\n", m, Q);
        return;
    }

    let lx: usize = l / N_PARAM;
    let ly: usize = l - lx * N_PARAM;

    // --------------------------------------------------------------------------

    {
        let s_star_u8: &mut [u8] = &mut s_vecs_1d_u8[E_BYTES * (s_s(NUM_SERVERS - 1) + lx * N_PARAM)
            ..E_BYTES * (s_s(NUM_SERVERS - 1) + (lx + 1) * N_PARAM)];
        fill_rand_aes128_modq_nr(s_star_u8, E_BYTES * N_PARAM);
    }

    fill_rand_aes128_nr(seeds, SEED_BLOCK);

    for iter in 0..(NUM_SERVERS - 1) {
        fill_rand_aes128_modq_nr_2_by_seed(
            &seeds[32 * iter..32 * iter + 16],
            &seeds[32 * iter + 16..32 * iter + 32],
            &mut b_vecs_u8[E_BYTES * b_s(iter)..E_BYTES * b_s(iter + 1)],
            &mut s_vecs_1d_u8[E_BYTES * s_s(iter)..E_BYTES * s_s(iter + 1)],
            E_BYTES * B_SLICE,
            E_BYTES * S_SLICE,
        );
    }

    let b_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(b_vecs_u8);
    let s_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(s_vecs_1d_u8);

    let s_star: &[i32] =
        &s_vecs_1d[s_s(NUM_SERVERS - 1) + lx * N_PARAM..s_s(NUM_SERVERS - 1) + (lx + 1) * N_PARAM];

    let v_vec: &mut [i32] = bytemuck::cast_slice_mut(v_vec_u8);

    g_func_noise(&a_vec, &s_star, v_vec);

    for i_iter in 0..B_SLICE {
        let mut temp = 0i32;
        for s_iter in 0..(NUM_SERVERS - 1) {
            temp -= b_vecs_1d[b_s(s_iter) + i_iter]
        }
        b_vecs_1d[b_s(NUM_SERVERS - 1) + i_iter] = temp;
    }
    b_vecs_1d[b_s(NUM_SERVERS - 1) + lx] += 1;

    // TODO: did we overwrite s_star?
    for i_iter in 0..S_SLICE {
        let mut temp = s_vecs_1d[s_s(NUM_SERVERS - 1) + i_iter];
        for s_iter in 0..(NUM_SERVERS - 1) {
            temp -= s_vecs_1d[s_s(s_iter) + i_iter]
        }
        s_vecs_1d[s_s(NUM_SERVERS - 1) + i_iter] = temp;
    }

    let (sign, sample) = noise::lwe_add_sample_noise_8_1_decompose();
    let noise = (1 - sign) * sample + sign * (Q - sample);
    //println!("sign is {}, sample is {}, Q is {}, noise is {}",sign, sample, Q,noise);
    //let new_m = noise + m;
    let new_m = noise + m;

    //TODO: rust arrray, do we need to make vec?

    // TODO: is this correct
    for iter in 0..N_PARAM {
        v_vec[iter] = Q - v_vec[iter];
    }
    v_vec[ly] += new_m;
}

pub fn dpf_gen_lwe_seed_sq_base(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vecs_u8: &mut [u8],
    s_vecs_1d_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    seeds: &mut [u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    if m >= Q {
        println!("m is too large! {} >= {}\n", m, Q);
        return;
    }

    let lx: usize = l / N_PARAM;
    let ly: usize = l - lx * N_PARAM;

    // --------------------------------------------------------------------------

    {
        let s_star_u8: &mut [u8] = &mut s_vecs_1d_u8[E_BYTES * (s_s(NUM_SERVERS - 1) + lx * N_PARAM)
            ..E_BYTES * (s_s(NUM_SERVERS - 1) + (lx + 1) * N_PARAM)];
        fill_rand_aes128_modq_nr(s_star_u8, E_BYTES * N_PARAM);
    }

    fill_rand_aes128_nr(seeds, SEED_BLOCK);

    for iter in 0..(NUM_SERVERS - 1) {
        fill_rand_aes128_modq_nr_2_by_seed_sq(
            &seeds[32 * iter..32 * iter + 16],
            &seeds[32 * iter + 16..32 * iter + 32],
            &mut b_vecs_u8[E_BYTES * b_s(iter)..E_BYTES * b_s(iter + 1)],
            &mut s_vecs_1d_u8[E_BYTES * s_s(iter)..E_BYTES * s_s(iter + 1)],
            E_BYTES * B_SLICE,
            E_BYTES * S_SLICE,
        );
    }

    let b_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(b_vecs_u8);
    let s_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(s_vecs_1d_u8);

    let s_star: &[i32] =
        &s_vecs_1d[s_s(NUM_SERVERS - 1) + lx * N_PARAM..s_s(NUM_SERVERS - 1) + (lx + 1) * N_PARAM];

    let v_vec: &mut [i32] = bytemuck::cast_slice_mut(v_vec_u8);

    g_func_noise(&a_vec, &s_star, v_vec);

    for i_iter in 0..B_SLICE {
        let mut temp = 0i32;
        for s_iter in 0..(NUM_SERVERS - 1) {
            temp -= b_vecs_1d[b_s(s_iter) + i_iter]
        }
        b_vecs_1d[b_s(NUM_SERVERS - 1) + i_iter] = temp;
    }
    b_vecs_1d[b_s(NUM_SERVERS - 1) + lx] += 1;

    // TODO: did we overwrite s_star?
    for i_iter in 0..S_SLICE {
        let mut temp = s_vecs_1d[s_s(NUM_SERVERS - 1) + i_iter];
        for s_iter in 0..(NUM_SERVERS - 1) {
            temp -= s_vecs_1d[s_s(s_iter) + i_iter]
        }
        s_vecs_1d[s_s(NUM_SERVERS - 1) + i_iter] = temp;
    }

    let (sign, sample) = noise::lwe_add_sample_noise_8_1_decompose();
    let noise = (1 - sign) * sample + sign * (Q - sample);
    //println!("sign is {}, sample is {}, Q is {}, noise is {}",sign, sample, Q,noise);
    let new_m = noise + m;

    //TODO: rust arrray, do we need to make vec?

    // TODO: is this correct
    for iter in 0..N_PARAM {
        v_vec[iter] = Q - v_vec[iter];
    }
    v_vec[ly] += new_m;
}

#[allow(dead_code)]
pub fn dpf_eval_lwe_base(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    let lx: usize = l / N_PARAM;
    let ly: usize = l - lx * N_PARAM;

    //println!("lx: {} || ly: {}",lx,ly);

    let mut g_expand = vec![0i32; N_PARAM];

    //SPEEDUP
    let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
    let s_star: &[i32] = &s_vecs[lx * N_PARAM..(lx + 1) * N_PARAM];

    //println!("seed is {} {} {}",s_star[0] ,s_star[1] ,s_star[2] );

    // TODO: Fix
    g_func(&a_vec, &s_star, &mut g_expand);
    //g_func_index(&a_vec, &s_star, &mut g_expand, ly);

    let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
    let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

    *m = g_expand[ly] + b_vec[lx] * v_vec[ly];
    //println!("looks like {}+{}*{} = {}",g_expand[ly],b_vec[lx],v_vec[ly],*m);
}

#[allow(dead_code)]
pub fn dpf_eval_lwe_all_base(
    all_output: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
    let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

    let mut g_expand = vec![0i32; N_PARAM];

    //SPEEDUP
    let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
    for lx_iter in 0..N_PARAM {
        let s_star: &[i32] = &s_vecs[lx_iter * N_PARAM..(lx_iter + 1) * N_PARAM];
        g_func(&a_vec, &s_star, &mut g_expand);

        for ly_iter in 0..N_PARAM {
            all_output[lx_iter * N_PARAM + ly_iter] =
                g_expand[ly_iter] + b_vec[lx_iter] * v_vec[ly_iter];
        }
    }
}

#[allow(dead_code)]
pub fn dpf_eval_lwe_all_base_block(
    all_output: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    for bl_iter in 0..NUM_BLOCK {
        dpf_eval_lwe_all_base(
            &mut all_output[bl_iter * M_SLICE..(bl_iter + 1) * M_SLICE],
            &a_vec[bl_iter * N_PARAM..(bl_iter + 1) * N_PARAM],
            &b_vec_u8[bl_iter * E_BYTES * B_SLICE..(bl_iter + 1) * E_BYTES * B_SLICE],
            &s_vec_1d_u8[bl_iter * E_BYTES * S_SLICE..(bl_iter + 1) * E_BYTES * S_SLICE],
            &v_vec_u8[bl_iter * E_BYTES * V_SLICE..(bl_iter + 1) * E_BYTES * V_SLICE],
        );
    }
}

#[allow(dead_code)]
pub fn dpf_eval_lwe_all_base_block_seed(
    all_output: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    fill_rand_aes128_modq_nr_2_by_seed(
        &seed[0..16],
        &seed[16..32],
        b_vec_u8,
        s_vec_1d_u8,
        E_BYTES * B_SLICE * NUM_BLOCK,
        E_BYTES * S_SLICE * NUM_BLOCK,
    );

    for bl_iter in 0..NUM_BLOCK {
        dpf_eval_lwe_all_base(
            &mut all_output[bl_iter * M_SLICE..(bl_iter + 1) * M_SLICE],
            &a_vec[bl_iter * N_PARAM..(bl_iter + 1) * N_PARAM],
            &b_vec_u8[bl_iter * E_BYTES * B_SLICE..(bl_iter + 1) * E_BYTES * B_SLICE],
            &s_vec_1d_u8[bl_iter * E_BYTES * S_SLICE..(bl_iter + 1) * E_BYTES * S_SLICE],
            &v_vec_u8[bl_iter * E_BYTES * V_SLICE..(bl_iter + 1) * E_BYTES * V_SLICE],
        );
    }
}

#[allow(dead_code)]
pub fn dpf_eval_lwe_seed_all_base(
    all_output: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    // expand the seeds
    fill_rand_aes128_modq_nr_2_by_seed(
        &seed[0..16],
        &seed[16..32],
        b_vec_u8,
        s_vec_1d_u8,
        E_BYTES * B_SLICE,
        E_BYTES * S_SLICE,
    );

    let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
    let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

    let mut g_expand = vec![0i32; N_PARAM];

    //SPEEDUP
    let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
    for lx_iter in 0..N_PARAM {
        let s_star: &[i32] = &s_vecs[lx_iter * N_PARAM..(lx_iter + 1) * N_PARAM];
        g_func(&a_vec, &s_star, &mut g_expand);

        for ly_iter in 0..N_PARAM {
            all_output[lx_iter * N_PARAM + ly_iter] =
                g_expand[ly_iter] + b_vec[lx_iter] * v_vec[ly_iter];
        }
    }
}

pub fn dpf_eval_lwe_base_one(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    let lx: usize = l / N_PARAM;
    let ly: usize = l - lx * N_PARAM;

    //println!("lx: {} || ly: {}",lx,ly);

    let mut g_expand = vec![0i32; N_PARAM];

    //SPEEDUP
    let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
    let s_star: &[i32] = &s_vecs[lx * N_PARAM..(lx + 1) * N_PARAM];

    //println!("seed is {} {} {}",s_star[0] ,s_star[1] ,s_star[2] );

    // TODO: Fix
    //g_func(&a_vec, &s_star, &mut g_expand);
    g_func_index(&a_vec, &s_star, &mut g_expand, ly);

    let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
    let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

    *m = g_expand[ly] + b_vec[lx] * v_vec[ly];
    //println!("looks like {}+{}*{} = {}",g_expand[ly],b_vec[lx],v_vec[ly],*m);
}

pub fn dpf_eval_lwe_base_one_sq(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= (DB_SIZE) {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    // moshih check to see if correct
    let lx: usize = l / N_PARAM;
    let ly: usize = l - lx * N_PARAM;

    //println!("lx: {} || ly: {}",lx,ly);

    let mut g_expand = vec![0i32; N_PARAM];

    //SPEEDUP
    let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);

    g_func_index(&a_vec, &s_vecs, &mut g_expand, ly);

    let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
    let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

    let bv: i32 = mul_mod_mont(b_vec[lx], v_vec[ly]);
    *m = g_expand[ly] + bv;
}

pub fn dpf_eval_lwe_base_one_sq_whole_poly(
    l: usize,
    m: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    // N_ROWS or N_PARAM?
    let lx: usize = l / N_PARAM;

    let mut g_expand = vec![0i32; N_PARAM];

    let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
    g_func(&a_vec, &s_vecs, &mut g_expand);

    let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
    let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

    let mut bv_i32: i32;
    for ly_iter in 0..N_PARAM {
        //bv = Wrapping(b_vec[lx]) * Wrapping(v_vec[ly_iter]);
        //m[ly_iter] = g_expand[ly_iter] + bv.0;

        bv_i32 = mul_mod_mont(b_vec[lx], v_vec[ly_iter]);
        m[ly_iter] = g_expand[ly_iter] + bv_i32;
    }
}

#[allow(dead_code)]
pub fn dpf_eval_lwe_seed_base_one(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    let lx: usize = l / N_PARAM;
    let ly: usize = l - lx * N_PARAM;

    //println!("lx: {} || ly: {}",lx,ly);

    let mut g_expand = vec![0i32; N_PARAM];

    // expand the seeds
    //let mut b_vec_u8 = vec![0u8; 4*N_PARAM];
    //let mut s_vec_1d_u8 = vec![0u8; 4*N_PARAM*N_PARAM];

    fill_rand_aes128_modq_nr_2_by_seed(
        &seed[0..16],
        &seed[16..32],
        b_vec_u8,
        s_vec_1d_u8,
        4 * B_SLICE,
        4 * S_SLICE,
    );

    //SPEEDUP
    let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
    let s_star: &[i32] = &s_vecs[lx * N_PARAM..(lx + 1) * N_PARAM];

    // TODO: Fix
    //g_func(&a_vec, &s_star, &mut g_expand);
    g_func_index(&a_vec, &s_star, &mut g_expand, ly);

    let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
    let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

    *m = g_expand[ly] + b_vec[lx] * v_vec[ly];
    //println!("looks like {}+{}*{} = {}",g_expand[ly],b_vec[lx],v_vec[ly],*m);
}

#[allow(dead_code)]
pub fn dpf_eval_lwe_seed_base_one_sq(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    let lx: usize = l / (NUM_BLOCK * N_PARAM);
    let ly: usize = l - lx * (NUM_BLOCK * N_PARAM);

    //println!("lx: {} || ly: {}",lx,ly);

    let mut g_expand = vec![0i32; N_PARAM];

    // expand the seeds
    //let mut b_vec_u8 = vec![0u8; 4*N_PARAM];
    //let mut s_vec_1d_u8 = vec![0u8; 4*N_PARAM*N_PARAM];

    /*
        fill_rand_aes128_modq_nr_2_by_seed(&seed[0..16],&seed[16..32],
            b_vec_u8, s_vec_1d_u8,
            4*B_SLICE, 4*S_SLICE);
    */
    fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(
        &seed[0..16],
        &seed[16..32],
        b_vec_u8,
        &mut s_vec_1d_u8[E_BYTES * N_PARAM * lx..E_BYTES * N_PARAM * (lx + 1)],
        E_BYTES * B_SLICE,
        E_BYTES * N_PARAM,
        lx,
        N_ROWS,
    );

    //SPEEDUP
    let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
    let s_star: &[i32] = &s_vecs[lx * N_PARAM..(lx + 1) * N_PARAM];

    //println!("seed is {} {} {}",s_star[0] ,s_star[1] ,s_star[2] );

    // TODO: Fix
    //g_func(&a_vec, &s_star, &mut g_expand);
    g_func_index(&a_vec, &s_star, &mut g_expand, ly);

    let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
    let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

    *m = g_expand[ly] + b_vec[lx] * v_vec[ly];
    //println!("looks like {}+{}*{} = {}",g_expand[ly],b_vec[lx],v_vec[ly],*m);
}

#[allow(dead_code)]
pub fn dpf_gen_lwe_seed(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vecs_u8: &mut [u8],
    s_vecs_1d_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    seeds: &mut [u8],
) {
    dpf_gen_lwe_seed_base(l, m, a_vec, b_vecs_u8, s_vecs_1d_u8, v_vec_u8, seeds);
}

#[allow(dead_code)]
pub fn dpf_gen_lwe_seed_sq(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vecs_u8: &mut [u8],
    s_vecs_1d_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    seeds: &mut [u8],
) {
    dpf_gen_lwe_seed_sq_base(l, m, a_vec, b_vecs_u8, s_vecs_1d_u8, v_vec_u8, seeds);
}

#[allow(dead_code)]
pub fn dpf_eval_lwe(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    dpf_eval_lwe_base_one(l, m, &a_vec, &b_vec_u8, &s_vec_1d_u8, &v_vec_u8);
}

#[allow(dead_code)]
pub fn dpf_eval_lwe_seed(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    dpf_eval_lwe_seed_base_one(l, m, &a_vec, b_vec_u8, s_vec_1d_u8, &seed, &v_vec_u8);
}

#[allow(dead_code)]
pub fn dpf_eval_lwe_seed_sq(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    dpf_eval_lwe_seed_base_one_sq(l, m, &a_vec, b_vec_u8, s_vec_1d_u8, &seed, &v_vec_u8);
}

#[allow(dead_code)]
pub fn dpf_gen_lwe_seed_block_new(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vecs_u8: &mut [u8],
    s_vecs_1d_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    seeds: &mut [u8],
) {
    let block_num = l / (N_PARAM * N_PARAM);
    let block_l = l % (N_PARAM * N_PARAM);

    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    if m >= Q {
        println!("m is too large! {} >= {}\n", m, Q);
        return;
    }

    let block_lx: usize = block_l / N_PARAM;
    let block_ly: usize = block_l - block_lx * N_PARAM;

    // --------------------------------------------------------------------------

    {
        let s_star_u8: &mut [u8] = &mut s_vecs_1d_u8[E_BYTES
            * (NUM_BLOCK * s_s(NUM_SERVERS - 1) + block_lx * N_PARAM)
            ..E_BYTES * (NUM_BLOCK * s_s(NUM_SERVERS - 1) + (block_lx + 1) * N_PARAM)];
        fill_rand_aes128_modq_nr(s_star_u8, E_BYTES * N_PARAM);
    }

    fill_rand_aes128_nr(seeds, SEED_BLOCK);

    for iter in 0..(NUM_SERVERS - 1) {
        fill_rand_aes128_modq_nr_2_by_seed(
            &seeds[32 * iter..32 * iter + 16],
            &seeds[32 * iter + 16..32 * iter + 32],
            &mut b_vecs_u8[4 * NUM_BLOCK * b_s(iter)..E_BYTES * NUM_BLOCK * b_s(iter + 1)],
            &mut s_vecs_1d_u8[4 * NUM_BLOCK * s_s(iter)..E_BYTES * NUM_BLOCK * s_s(iter + 1)],
            E_BYTES * B_SLICE * NUM_BLOCK,
            E_BYTES * S_SLICE * NUM_BLOCK,
        );
    }

    let b_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(b_vecs_u8);
    let s_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(s_vecs_1d_u8);

    let s_star: &[i32] =
        &s_vecs_1d[s_s(NUM_SERVERS - 1) * NUM_BLOCK + block_num * S_SLICE + block_lx * N_PARAM
            ..s_s(NUM_SERVERS - 1) * NUM_BLOCK + block_num * S_SLICE + (block_lx + 1) * N_PARAM];

    let v_vec: &mut [i32] = bytemuck::cast_slice_mut(v_vec_u8);

    for iter in 0..NUM_BLOCK {
        g_func_noise(
            &a_vec[A_SLICE * iter..A_SLICE * (iter + 1)],
            &s_star,
            &mut v_vec[V_SLICE * iter..V_SLICE * (iter + 1)],
        );
    }

    for bl_iter in 0..NUM_BLOCK {
        for i_iter in 0..B_SLICE {
            let mut temp = 0i32;
            for s_iter in 0..(NUM_SERVERS - 1) {
                temp -= b_vecs_1d[NUM_BLOCK * b_s(s_iter) + bl_iter * B_SLICE + i_iter]
            }
            b_vecs_1d[NUM_BLOCK * b_s(NUM_SERVERS - 1) + bl_iter * B_SLICE + i_iter] = temp;
        }
        b_vecs_1d[NUM_BLOCK * b_s(NUM_SERVERS - 1) + bl_iter * B_SLICE + block_lx] += 1;

        for i_iter in 0..S_SLICE {
            let mut temp = s_vecs_1d[NUM_BLOCK * s_s(NUM_SERVERS - 1) + bl_iter * S_SLICE + i_iter];
            for s_iter in 0..(NUM_SERVERS - 1) {
                temp -= s_vecs_1d[NUM_BLOCK * s_s(s_iter) + bl_iter * S_SLICE + i_iter]
            }
            s_vecs_1d[NUM_BLOCK * s_s(NUM_SERVERS - 1) + bl_iter * S_SLICE + i_iter] = temp;
        }
    }

    let (sign, sample) = noise::lwe_add_sample_noise_8_1_decompose();
    let noise = (1 - sign) * sample + sign * (Q - sample);
    //println!("sign is {}, sample is {}, Q is {}, noise is {}",sign, sample, Q,noise);
    let new_m = noise + m;

    for bl_iter in 0..NUM_BLOCK {
        for iter in 0..N_PARAM {
            v_vec[V_SLICE * bl_iter + iter] = Q - v_vec[V_SLICE * bl_iter + iter];
        }
    }
    v_vec[V_SLICE * block_num + block_ly] += new_m;
}

pub fn dpf_gen_lwe_seed_block_new_sq(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vecs_u8: &mut [u8],
    s_vecs_1d_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    seeds: &mut [u8],
) {
    let block_num = l / (N_PARAM * N_PARAM);
    let block_l = l % (N_PARAM * N_PARAM);

    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    if m >= Q {
        println!("m is too large! {} >= {}\n", m, Q);
        return;
    }

    let block_lx: usize = block_l / N_PARAM;
    let block_ly: usize = block_l - block_lx * N_PARAM;

    // --------------------------------------------------------------------------

    {
        let s_star_u8: &mut [u8] = &mut s_vecs_1d_u8[E_BYTES
            * (s_s(NUM_SERVERS - 1) + block_lx * N_PARAM)
            ..E_BYTES * (s_s(NUM_SERVERS - 1) + (block_lx + 1) * N_PARAM)];
        fill_rand_aes128_modq_nr(s_star_u8, E_BYTES * N_PARAM);
    }

    fill_rand_aes128_nr(seeds, SEED_BLOCK);

    for iter in 0..(NUM_SERVERS - 1) {
        /*
                let mut temp_seeds = vec![0u8; SEED_IV_LEN*NUM_BLOCK];

                type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
                let mut block_seed_cipher = Aes128Ctr64LE::new((&seeds[32*iter..32*iter+16]).into(),
                    (&seeds[32*iter+16..32*iter+32]).into());
                block_seed_cipher.apply_keystream(&mut temp_seeds);
        */
        fill_rand_aes128_modq_nr_2_by_seed_sq(
            &seeds[32 * iter..32 * iter + 16],
            &seeds[32 * iter + 16..32 * iter + 32],
            &mut b_vecs_u8[E_BYTES * b_s(iter)..E_BYTES * b_s(iter + 1)],
            &mut s_vecs_1d_u8[E_BYTES * s_s(iter)..E_BYTES * s_s(iter + 1)],
            E_BYTES * B_SLICE,
            E_BYTES * S_SLICE,
        );
    }

    let b_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(b_vecs_u8);
    let s_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(s_vecs_1d_u8);

    let s_star: &[i32] = &s_vecs_1d[s_s(NUM_SERVERS - 1) + block_lx * N_PARAM
        ..s_s(NUM_SERVERS - 1) + (block_lx + 1) * N_PARAM];

    let v_vec: &mut [i32] = bytemuck::cast_slice_mut(v_vec_u8);

    for iter in 0..NUM_BLOCK {
        g_func_noise(
            &a_vec[A_SLICE * iter..A_SLICE * (iter + 1)],
            &s_star,
            &mut v_vec[V_SLICE * iter..V_SLICE * (iter + 1)],
        );
    }

    for i_iter in 0..B_SLICE {
        let mut temp = 0i32;
        for s_iter in 0..(NUM_SERVERS - 1) {
            temp -= b_vecs_1d[b_s(s_iter) + i_iter]
        }
        b_vecs_1d[b_s(NUM_SERVERS - 1) + i_iter] = temp;
    }
    //b_vecs_1d[NUM_BLOCK*b_s(NUM_SERVERS-1)+bl_iter*B_SLICE+block_lx] += 1;

    for i_iter in 0..S_SLICE {
        let mut temp = s_vecs_1d[s_s(NUM_SERVERS - 1) + i_iter];
        for s_iter in 0..(NUM_SERVERS - 1) {
            temp -= s_vecs_1d[s_s(s_iter) + i_iter]
        }
        s_vecs_1d[s_s(NUM_SERVERS - 1) + i_iter] = temp;
    }

    b_vecs_1d[b_s(NUM_SERVERS - 1) + block_lx] += 1;

    let (sign, sample) = noise::lwe_add_sample_noise_8_1_decompose();
    let noise = (1 - sign) * sample + sign * (Q - sample);
    //println!("sign is {}, sample is {}, Q is {}, noise is {}",sign, sample, Q,noise);
    let new_m = noise + m;

    for bl_iter in 0..NUM_BLOCK {
        for iter in 0..N_PARAM {
            v_vec[V_SLICE * bl_iter + iter] = Q - v_vec[V_SLICE * bl_iter + iter];
        }
    }
    v_vec[V_SLICE * block_num + block_ly] += new_m;
}

#[allow(dead_code)]
pub fn dpf_gen_lwe_seed_block_new_sq_compact(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    seeds: &mut [u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= (DB_SIZE) {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    if m >= Q {
        println!("m is too large! {} >= {}\n", m, Q);
        return;
    }

    let block_num = l / (N_PARAM * N_ROWS);
    let block_l = l % (N_PARAM * N_ROWS);

    //let block_lx = l/(NUM_BLOCK*N_PARAM);
    //let block_ly = l%(NUM_BLOCK*N_PARAM);

    let block_lx: usize = block_l / N_PARAM;
    let block_ly: usize = block_l - block_lx * N_PARAM;

    {
        let s_star_u8: &mut [u8] =
            &mut s_vec_u8[E_BYTES * block_lx * N_PARAM..E_BYTES * (block_lx + 1) * N_PARAM];
        fill_rand_aes128_modq_nr(s_star_u8, E_BYTES * N_PARAM);
    }

    fill_rand_aes128_nr(seeds, SEED_BLOCK);

    let b_vec: &mut [i32] = bytemuck::cast_slice_mut(b_vec_u8);
    let s_vec: &mut [i32] = bytemuck::cast_slice_mut(s_vec_u8);

    let s_star: &[i32] = &s_vec[block_lx * N_PARAM..(block_lx + 1) * N_PARAM];

    let v_vec: &mut [i32] = bytemuck::cast_slice_mut(v_vec_u8);

    for iter in 0..BLOCKS {
        g_func_noise(
            &a_vec[N_PARAM * iter..N_PARAM * (iter + 1)],
            &s_star,
            &mut v_vec[N_PARAM * iter..N_PARAM * (iter + 1)],
        );
    }

    let mut b_vec_u8_temp = vec![0u8; E_BYTES * B_SLICE];
    let mut s_vec_u8_temp = vec![0u8; E_BYTES * S_SLICE];

    // TODO: FIX for compact
    for iter in 0..(NUM_SERVERS - 1) {
        fill_rand_aes128_modq_nr_2_by_seed_sq(
            &seeds[32 * iter..32 * iter + 16],
            &seeds[32 * iter + 16..32 * iter + 32],
            &mut b_vec_u8_temp[..],
            &mut s_vec_u8_temp[..],
            E_BYTES * B_SLICE,
            E_BYTES * S_SLICE,
        );

        let b_vec_temp: &mut [i32] = bytemuck::cast_slice_mut(&mut b_vec_u8_temp[..]);
        let s_vec_temp: &mut [i32] = bytemuck::cast_slice_mut(&mut s_vec_u8_temp[..]);

        for iter in 0..B_SLICE {
            b_vec[iter] -= b_vec_temp[iter];
        }

        for iter in 0..S_SLICE {
            s_vec[iter] -= s_vec_temp[iter];
        }

        //b_vec_temp.fill(0);
        //s_vec_temp.fill(0);
        for i in 0..b_vec_temp.len() {
            b_vec_temp[i] = 0;
        }
        for i in 0..s_vec_temp.len() {
            s_vec_temp[i] = 0;
        }
    }
    b_vec[block_lx] += 1;

    /*
    let (sign, sample) = noise::lwe_add_sample_noise_8_1_decompose();
    let noise = (1 - sign) * sample + sign * (Q - sample);
    //println!("sign is {}, sample is {}, Q is {}, noise is {}",sign, sample, Q,noise);
    let new_m = noise + m;
     */

    let new_m = m;

    for iter in 0..V_SLICE {
        v_vec[iter] = Q - v_vec[iter];
    }

    v_vec[N_PARAM * block_num + block_ly] += new_m;
}

#[allow(dead_code)]
pub fn dpf_gen_lwe_seed_block_new_sq_compact_snip(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    noise_vec: &mut [i32],
    seeds: &mut [u8],
    snip_seeds: &mut [u8],
    enable_snip: bool,
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
    }

    if m >= Q {
        println!("m is too large! {} >= {}\n", m, Q);
    }

    let block_num = l / (N_PARAM * N_PARAM);
    let block_l = l % (N_PARAM * N_PARAM);

    //let block_lx = l/(NUM_BLOCK*N_PARAM);
    //let block_ly = l%(NUM_BLOCK*N_PARAM);

    let block_lx: usize = block_l / N_PARAM;
    let block_ly: usize = block_l - block_lx * N_PARAM;

    {
        let s_star_u8: &mut [u8] =
            &mut s_vec_u8[E_BYTES * block_lx * N_PARAM..E_BYTES * (block_lx + 1) * N_PARAM];
        fill_rand_aes128_modq_nr(s_star_u8, E_BYTES * N_PARAM);
    }

    fill_rand_aes128_nr(seeds, SEED_BLOCK);

    let b_vec: &mut [i32] = bytemuck::cast_slice_mut(b_vec_u8);
    let s_vec: &mut [i32] = bytemuck::cast_slice_mut(s_vec_u8);

    let s_star: &[i32] = &s_vec[block_lx * N_PARAM..(block_lx + 1) * N_PARAM];

    let v_vec: &mut [i32] = bytemuck::cast_slice_mut(v_vec_u8);

    for iter in 0..NUM_BLOCK {
        if enable_snip {
            g_func_noise_output(
                &a_vec[A_SLICE * iter..A_SLICE * (iter + 1)],
                &s_star,
                &mut v_vec[V_SLICE * iter..V_SLICE * (iter + 1)],
                &mut noise_vec[V_SLICE * iter..V_SLICE * (iter + 1)],
            );
        } else {
            g_func_noise(
                &a_vec[A_SLICE * iter..A_SLICE * (iter + 1)],
                &s_star,
                &mut v_vec[V_SLICE * iter..V_SLICE * (iter + 1)],
            );
        }
    }

    let mut rx_seed = [0u8; SEED_IV_LEN];
    let mut st_seed = [0u8; SEED_IV_LEN];
    let mut sa_seed = [0u8; SEED_IV_LEN];
    if enable_snip {
        gen_rand_coeff_seeds(snip_seeds, &mut rx_seed, &mut st_seed, &mut sa_seed);
    }

    let mut b_vec_u8_temp = vec![0u8; E_BYTES * N_PARAM];
    let mut s_vec_u8_temp = vec![0u8; E_BYTES * N_PARAM * N_PARAM];

    // TODO: FIX for compact
    for iter in 0..(NUM_SERVERS - 1) {
        fill_rand_aes128_modq_nr_2_by_seed_sq(
            &seeds[32 * iter..32 * iter + 16],
            &seeds[32 * iter + 16..32 * iter + 32],
            &mut b_vec_u8_temp[..],
            &mut s_vec_u8_temp[..],
            E_BYTES * B_SLICE,
            E_BYTES * S_SLICE,
        );

        let b_vec_temp: &mut [i32] = bytemuck::cast_slice_mut(&mut b_vec_u8_temp[..]);
        let s_vec_temp: &mut [i32] = bytemuck::cast_slice_mut(&mut s_vec_u8_temp[..]);

        for iter in 0..B_SLICE {
            b_vec[iter] = b_vec[iter] - b_vec_temp[iter];
        }

        for iter in 0..S_SLICE {
            s_vec[iter] = s_vec[iter] - s_vec_temp[iter];
        }

        //b_vec_temp.fill(0);
        //s_vec_temp.fill(0);
        for i in 0..b_vec_temp.len() {
            b_vec_temp[i] = 0;
        }
        for i in 0..s_vec_temp.len() {
            s_vec_temp[i] = 0;
        }
    }
    b_vec[block_lx] += 1;

    for iter in 0..B_SLICE {
        b_vec[iter] = barrett_reduce(b_vec[iter]);
    }
    for iter in 0..S_SLICE {
        s_vec[iter] = barrett_reduce(s_vec[iter]);
    }

    //let (sign, sample) = noise::lwe_add_sample_noise_8_1_decompose();
    //let noise = (1 - sign) * sample + sign * (Q - sample);
    //let new_m = noise + m;
    let new_m = m;

    for iter in 0..NUM_BLOCK * N_PARAM {
        v_vec[iter] = Q - v_vec[iter];
    }

    v_vec[V_SLICE * block_num + block_ly] += new_m;
}

pub fn dpf_gen_lwe_seed_block_new_sq_compact_veri(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    noise_vec: &mut [i32],
    noise_sign_i8: &mut [i8],
    seeds: &mut [u8],
    coeff_seeds: &mut [u8],
    enable_veri: bool,
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
    }

    if m >= Q {
        println!("m is too large! {} >= {}\n", m, Q);
    }

    let block_num = l / (N_PARAM * N_ROWS);
    let block_l = l % (N_PARAM * N_ROWS);

    let block_lx: usize = block_l / N_PARAM;
    let block_ly: usize = block_l - block_lx * N_PARAM;

    {
        let s_star_u8: &mut [u8] =
            &mut s_vec_u8[E_BYTES * block_lx * N_PARAM..E_BYTES * (block_lx + 1) * N_PARAM];
        fill_rand_aes128_modq_nr(s_star_u8, E_BYTES * N_PARAM);
    }

    fill_rand_aes128_nr(seeds, SEED_BLOCK);

    let b_vec: &mut [i32] = bytemuck::cast_slice_mut(b_vec_u8);
    let s_vec: &mut [i32] = bytemuck::cast_slice_mut(s_vec_u8);

    let s_star: &[i32] = &s_vec[block_lx * N_PARAM..(block_lx + 1) * N_PARAM];

    let v_vec: &mut [i32] = bytemuck::cast_slice_mut(v_vec_u8);

    for iter in 0..BLOCKS {
        if enable_veri {
            g_func_noise_output_sign(
                &a_vec[N_PARAM * iter..N_PARAM * (iter + 1)],
                &s_star,
                &mut v_vec[N_PARAM * iter..N_PARAM * (iter + 1)],
                &mut noise_vec[N_PARAM * iter..N_PARAM * (iter + 1)],
                &mut noise_sign_i8[N_PARAM * iter..N_PARAM * (iter + 1)],
            );
        } else {
            g_func_noise(
                &a_vec[A_SLICE * iter..A_SLICE * (iter + 1)],
                &s_star,
                &mut v_vec[V_SLICE * iter..V_SLICE * (iter + 1)],
            );
        }
    }

    let mut rx_seed = [0u8; SEED_IV_LEN];
    let mut st_seed = [0u8; SEED_IV_LEN];
    let mut sa_seed = [0u8; SEED_IV_LEN];
    if enable_veri {
        gen_rand_coeff_seeds(coeff_seeds, &mut rx_seed, &mut st_seed, &mut sa_seed);
    }

    let mut b_vec_u8_temp = vec![0u8; E_BYTES * B_SLICE];
    let mut s_vec_u8_temp = vec![0u8; E_BYTES * S_SLICE];

    for iter in 0..(NUM_SERVERS - 1) {
        fill_rand_aes128_modq_nr_2_by_seed_sq(
            &seeds[32 * iter..32 * iter + 16],
            &seeds[32 * iter + 16..32 * iter + 32],
            &mut b_vec_u8_temp[..],
            &mut s_vec_u8_temp[..],
            E_BYTES * B_SLICE,
            E_BYTES * S_SLICE,
        );

        let b_vec_temp: &mut [i32] = bytemuck::cast_slice_mut(&mut b_vec_u8_temp[..]);
        let s_vec_temp: &mut [i32] = bytemuck::cast_slice_mut(&mut s_vec_u8_temp[..]);

        for iter in 0..B_SLICE {
            b_vec[iter] = b_vec[iter] - b_vec_temp[iter];
        }

        for iter in 0..S_SLICE {
            s_vec[iter] = s_vec[iter] - s_vec_temp[iter];
        }

        //b_vec_temp.fill(0);
        //s_vec_temp.fill(0);
        for i in 0..b_vec_temp.len() {
            b_vec_temp[i] = 0;
        }
        for i in 0..s_vec_temp.len() {
            s_vec_temp[i] = 0;
        }
    }
    b_vec[block_lx] += 1;

    for iter in 0..B_SLICE {
        b_vec[iter] = barrett_reduce(b_vec[iter]);
    }
    for iter in 0..S_SLICE {
        s_vec[iter] = barrett_reduce(s_vec[iter]);
    }

    let new_m = m;

    for iter in 0..V_SLICE {
        v_vec[iter] = Q - v_vec[iter];
    }

    v_vec[N_PARAM * block_num + block_ly] += new_m;
}

#[allow(dead_code)]
pub fn dpf_gen_lwe_seed_block_new_sq_double_expand_compact(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    seeds: &mut [u8],
) {
    let block_num = l / (N_PARAM * N_PARAM);
    let block_l = l % (N_PARAM * N_PARAM);

    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    if m >= Q {
        println!("m is too large! {} >= {}\n", m, Q);
        return;
    }

    let block_lx: usize = block_l / N_PARAM;
    let block_ly: usize = block_l - block_lx * N_PARAM;

    // --------------------------------------------------------------------------

    {
        let s_star_u8: &mut [u8] =
            &mut s_vec_u8[E_BYTES * block_lx * N_PARAM..E_BYTES * (block_lx + 1) * N_PARAM];
        fill_rand_aes128_modq_nr(s_star_u8, E_BYTES * N_PARAM);
    }

    fill_rand_aes128_nr(seeds, SEED_BLOCK);

    let b_vec: &mut [i32] = bytemuck::cast_slice_mut(b_vec_u8);
    let s_vec: &mut [i32] = bytemuck::cast_slice_mut(s_vec_u8);

    let s_star: &[i32] = &s_vec
        [block_num * S_SLICE + block_lx * N_PARAM..block_num * S_SLICE + (block_lx + 1) * N_PARAM];

    let v_vec: &mut [i32] = bytemuck::cast_slice_mut(v_vec_u8);

    for iter in 0..NUM_BLOCK {
        g_func_noise(
            &a_vec[A_SLICE * iter..A_SLICE * (iter + 1)],
            &s_star,
            &mut v_vec[V_SLICE * iter..V_SLICE * (iter + 1)],
        );
    }

    let mut b_vec_u8_temp = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];
    let mut s_vec_u8_temp = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM * N_PARAM];

    // TODO: FIX for compact
    for iter in 0..(NUM_SERVERS - 1) {
        fill_rand_aes128_modq_nr_2_by_seed_sq_block(
            &seeds[32 * iter..32 * iter + 16],
            &seeds[32 * iter + 16..32 * iter + 32],
            &mut b_vec_u8_temp[..],
            &mut s_vec_u8_temp[..],
            E_BYTES * B_SLICE * NUM_BLOCK,
            E_BYTES * S_SLICE * NUM_BLOCK,
        );

        let b_vec_temp: &mut [i32] = bytemuck::cast_slice_mut(&mut b_vec_u8_temp[..]);
        let s_vec_temp: &mut [i32] = bytemuck::cast_slice_mut(&mut s_vec_u8_temp[..]);

        for iter in 0..NUM_BLOCK * B_SLICE {
            b_vec[iter] -= b_vec_temp[iter];
        }

        for iter in 0..NUM_BLOCK * S_SLICE {
            s_vec[iter] -= s_vec_temp[iter];
        }

        //b_vec_temp.fill(0);
        //s_vec_temp.fill(0);
        for i in 0..b_vec_temp.len() {
            b_vec_temp[i] = 0;
        }
        for i in 0..s_vec_temp.len() {
            s_vec_temp[i] = 0;
        }
    }
    b_vec[block_num * B_SLICE + block_lx] += 1;

    let (sign, sample) = noise::lwe_add_sample_noise_8_1_decompose();
    let noise = (1 - sign) * sample + sign * (Q - sample);
    //println!("sign is {}, sample is {}, Q is {}, noise is {}",sign, sample, Q,noise);
    let new_m = noise + m;

    for iter in 0..NUM_BLOCK * N_PARAM {
        v_vec[iter] = Q - v_vec[iter];
    }

    v_vec[V_SLICE * block_num + block_ly] += new_m;
}

#[allow(dead_code)]
pub fn dpf_gen_lwe_seed_block_new_sq_double_expand(
    l: usize,
    m: i32,
    a_vec: &[i32],
    b_vecs_u8: &mut [u8],
    s_vecs_1d_u8: &mut [u8],
    v_vec_u8: &mut [u8],
    seeds: &mut [u8],
) {
    let block_num = l / (N_PARAM * N_PARAM);
    let block_l = l % (N_PARAM * N_PARAM);

    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    if m >= Q {
        println!("m is too large! {} >= {}\n", m, Q);
        return;
    }

    let block_lx: usize = block_l / N_PARAM;
    let block_ly: usize = block_l - block_lx * N_PARAM;

    // --------------------------------------------------------------------------

    {
        let s_star_u8: &mut [u8] = &mut s_vecs_1d_u8[E_BYTES
            * (NUM_BLOCK * s_s(NUM_SERVERS - 1) + block_lx * N_PARAM)
            ..E_BYTES * (NUM_BLOCK * s_s(NUM_SERVERS - 1) + (block_lx + 1) * N_PARAM)];
        fill_rand_aes128_modq_nr(s_star_u8, E_BYTES * N_PARAM);
    }

    fill_rand_aes128_nr(seeds, SEED_BLOCK);

    for iter in 0..(NUM_SERVERS - 1) {
        /*
                let mut temp_seeds = vec![0u8; SEED_IV_LEN*NUM_BLOCK];

                type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
                let mut block_seed_cipher = Aes128Ctr64LE::new((&seeds[32*iter..32*iter+16]).into(),
                    (&seeds[32*iter+16..32*iter+32]).into());
                block_seed_cipher.apply_keystream(&mut temp_seeds);
        */
        fill_rand_aes128_modq_nr_2_by_seed_sq_block(
            &seeds[32 * iter..32 * iter + 16],
            &seeds[32 * iter + 16..32 * iter + 32],
            &mut b_vecs_u8[E_BYTES * NUM_BLOCK * b_s(iter)..E_BYTES * NUM_BLOCK * b_s(iter + 1)],
            &mut s_vecs_1d_u8[E_BYTES * NUM_BLOCK * s_s(iter)..E_BYTES * NUM_BLOCK * s_s(iter + 1)],
            E_BYTES * B_SLICE * NUM_BLOCK,
            E_BYTES * S_SLICE * NUM_BLOCK,
        );
    }

    let b_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(b_vecs_u8);
    let s_vecs_1d: &mut [i32] = bytemuck::cast_slice_mut(s_vecs_1d_u8);

    let s_star: &[i32] =
        &s_vecs_1d[s_s(NUM_SERVERS - 1) * NUM_BLOCK + block_num * S_SLICE + block_lx * N_PARAM
            ..s_s(NUM_SERVERS - 1) * NUM_BLOCK + block_num * S_SLICE + (block_lx + 1) * N_PARAM];

    let v_vec: &mut [i32] = bytemuck::cast_slice_mut(v_vec_u8);

    for iter in 0..NUM_BLOCK {
        g_func_noise(
            &a_vec[A_SLICE * iter..A_SLICE * (iter + 1)],
            &s_star,
            &mut v_vec[V_SLICE * iter..V_SLICE * (iter + 1)],
        );
    }

    for bl_iter in 0..NUM_BLOCK {
        for i_iter in 0..B_SLICE {
            let mut temp = 0i32;
            for s_iter in 0..(NUM_SERVERS - 1) {
                temp -= b_vecs_1d[NUM_BLOCK * b_s(s_iter) + bl_iter * B_SLICE + i_iter]
            }
            b_vecs_1d[NUM_BLOCK * b_s(NUM_SERVERS - 1) + bl_iter * B_SLICE + i_iter] = temp;
        }
        b_vecs_1d[NUM_BLOCK * b_s(NUM_SERVERS - 1) + bl_iter * B_SLICE + block_lx] += 1;

        for i_iter in 0..S_SLICE {
            let mut temp = s_vecs_1d[NUM_BLOCK * s_s(NUM_SERVERS - 1) + bl_iter * S_SLICE + i_iter];
            for s_iter in 0..(NUM_SERVERS - 1) {
                temp -= s_vecs_1d[NUM_BLOCK * s_s(s_iter) + bl_iter * S_SLICE + i_iter]
            }
            s_vecs_1d[NUM_BLOCK * s_s(NUM_SERVERS - 1) + bl_iter * S_SLICE + i_iter] = temp;
        }
    }
    b_vecs_1d[NUM_BLOCK * b_s(NUM_SERVERS - 1) + block_num * B_SLICE + block_lx] += 1;

    let (sign, sample) = noise::lwe_add_sample_noise_8_1_decompose();
    let noise = (1 - sign) * sample + sign * (Q - sample);
    //println!("sign is {}, sample is {}, Q is {}, noise is {}",sign, sample, Q,noise);
    let new_m = noise + m;

    for bl_iter in 0..NUM_BLOCK {
        for iter in 0..N_PARAM {
            v_vec[V_SLICE * bl_iter + iter] = Q - v_vec[V_SLICE * bl_iter + iter];
        }
    }
    v_vec[V_SLICE * block_num + block_ly] += new_m;
}

pub fn dpf_eval_lwe_seed_block(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    let block_num: usize = l / (N_PARAM * N_ROWS);
    let block_l: usize = l % (N_PARAM * N_ROWS);

    let block_lx: usize = block_l / N_PARAM;

    fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(
        &seed[0..16],
        &seed[16..32],
        b_vec_u8,
        s_vec_1d_u8,
        E_BYTES * B_SLICE,
        E_BYTES * S_SLICE,
        block_lx,
        N_ROWS,
    );

    dpf_eval_lwe_base_one_sq(
        block_l,
        m,
        &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
        &b_vec_u8[..],
        &s_vec_1d_u8[..],
        &v_vec_u8[block_num * E_BYTES * N_PARAM..(block_num + 1) * E_BYTES * N_PARAM],
    );
}

pub fn dpf_eval_lwe_seed_block_get_bs(
    l: usize,
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
) {
    let block_num: usize = l / (N_PARAM * N_ROWS);
    let block_l: usize = l % (N_PARAM * N_ROWS);

    let block_lx: usize = block_l / N_PARAM;

    fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(
        &seed[0..16],
        &seed[16..32],
        b_vec_u8,
        s_vec_1d_u8,
        E_BYTES * B_SLICE,
        E_BYTES * S_SLICE,
        block_lx,
        N_ROWS,
    );
}

/*
#[allow(dead_code)]
pub fn dpf_eval_lwe_seed_block_double_expand(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    let block_num = l / (N_PARAM * N_PARAM);
    let block_l = l % (N_PARAM * N_PARAM);

    let seed_num = l / (N_PARAM);

    fill_rand_aes128_modq_nr_2_by_seed_sq_block_getsub(
        &seed[0..16],
        &seed[16..32],
        b_vec_u8,
        s_vec_1d_u8,
        E_BYTES * B_SLICE,
        E_BYTES * N_PARAM,
        seed_num,
    );
    dpf_eval_lwe_base_one_sq(
        block_l,
        m,
        &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
        &b_vec_u8[block_num * E_BYTES * B_SLICE..(block_num + 1) * E_BYTES * B_SLICE],
        &s_vec_1d_u8[0..E_BYTES * S_SLICE],
        &v_vec_u8[block_num * E_BYTES * V_SLICE..(block_num + 1) * E_BYTES * V_SLICE],
    );

    /*

        fill_rand_aes128_modq_nr_2_by_seed(&seed[0..16],&seed[16..32],
            b_vec_u8,
            s_vec_1d_u8,
            4*B_SLICE*NUM_BLOCK, 4*S_SLICE*NUM_BLOCK);

        dpf_eval_lwe_base_one(block_l, m
            , &a_vec[block_num*N_PARAM..(block_num+1)*N_PARAM]
            , &b_vec_u8[block_num*4*B_SLICE..(block_num+1)*4*B_SLICE]
            , &s_vec_1d_u8[block_num*4*S_SLICE..(block_num+1)*4*S_SLICE]
            ,  &v_vec_u8[block_num*4*V_SLICE..(block_num+1)*4*V_SLICE]);
    */
}

 */

#[allow(dead_code)]
pub fn dpf_eval_lwe_block_new(
    l: usize,
    m: &mut i32,
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    //let block_num = l/(NUM_BLOCK*N_PARAM);
    //let block_l = l%(NUM_BLOCK*N_PARAM);
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    if l >= DB_SIZE {
        println!("l is too large! {} >= {}\n", l, DB_SIZE);
        return;
    }

    let block_num = l / (N_PARAM * N_ROWS);
    let block_l = l % (N_PARAM * N_ROWS);

    let block_lx: usize = block_l / N_PARAM;
    let block_ly: usize = block_l - block_lx * N_PARAM;

    //SPEEDUP
    let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
    let s_star: &[i32] = &s_vecs[block_lx * N_PARAM..(block_lx + 1) * N_PARAM];

    let mut g_expand = vec![0i32; N_PARAM];
    g_func_index(
        &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
        &s_star,
        &mut g_expand,
        block_ly,
    );

    let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
    let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

    //*m = g_expand[block_ly]+b_vec[block_lx]*v_vec[V_SLICE*block_num+block_ly];

    //let bv = Wrapping(b_vec[block_lx]) * Wrapping(v_vec[V_SLICE * block_num + block_ly]);
    //*m = g_expand[block_ly] + bv.0;

    let bv: i32 = mul_mod_mont(b_vec[block_lx], v_vec[N_PARAM * block_num + block_ly]);
    *m = g_expand[block_ly] + bv;
}

// used by the single server that has the full uncompressed vectors
#[allow(dead_code)]
pub fn dpf_eval_lwe_block_new_all(
    m: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }

    for l_iter in (0..N_PARAM * N_PARAM * NUM_BLOCK).step_by(N_PARAM) {
        let block_num = l_iter / (N_PARAM * N_PARAM);
        let block_l = l_iter % (N_PARAM * N_PARAM);

        let block_lx: usize = block_l / N_PARAM;

        //SPEEDUP
        let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
        let s_star: &[i32] = &s_vecs[block_lx * N_PARAM..(block_lx + 1) * N_PARAM];

        let mut g_expand = vec![0i32; N_PARAM];
        g_func(
            &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
            &s_star,
            &mut g_expand,
        );

        let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
        let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

        let mut bv_i32: i32;
        for ly_iter in 0..N_PARAM {
            //bv = Wrapping(b_vec[block_lx]) * Wrapping(v_vec[V_SLICE * block_num + ly_iter]);
            //m[ly_iter+block_num*N_PARAM*N_PARAM+block_lx*N_PARAM] = g_expand[ly_iter] + bv.0;

            bv_i32 = mul_mod_mont(b_vec[block_lx], v_vec[V_SLICE * block_num + ly_iter]);
            m[ly_iter + block_num * N_PARAM * N_PARAM + block_lx * N_PARAM] =
                g_expand[ly_iter] + bv_i32;
        }
    }
}

// used by the single server that has the full uncompressed vectors
// this produces N_PARAM parts
pub fn dpf_eval_lwe_block_new_all_sub(
    index: usize,
    m: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }
    //for l_iter in (0..N_PARAM * N_PARAM * NUM_BLOCK).step_by(N_PARAM)
    //let l_iter:usize = N_PARAM * index;
    for blk_i in 0..BLOCKS {
        let l_iter: usize = index * N_PARAM + blk_i * N_PARAM * N_ROWS;
        {
            let block_num = l_iter / (N_PARAM * N_ROWS);
            let block_l = l_iter % (N_PARAM * N_ROWS);

            let block_lx: usize = block_l / N_PARAM;

            //SPEEDUP
            let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
            let s_star: &[i32] = &s_vecs[block_lx * N_PARAM..(block_lx + 1) * N_PARAM];

            let mut g_expand = vec![0i32; N_PARAM];
            g_func(
                &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
                &s_star,
                &mut g_expand,
            );

            let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
            let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

            let mut bv_i32: i32;

            for ly_iter in 0..N_PARAM {
                bv_i32 = mul_mod_mont(b_vec[block_lx], v_vec[N_PARAM * block_num + ly_iter]);

                //m[ly_iter + block_num * N_PARAM * N_PARAM + block_lx * N_PARAM] = g_expand[ly_iter] + bv_i32;
                m[ly_iter + blk_i * N_PARAM] = g_expand[ly_iter] + bv_i32;
            }
        }
    }
}

// used by the single server that has the full uncompressed vectors
// this produces N_PARAM parts
pub fn dpf_eval_lwe_block_new_all_sub_timing(
    index: usize,
    m: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &[u8],
    s_vec_1d_u8: &[u8],
    v_vec_u8: &[u8],
) {
    if NUM_SERVERS < 2 {
        println!("There must be at least 2 servers!\n");
        return;
    }
    //for l_iter in (0..N_PARAM * N_PARAM * NUM_BLOCK).step_by(N_PARAM)
    //let l_iter:usize = N_PARAM * index;
    for blk_i in 0..BLOCKS {
        let l_iter: usize = index * N_PARAM + blk_i * N_PARAM * N_ROWS;
        {
            let block_num = l_iter / (N_PARAM * N_ROWS);
            let block_l = l_iter % (N_PARAM * N_ROWS);

            let block_lx: usize = block_l / N_PARAM;

            //SPEEDUP
            let s_vecs: &[i32] = bytemuck::cast_slice(s_vec_1d_u8);
            let s_star: &[i32] = &s_vecs[block_lx * N_PARAM..(block_lx + 1) * N_PARAM];

            let mut g_expand = vec![0i32; N_PARAM];
            g_func(
                &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
                &s_star,
                &mut g_expand,
            );

            let b_vec: &[i32] = bytemuck::cast_slice(b_vec_u8);
            let v_vec: &[i32] = bytemuck::cast_slice(v_vec_u8);

            let mut bv_i32: i32;

            for ly_iter in 0..N_PARAM {
                bv_i32 = mul_mod_mont(b_vec[block_lx], v_vec[N_PARAM * block_num + ly_iter]);

                //m[ly_iter + block_num * N_PARAM * N_PARAM + block_lx * N_PARAM] = g_expand[ly_iter] + bv_i32;
                m[ly_iter + blk_i * N_PARAM] = g_expand[ly_iter] + bv_i32;
            }
        }
    }
}

// used by the all but one server
#[allow(dead_code)]
pub fn dpf_eval_lwe_seed_block_all(
    m: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    for l_iter in (0..N_PARAM * N_PARAM * NUM_BLOCK).step_by(N_PARAM) {
        let block_num = l_iter / (N_PARAM * N_PARAM);
        let block_l = l_iter % (N_PARAM * N_PARAM);

        let block_lx: usize = block_l / N_PARAM;

        //b_vec_u8.fill(0);
        //s_vec_1d_u8.fill(0);
        for i in 0..b_vec_u8.len() {
            b_vec_u8[i] = 0;
        }
        for i in 0..s_vec_1d_u8.len() {
            s_vec_1d_u8[i] = 0;
        }

        fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(
            &seed[0..16],
            &seed[16..32],
            b_vec_u8,
            s_vec_1d_u8,
            E_BYTES * B_SLICE,
            E_BYTES * N_PARAM,
            block_lx,
            N_ROWS,
        );

        dpf_eval_lwe_base_one_sq_whole_poly(
            block_l,
            &mut m[l_iter..l_iter + N_PARAM],
            &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
            &b_vec_u8[..],
            &s_vec_1d_u8[..],
            &v_vec_u8[block_num * E_BYTES * V_SLICE..(block_num + 1) * E_BYTES * V_SLICE],
        );
    }
}

// used by the all but one server
pub fn dpf_eval_lwe_seed_block_all_sub(
    index: usize,
    m: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    //for l_iter in (0..N_PARAM * N_PARAM * NUM_BLOCK).step_by(N_PARAM)
    //let l_iter:usize = index*N_PARAM;
    for blk_i in 0..BLOCKS {
        let l_iter: usize = index * N_PARAM + blk_i * N_PARAM * N_ROWS;
        {
            let block_num = l_iter / (N_PARAM * N_ROWS);
            let block_l = l_iter % (N_PARAM * N_ROWS);

            let block_lx: usize = block_l / N_PARAM;

            //b_vec_u8.fill(0);
            //s_vec_1d_u8.fill(0);
            for i in 0..b_vec_u8.len() {
                b_vec_u8[i] = 0;
            }
            for i in 0..s_vec_1d_u8.len() {
                s_vec_1d_u8[i] = 0;
            }

            // moshih
            fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(
                &seed[0..16],
                &seed[16..32],
                b_vec_u8,
                s_vec_1d_u8,
                E_BYTES * B_SLICE,
                E_BYTES * N_PARAM,
                block_lx,
                N_ROWS,
            );


            dpf_eval_lwe_base_one_sq_whole_poly(
                block_l,
                //&mut m[l_iter..l_iter + N_PARAM],
                &mut m[blk_i * N_PARAM..blk_i * N_PARAM + N_PARAM],
                &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
                &b_vec_u8[..],
                &s_vec_1d_u8[..],
                &v_vec_u8[block_num * E_BYTES * N_PARAM..(block_num + 1) * E_BYTES * N_PARAM],
            );
        }
    }
    /*
    for l_iter in (index * N_PARAM * NUM_BLOCK..(index+1) * N_PARAM * NUM_BLOCK).step_by(N_PARAM)
    {
        let block_num = l_iter / (N_PARAM * N_PARAM);
        let block_l = l_iter % (N_PARAM * N_PARAM);

        let block_lx: usize = block_l / N_PARAM;

        b_vec_u8.fill(0);
        s_vec_1d_u8.fill(0);
        fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(
            &seed[0..16],
            &seed[16..32],
            b_vec_u8,
            s_vec_1d_u8,
            4 * B_SLICE,
            4 * N_PARAM,
            block_lx,
            N_PARAM,
        );

        dpf_eval_lwe_base_one_sq_whole_poly(
            block_l,
            //&mut m[l_iter..l_iter + N_PARAM],
            &mut m[offset*N_PARAM.. offset*N_PARAM+N_PARAM],
            &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
            &b_vec_u8[..],
            &s_vec_1d_u8[..],
            &v_vec_u8[block_num * 4 * V_SLICE..(block_num + 1) * 4 * V_SLICE],
        );
        offset+=1;
    }

     */
}

// used by the all but one server
pub fn dpf_eval_lwe_seed_block_all_sub_timing(
    index: usize,
    m: &mut [i32],
    a_vec: &[i32],
    b_vec_u8: &mut [u8],
    s_vec_1d_u8: &mut [u8],
    seed: &[u8],
    v_vec_u8: &[u8],
) {
    //for l_iter in (0..N_PARAM * N_PARAM * NUM_BLOCK).step_by(N_PARAM)
    //let l_iter:usize = index*N_PARAM;
    for blk_i in 0..BLOCKS {
        let l_iter: usize = index * N_PARAM + blk_i * N_PARAM * N_ROWS;
        {
            let block_num = l_iter / (N_PARAM * N_ROWS);
            let block_l = l_iter % (N_PARAM * N_ROWS);

            let block_lx: usize = block_l / N_PARAM;

            //b_vec_u8.fill(0);
            //s_vec_1d_u8.fill(0);

            for i in 0..b_vec_u8.len() {
                b_vec_u8[i] = 0;
            }
            for i in 0..s_vec_1d_u8.len() {
                s_vec_1d_u8[i] = 0;
            }

            // todo: reimp
            fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(
                &seed[0..16],
                &seed[16..32],
                b_vec_u8,
                s_vec_1d_u8,
                E_BYTES * B_SLICE,
                E_BYTES * N_PARAM,
                block_lx,
                N_ROWS,
            );

            dpf_eval_lwe_base_one_sq_whole_poly(
                block_l,
                //&mut m[l_iter..l_iter + N_PARAM],
                &mut m[blk_i * N_PARAM..blk_i * N_PARAM + N_PARAM],
                &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
                &b_vec_u8[..],
                &s_vec_1d_u8[..],
                &v_vec_u8[block_num * E_BYTES * N_PARAM..(block_num + 1) * E_BYTES * N_PARAM],
            );
        }
    }
    /*
    for l_iter in (index * N_PARAM * NUM_BLOCK..(index+1) * N_PARAM * NUM_BLOCK).step_by(N_PARAM)
    {
        let block_num = l_iter / (N_PARAM * N_PARAM);
        let block_l = l_iter % (N_PARAM * N_PARAM);

        let block_lx: usize = block_l / N_PARAM;

        b_vec_u8.fill(0);
        s_vec_1d_u8.fill(0);
        fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(
            &seed[0..16],
            &seed[16..32],
            b_vec_u8,
            s_vec_1d_u8,
            4 * B_SLICE,
            4 * N_PARAM,
            block_lx,
            N_PARAM,
        );

        dpf_eval_lwe_base_one_sq_whole_poly(
            block_l,
            //&mut m[l_iter..l_iter + N_PARAM],
            &mut m[offset*N_PARAM.. offset*N_PARAM+N_PARAM],
            &a_vec[block_num * N_PARAM..(block_num + 1) * N_PARAM],
            &b_vec_u8[..],
            &s_vec_1d_u8[..],
            &v_vec_u8[block_num * 4 * V_SLICE..(block_num + 1) * 4 * V_SLICE],
        );
        offset+=1;
    }

     */
}
