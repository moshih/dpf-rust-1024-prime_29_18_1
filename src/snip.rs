#[allow(dead_code)]
use rand::thread_rng;
use rand::Rng;

use aes::cipher::{KeyIvInit, StreamCipher};

use crate::dpf::{
    fill_rand3_by_seed_aes128_nr, fill_rand4_by_seed_aes128_nr, fill_rand_aes128_modq,
    fill_rand_aes128_modq_nr_1_by_seed, fill_rand_aes128_nr,
};
use crate::ntt::{barrett_reduce, mul_mod_mont};
use crate::params::*;

pub fn fill_rand_aes128_modq_nr_1_by_seed_custom(
    key: &[u8],
    iv: &[u8],
    input2: &mut [u8],
    len2: usize,
    num_seeds: usize,
) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());

    let mut temp_seeds = vec![0u8; SEED_IV_LEN * num_seeds];
    let output_per_seed = len2 / num_seeds;
    cipher.apply_keystream(&mut temp_seeds);
    //println!("temp_seeds: {:?}", &temp_seeds[0..16]);
    //println!("--temp_seeds: {:?}", &temp_seeds[16..32]);

    let iterations: usize = N_PARAM;
    for iter in 0..iterations {
        let mut seed_cipher = Aes128Ctr64LE::new(
            (&temp_seeds[32 * iter..32 * iter + 16]).into(),
            (&temp_seeds[32 * iter + 16..32 * iter + 32]).into(),
        );
        seed_cipher
            .apply_keystream(&mut input2[output_per_seed * iter..output_per_seed * (iter + 1)]);
    }
    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    for i in 0..(len2 / E_BYTES) {
        if i % (output_per_seed / E_BYTES) == 0 {
            //if temp[0]|temp[1]|temp[2]|temp[3] != 0 {
            temp = [0; E_BYTES];
            //}
            cipher = Aes128Ctr64LE::new(
                (&temp_seeds
                    [32 * (i / (output_per_seed / 4)) + 16..32 * (i / (output_per_seed / 4)) + 32])
                    .into(),
                (&temp_seeds
                    [32 * (i / (output_per_seed / 4))..32 * (i / (output_per_seed / 4)) + 16])
                    .into(),
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

pub fn fill_rand_aes128_modq_nr_1_by_seed_sq_getsub_custom(
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
    // println!("temp_seeds: {:?}", &temp_seeds[0..16]);
    //println!("--temp_seeds: {:?}", &temp_seeds[16..32]);

    let mut seed_cipher = Aes128Ctr64LE::new(
        (&temp_seeds[32 * seed_index..32 * seed_index + 16]).into(),
        (&temp_seeds[32 * seed_index + 16..32 * seed_index + 32]).into(),
    );
    seed_cipher.apply_keystream(&mut input2[0..len2]);

    let output2: &mut [i32] = bytemuck::cast_slice_mut(input2);

    let mut temp = [0u8; E_BYTES];
    let mut temp_value: u32;

    cipher = Aes128Ctr64LE::new(
        (&temp_seeds[32 * seed_index + 16..32 * seed_index + 32]).into(),
        (&temp_seeds[32 * seed_index..32 * seed_index + 16]).into(),
    );

    for i in 0..(len2 / E_BYTES) {
        while (output2[i] as u32) > MAX_RAND {
            //println!("(p)HIT {} {} => {}", seed_index, i,output2[i]);
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

#[allow(dead_code)]
pub fn server_gen_cc_combine(
    b_vec: &[i32],
    rx_seed: &[u8],
    noise_vec: &[i32],
    entries_vec: &[i32],
    c0_alpha: &mut [i32],
    c1_alpha: &mut [i32],
    c2_alpha: &mut [i32],
    b_alpha: &mut [i32],
) {
    let mut c0_temp: i32;
    let mut c1_temp: i32;
    let mut c2_temp: i32;

    let mut rx_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    for a_iter in 0..N_PARAM {
        //rx_vec_u8.fill(0);
        for i in 0..rx_vec_u8.len() {
            rx_vec_u8[i] = 0;
        }

        c0_temp = 0;
        c1_temp = 0;
        c2_temp = 0;

        gen_rx_vec_sub(rx_seed, &mut rx_vec_u8, a_iter);
        let rx_vec: &mut [i32] = bytemuck::cast_slice_mut(&mut rx_vec_u8);
        // 51840

        for b_iter in 0..NUM_BLOCK {
            for c_iter in 0..N_PARAM {
                c0_temp = barrett_reduce(
                    c0_temp
                        + entries_vec[(b_iter * N_PARAM * N_PARAM) + a_iter * N_PARAM + c_iter]
                        + noise_vec[b_iter * N_PARAM + c_iter],
                );

                c1_temp = barrett_reduce(
                    c1_temp
                        + mul_mod_mont(
                            rx_vec[b_iter],
                            entries_vec[(b_iter * N_PARAM * N_PARAM) + a_iter * N_PARAM + c_iter]
                                + noise_vec[b_iter * N_PARAM + c_iter],
                        ),
                );

                c2_temp = barrett_reduce(
                    c2_temp
                        + mul_mod_mont(
                            mul_mod_mont(rx_vec[b_iter], rx_vec[b_iter]),
                            entries_vec[(b_iter * N_PARAM * N_PARAM) + a_iter * N_PARAM + c_iter]
                                + noise_vec[b_iter * N_PARAM + c_iter],
                        ),
                );
            }
        }
        c0_alpha[a_iter] = c0_temp;
        c1_alpha[a_iter] = c1_temp;
        c2_alpha[a_iter] = c2_temp;
        b_alpha[a_iter] = b_vec[a_iter];
    }
}

#[allow(dead_code)]
pub fn snip_test_temp() {
    let mut seed = [0u8; 32];
    fill_rand_aes128_nr(&mut seed, SEED_IV_LEN);
    let mut vec_out = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM * N_PARAM];

    //for blk_i in 0..NUM_BLOCK {
    fill_rand_aes128_modq_nr_1_by_seed_custom(
        &seed[0..16],
        &seed[16..32],
        &mut vec_out[..],
        4 * NUM_BLOCK * N_PARAM * N_PARAM,
        N_PARAM,
    );
    //}
    let vec_out_i32: &mut [i32] = bytemuck::cast_slice_mut(&mut vec_out[..]);
    println!(
        "{:?}",
        &vec_out_i32[NUM_BLOCK * N_PARAM * N_PARAM - 16..NUM_BLOCK * N_PARAM * N_PARAM]
    );
    //println!("{:?}", &vec_out_i32[0..16]);

    let mut total_sum: i32 = 0;
    //for iter in 0..vec_out_i32.len() {
    for iter in 0..N_PARAM * NUM_BLOCK * N_PARAM {
        total_sum = modq(total_sum + vec_out_i32[iter]);
    }
    println!("Total sum is {}", total_sum);

    let mut running_total: i32 = 0;
    let mut vec_out_partial = vec![0u8; 4 * NUM_BLOCK * N_PARAM];
    for iter in 0..N_PARAM {
        //vec_out_partial.fill(0);
        for i in 0..vec_out_partial.len() {
            vec_out_partial[i] = 0;
        }

        fill_rand_aes128_modq_nr_1_by_seed_sq_getsub_custom(
            &seed[0..16],
            &seed[16..32],
            &mut vec_out_partial,
            4 * NUM_BLOCK * N_PARAM,
            iter,
            N_PARAM,
        );
        let vec_out_i32_partial: &mut [i32] = bytemuck::cast_slice_mut(&mut vec_out_partial[..]);
        //println!("{:?}", &vec_out_i32_partial[NUM_BLOCK*N_PARAM-16..NUM_BLOCK*N_PARAM]);
        for iter_index in 0..vec_out_i32_partial.len() {
            running_total = modq(running_total + vec_out_i32_partial[iter_index]);
            if vec_out_i32_partial[iter_index]
                != vec_out_i32[iter_index + NUM_BLOCK * N_PARAM * iter]
            {
                println!(
                    "ERROR at {} {} got {} instead of {}",
                    iter,
                    iter_index,
                    vec_out_i32_partial[iter_index],
                    vec_out_i32[iter_index + NUM_BLOCK * N_PARAM * iter]
                );
                return;
            }
        }
    }

    let vec_out_i32_partial: &mut [i32] = bytemuck::cast_slice_mut(&mut vec_out_partial[..]);
    println!(
        "{:?}",
        &vec_out_i32_partial[NUM_BLOCK * N_PARAM - 16..NUM_BLOCK * N_PARAM]
    );
    //println!("{:?}", &vec_out_i32_partial[0..16]);
    println!("(running) Total sum is {}", running_total);
}

// records sign bit
// (l+1)*m (NUM_BLOCK*N_PARAM) bits
// output should be (l+1)*m*NUM_SERVERS
#[allow(dead_code)]
pub fn separate_bits_debug(input: &[i32], bits: &mut [u32], output: &mut [u32]) {
    for iter in 0..NOISE_LEN {
        for bit in 0..NOISE_BITS {
            bits[iter * NOISE_BITS + bit] = ((input[iter] as u32) >> bit) & 1;
        }
    }

    let mut output_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut output[..]);
    let output_shares = fill_rand_aes128_modq(
        &mut output_vec_u8,
        NOISE_BITS * (NOISE_LEN) * (NUM_SERVERS - 1),
    );

    for iter in 0..NOISE_BITS * NOISE_LEN {
        let mut temp: i32 = 0;
        for iter_s in 0..(NUM_SERVERS - 1) {
            temp = barrett_reduce(temp + output_shares[iter_s * NOISE_BITS * NOISE_LEN + iter]);
        }
        //print!("|{}|", (Q-barrett_reduce(temp)));
        output_shares[(NUM_SERVERS - 1) * NOISE_BITS * NOISE_LEN + iter] =
            barrett_reduce((bits[iter] as i32) - temp);
    }
}

#[allow(dead_code)]
pub fn separate_bits_debug_og(input: &[i32], bits: &mut [u32], output: &mut [u32]) {
    for iter in 0..NOISE_LEN {
        for bit in 0..NOISE_BITS {
            bits[iter * NOISE_BITS + bit] = ((input[iter] as u32) >> bit) & 1;
        }
    }

    let mut output_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut output[..]);
    let output_shares = fill_rand_aes128_modq(
        &mut output_vec_u8,
        NOISE_BITS * (NOISE_LEN) * (NUM_SERVERS - 1),
    );

    for iter in 0..NOISE_BITS * NOISE_LEN {
        let mut temp: i32 = 0;
        for iter_s in 0..(NUM_SERVERS - 1) {
            temp = temp + output_shares[iter_s * NOISE_BITS * NOISE_LEN + iter];
        }
        output_shares[(NUM_SERVERS - 1) * NOISE_BITS * NOISE_LEN + iter] =
            (bits[iter] as i32) - temp;
    }
}

// client separates into server shares
// takes in noise vector, separates to bits, then outputs additive secret shares
pub fn separate_bits(input: &[i32], output: &mut [u32]) {
    let mut bits = vec![0u32; NOISE_LEN * NOISE_BITS];
    for iter in 0..NOISE_LEN {
        for bit in 0..NOISE_BITS {
            bits[iter * NOISE_BITS + bit] = ((input[iter] as u32) >> bit) & 1;
        }
    }

    let mut output_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut output[..]);
    let output_shares = fill_rand_aes128_modq(
        &mut output_vec_u8,
        NOISE_BITS * (NOISE_LEN) * (NUM_SERVERS - 1),
    );

    for iter in 0..NOISE_BITS * NOISE_LEN {
        let mut temp: i32 = 0;
        for iter_s in 0..(NUM_SERVERS - 1) {
            temp = barrett_reduce(temp + output_shares[iter_s * NOISE_BITS * NOISE_LEN + iter]);
        }
        output_shares[(NUM_SERVERS - 1) * NOISE_BITS * NOISE_LEN + iter] =
            barrett_reduce((bits[iter] as i32) - temp);
    }
}

pub fn separate_bits_single_block(input: &[i32], output: &mut [u32]) {
    let mut bits = vec![0u32; NOISE_LEN / NUM_BLOCK * NOISE_BITS];
    for iter in 0..NOISE_LEN / NUM_BLOCK {
        for bit in 0..NOISE_BITS {
            bits[iter * NOISE_BITS + bit] = ((input[iter] as u32) >> bit) & 1;
        }
    }

    let mut output_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut output[..]);
    let output_shares = fill_rand_aes128_modq(
        &mut output_vec_u8,
        NOISE_BITS * (NOISE_LEN / NUM_BLOCK) * (NUM_SERVERS - 1),
    );

    for iter in 0..NOISE_BITS * NOISE_LEN / NUM_BLOCK {
        let mut temp: i32 = 0;
        for iter_s in 0..(NUM_SERVERS - 1) {
            temp = barrett_reduce(
                temp + output_shares[iter_s * NOISE_BITS * NOISE_LEN / NUM_BLOCK + iter],
            );
        }
        output_shares[(NUM_SERVERS - 1) * NOISE_BITS * NOISE_LEN / NUM_BLOCK + iter] =
            barrett_reduce((bits[iter] as i32) - temp);
    }
}

// server combines bits of their own share
pub fn combine_bits(input: &[u32], output: &mut [i32]) {
    for value_iter in 0..NOISE_LEN {
        let mut temp: i32 = 0;
        for bit_iter in 0..NOISE_BITS {
            temp = temp
                + mul_mod_mont(
                    input[NOISE_BITS * value_iter + bit_iter] as i32,
                    POW2I32[bit_iter],
                );
        }
        output[value_iter] = barrett_reduce(temp);
    }
}

#[allow(dead_code)]
pub fn combine_bits_og(input: &[u32], output: &mut [i32]) {
    for value_iter in 0..NOISE_LEN {
        let mut temp: i32 = 0;
        for bit_iter in 0..NOISE_BITS {
            temp = (input[NOISE_BITS * value_iter + bit_iter] << bit_iter) as i32;
        }
        output[value_iter] = temp;
    }
}

// from a 32 u8 seed,
// for r_x is len NUM_BLOCK*N_PARAM*N_PARAM
// s_t is NOISE_BITS*NUM_BLOCK*N_PARAM
// sigma_alpha is N_PARAM
pub fn gen_rand_coeff_seeds(
    seed: &mut [u8],
    rx_seed: &mut [u8],
    st_seed: &mut [u8],
    sa_seed: &mut [u8],
) {
    fill_rand_aes128_nr(seed, SEED_IV_LEN);
    fill_rand3_by_seed_aes128_nr(
        &seed[0..16],
        &seed[16..32],
        rx_seed,
        st_seed,
        sa_seed,
        SEED_IV_LEN,
        SEED_IV_LEN,
        SEED_IV_LEN,
    );
}

pub fn get_rand_coeff_seeds(
    seed: &[u8],
    rx_seed: &mut [u8],
    st_seed: &mut [u8],
    sa_seed: &mut [u8],
) {
    fill_rand3_by_seed_aes128_nr(
        &seed[0..16],
        &seed[16..32],
        rx_seed,
        st_seed,
        sa_seed,
        SEED_IV_LEN,
        SEED_IV_LEN,
        SEED_IV_LEN,
    );
}

#[allow(dead_code)]
pub fn get_rand_coeff_bt_seeds(
    seed: &[u8],
    rx_seed: &mut [u8],
    st_seed: &mut [u8],
    sa_seed: &mut [u8],
    bt_seed: &mut [u8],
) {
    fill_rand4_by_seed_aes128_nr(
        &seed[0..16],
        &seed[16..32],
        rx_seed,
        st_seed,
        sa_seed,
        bt_seed,
        SEED_IV_LEN,
        SEED_IV_LEN,
        SEED_IV_LEN,
        SEED_IV_LEN,
    );
}

#[allow(dead_code)]
pub fn gen_rx_vec(rx_seed: &[u8], rx_vec: &mut [u8]) {
    fill_rand_aes128_modq_nr_1_by_seed_custom(
        &rx_seed[0..16],
        &rx_seed[16..32],
        rx_vec,
        E_BYTES * NUM_BLOCK * N_PARAM * NOISE_BITS,
        N_PARAM,
    );
}

pub fn gen_rx_vec_sub(rx_seed: &[u8], rx_vec: &mut [u8], seed_index: usize) {
    fill_rand_aes128_modq_nr_1_by_seed_sq_getsub_custom(
        &rx_seed[0..16],
        &rx_seed[16..32],
        rx_vec,
        E_BYTES * NUM_BLOCK * NOISE_BITS,
        seed_index,
        N_PARAM,
    );
}

pub fn gen_r1_vec_sub(r1_seed: &[u8], r1_vec: &mut [u8], seed_index: usize) {
    fill_rand_aes128_modq_nr_1_by_seed_sq_getsub_custom(
        &r1_seed[0..16],
        &r1_seed[16..32],
        r1_vec,
        E_BYTES * NOISE_LEN,
        seed_index,
        N_PARAM,
    );
}

pub fn gen_r2_vec_sub(r2_seed: &[u8], r2_vec: &mut [u8]) {
    fill_rand_aes128_modq_nr_1_by_seed(
        &r2_seed[0..16],
        &r2_seed[16..32],
        r2_vec,
        E_BYTES * N_PARAM,
    );
}

pub fn gen_r3_vec_sub(r3_seed: &[u8], r3_vec: &mut [u8]) {
    fill_rand_aes128_modq_nr_1_by_seed(
        &r3_seed[0..16],
        &r3_seed[16..32],
        r3_vec,
        E_BYTES * NOISE_LEN * NOISE_BITS,
    );
}

#[allow(dead_code)]
pub fn gen_st_vec(st_seed: &[u8], st_vec: &mut [u8]) {
    fill_rand_aes128_modq_nr_1_by_seed(
        &st_seed[0..16],
        &st_seed[16..32],
        st_vec,
        E_BYTES * NOISE_BITS * NUM_BLOCK * N_PARAM,
    );
}

#[allow(dead_code)]
pub fn gen_sa_vec(sa_seed: &[u8], sa_vec: &mut [u8]) {
    fill_rand_aes128_modq_nr_1_by_seed(
        &sa_seed[0..16],
        &sa_seed[16..32],
        sa_vec,
        E_BYTES * N_PARAM,
    );
}

///////////////////////////////////////////////////////////////////////////////////////////////////
pub fn mul_shares_p1(in_y: i32, in_z: i32, bt_a: i32, bt_b: i32, _bt_c: i32) -> (i32, i32) {
    let d_out: i32 = in_y - bt_a;
    let e_out: i32 = in_z - bt_b;

    return (d_out, e_out);
}

pub fn gcd_extended(a: i32, b: i32, x: &mut i32, y: &mut i32) -> i32 {
    if a == 0 {
        *x = 0;
        *y = 1;

        return b;
    }

    let mut x1: i32 = 0;
    let mut y1: i32 = 0;

    //println!("{} % {} = {}", b, a, (b % a));
    //println!("{} / {} = {}", b, a, (b / a));
    let gcd = gcd_extended(b % a, a, &mut x1, &mut y1);

    *x = y1 - (b / a) * x1;
    *y = x1;

    return gcd;
}

pub fn mod_inverse(a: i32, b: i32) -> i32 {
    let mut x: i32 = 0;
    let mut y: i32 = 0;

    let g = gcd_extended(a, b, &mut x, &mut y);
    if g != 1 {
        println!("No Inverse Exists!");
    }

    let inv = ((x % b) + b) % b;
    return inv;
}

pub fn mul_shares_p2(in_d: i32, in_e: i32, bt_a: i32, bt_b: i32, bt_c: i32, inv_s: i32) -> i32 {
    //let output:i64 = (in_d as i64)*in_e*inv_s + in_d*bt_b + in_e*bt_a + bt_c;
    /*
    let output: i64 = (in_d as i64) * (in_e as i64) * (inv_s as i64)
        + (in_d as i64) * (bt_b as i64)
        + (in_e as i64) * (bt_a as i64)
        + (bt_c as i64);

    return (output % Q as i64) as i32;
     */

    let output1: i32 = mul_mod_mont(mul_mod_mont(in_d, in_e), inv_s);
    let output: i32 =
        barrett_reduce(output1 + mul_mod_mont(in_d, bt_b) + mul_mod_mont(in_e, bt_a) + bt_c);

    return output;
}

#[allow(dead_code)]
pub fn create_bit_shares(bit_value: i32, bit_shares_vec: &mut [i32]) {
    let mut bit_shares_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut bit_shares_vec[..]);
    let bit_shares = fill_rand_aes128_modq(&mut bit_shares_vec_u8, NUM_SERVERS);

    let mut bit_sum: i32 = 0;
    for iter in 0..NUM_SERVERS {
        bit_sum += bit_shares[iter];
    }

    bit_shares[0] += bit_value - bit_sum;
}

#[allow(dead_code)]
pub fn create_bit_snip(bit_value: i32, snip_out: &mut [SnipI]) {
    let mut snip_rand_vec = vec![0i64; BIT_SNIP_RAND_VAL];

    let mut f_zero: i32 = 0;
    let mut g_zero: i32 = 0;

    let mut h0: i32 = 0;
    let mut h1: i32 = 0;
    let mut h2: i32 = 0;

    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;

    let mut snip_rand_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut snip_rand_vec[..]);
    let rand_values = fill_rand_aes128_modq(&mut snip_rand_vec_u8, BIT_SNIP_RAND_VAL);

    for iter in 0..NUM_SERVERS {
        f_zero += rand_values[iter];
        g_zero += rand_values[NUM_SERVERS + iter];

        h0 += rand_values[2 * NUM_SERVERS + iter];
        h1 += rand_values[3 * NUM_SERVERS + iter];
        h2 += rand_values[4 * NUM_SERVERS + iter];

        a += rand_values[5 * NUM_SERVERS + iter];
        b += rand_values[6 * NUM_SERVERS + iter];
        c += rand_values[7 * NUM_SERVERS + iter];
    }
    f_zero = modq(f_zero);
    g_zero = modq(g_zero);

    // setting the sum of h0_i = f_zero*g_zero
    rand_values[2 * NUM_SERVERS] =
        modq(rand_values[2 * NUM_SERVERS] + mul_modq(f_zero, g_zero) - h0);

    // setting the sum of h1_i = (b-f_zero)*g_zero+(b-1-g_zero)*f_zero
    rand_values[3 * NUM_SERVERS] = modq(
        rand_values[3 * NUM_SERVERS]
            + (mul_modq(modq(bit_value - f_zero), g_zero)
                + mul_modq(modq(bit_value - 1 - g_zero), f_zero))
            - h1,
    );

    // setting the sum of h2_i = (b-f_zero)*(b-1-g_zero)
    rand_values[4 * NUM_SERVERS] = modq(
        rand_values[4 * NUM_SERVERS]
            + mul_modq(modq(bit_value - f_zero), modq(bit_value - 1 - g_zero))
            - h2,
    );

    // setting a*b = c
    rand_values[7 * NUM_SERVERS] += (((a as i64) * (b as i64)) % (Q as i64)) as i32 - c;

    for iter in 0..NUM_SERVERS {
        snip_out[iter].f_zero_i = rand_values[iter];
        snip_out[iter].g_zero_i = rand_values[NUM_SERVERS + iter];

        snip_out[iter].h0_i = modq(rand_values[2 * NUM_SERVERS + iter]);
        snip_out[iter].h1_i = modq(rand_values[3 * NUM_SERVERS + iter]);
        snip_out[iter].h2_i = modq(rand_values[4 * NUM_SERVERS + iter]);

        snip_out[iter].a_i = rand_values[5 * NUM_SERVERS + iter];
        snip_out[iter].b_i = rand_values[6 * NUM_SERVERS + iter];
        snip_out[iter].c_i = rand_values[7 * NUM_SERVERS + iter];
    }
}

#[allow(dead_code)]
pub fn create_bit_snip_proper(bit_value: i32, snip_out: &mut [SnipI]) {
    let mut snip_rand_vec = vec![0i32; BIT_SNIP_RAND_VAL];

    let mut f_zero: i32 = 0;
    let mut g_zero: i32 = 0;

    let mut h0: i32 = 0;
    let mut h1: i32 = 0;
    let mut h2: i32 = 0;

    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;

    let mut snip_rand_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut snip_rand_vec[..]);
    let rand_values = fill_rand_aes128_modq(&mut snip_rand_vec_u8, BIT_SNIP_RAND_VAL);

    for iter in 0..NUM_SERVERS {
        f_zero += rand_values[iter];
        g_zero += rand_values[NUM_SERVERS + iter];

        h0 += rand_values[2 * NUM_SERVERS + iter];
        h1 += rand_values[3 * NUM_SERVERS + iter];
        h2 += rand_values[4 * NUM_SERVERS + iter];

        a += rand_values[5 * NUM_SERVERS + iter];
        b += rand_values[6 * NUM_SERVERS + iter];
        c += rand_values[7 * NUM_SERVERS + iter];
    }
    f_zero = barrett_reduce(f_zero);
    g_zero = barrett_reduce(g_zero);

    h0 = barrett_reduce(h0);
    h1 = barrett_reduce(h1);
    h2 = barrett_reduce(h2);

    a = barrett_reduce(a);
    b = barrett_reduce(b);
    c = barrett_reduce(c);

    // setting the sum of h0_i = f_zero*g_zero
    rand_values[2 * NUM_SERVERS] =
        barrett_reduce(rand_values[2 * NUM_SERVERS] + mul_mod_mont(f_zero, g_zero) - h0);

    // setting the sum of h1_i = (b-f_zero)*g_zero+(b-1-g_zero)*f_zero
    rand_values[3 * NUM_SERVERS] = modq(
        rand_values[3 * NUM_SERVERS]
            + (mul_mod_mont(barrett_reduce(bit_value - f_zero), g_zero)
                + mul_mod_mont(barrett_reduce(bit_value - 1 - g_zero), f_zero))
            - h1,
    );

    // setting the sum of h2_i = (b-f_zero)*(b-1-g_zero)
    rand_values[4 * NUM_SERVERS] = barrett_reduce(
        rand_values[4 * NUM_SERVERS]
            + mul_mod_mont(
                barrett_reduce(bit_value - f_zero),
                barrett_reduce(bit_value - 1 - g_zero),
            )
            - h2,
    );

    // setting a*b = c
    rand_values[7 * NUM_SERVERS] += mul_mod_mont(a, b) - c;

    for iter in 0..NUM_SERVERS {
        snip_out[iter].f_zero_i = rand_values[iter];
        snip_out[iter].g_zero_i = rand_values[NUM_SERVERS + iter];

        snip_out[iter].h0_i = barrett_reduce(rand_values[2 * NUM_SERVERS + iter]);
        snip_out[iter].h1_i = barrett_reduce(rand_values[3 * NUM_SERVERS + iter]);
        snip_out[iter].h2_i = barrett_reduce(rand_values[4 * NUM_SERVERS + iter]);

        snip_out[iter].a_i = rand_values[5 * NUM_SERVERS + iter];
        snip_out[iter].b_i = rand_values[6 * NUM_SERVERS + iter];
        snip_out[iter].c_i = rand_values[7 * NUM_SERVERS + iter];
    }
}

#[allow(dead_code)]
pub fn create_snip_proper(mul_a: i32, mul_b: i32, snip_out: &mut [SnipI]) {
    let mut snip_rand_vec = vec![0i32; BIT_SNIP_RAND_VAL];

    let mut f_zero: i32 = 0;
    let mut g_zero: i32 = 0;

    let mut h0: i32 = 0;
    let mut h1: i32 = 0;
    let mut h2: i32 = 0;

    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;

    let mut snip_rand_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut snip_rand_vec[..]);
    let rand_values = fill_rand_aes128_modq(&mut snip_rand_vec_u8, BIT_SNIP_RAND_VAL);

    for iter in 0..NUM_SERVERS {
        f_zero += rand_values[iter];
        g_zero += rand_values[NUM_SERVERS + iter];

        h0 += rand_values[2 * NUM_SERVERS + iter];
        h1 += rand_values[3 * NUM_SERVERS + iter];
        h2 += rand_values[4 * NUM_SERVERS + iter];

        a += rand_values[5 * NUM_SERVERS + iter];
        b += rand_values[6 * NUM_SERVERS + iter];
        c += rand_values[7 * NUM_SERVERS + iter];
    }
    f_zero = barrett_reduce(f_zero);
    g_zero = barrett_reduce(g_zero);

    h0 = barrett_reduce(h0);
    h1 = barrett_reduce(h1);
    h2 = barrett_reduce(h2);

    a = barrett_reduce(a);
    b = barrett_reduce(b);
    c = barrett_reduce(c);

    // setting the sum of h0_i = f_zero*g_zero
    rand_values[2 * NUM_SERVERS] =
        barrett_reduce(rand_values[2 * NUM_SERVERS] + mul_mod_mont(f_zero, g_zero) - h0);

    // setting the sum of h1_i = (b-f_zero)*g_zero+(b-1-g_zero)*f_zero
    rand_values[3 * NUM_SERVERS] = modq(
        rand_values[3 * NUM_SERVERS]
            + (mul_mod_mont(barrett_reduce(mul_a - f_zero), g_zero)
                + mul_mod_mont(barrett_reduce(mul_b - g_zero), f_zero))
            - h1,
    );

    // setting the sum of h2_i = (b-f_zero)*(b-1-g_zero)
    rand_values[4 * NUM_SERVERS] = barrett_reduce(
        rand_values[4 * NUM_SERVERS]
            + mul_mod_mont(
                barrett_reduce(mul_a - f_zero),
                barrett_reduce(mul_b - g_zero),
            )
            - h2,
    );

    // setting a*b = c
    rand_values[7 * NUM_SERVERS] += mul_mod_mont(a, b) - c;

    for iter in 0..NUM_SERVERS {
        snip_out[iter].f_zero_i = rand_values[iter];
        snip_out[iter].g_zero_i = rand_values[NUM_SERVERS + iter];

        snip_out[iter].h0_i = barrett_reduce(rand_values[2 * NUM_SERVERS + iter]);
        snip_out[iter].h1_i = barrett_reduce(rand_values[3 * NUM_SERVERS + iter]);
        snip_out[iter].h2_i = barrett_reduce(rand_values[4 * NUM_SERVERS + iter]);

        snip_out[iter].a_i = rand_values[5 * NUM_SERVERS + iter];
        snip_out[iter].b_i = rand_values[6 * NUM_SERVERS + iter];
        snip_out[iter].c_i = rand_values[7 * NUM_SERVERS + iter];
    }
}

#[allow(dead_code)]
pub fn gen_rand_pt() -> i32 {
    let mut rand_pt: i32 = thread_rng().gen();
    while (rand_pt as u32) > MAX_RAND {
        rand_pt = thread_rng().gen();
    }
    return barrett_reduce(rand_pt);
}

#[allow(dead_code)]
pub fn server_pt1(
    bit_shares_vec: &[i32],
    rand_pt: i32,
    snip: &[SnipI],
    fr_i: &mut [i32],
    gr_i: &mut [i32],
    hr_i: &mut [i32],
    d_i: &mut [i32],
    e_i: &mut [i32],
) {
    for iter in 0..NUM_SERVERS {
        fr_i[iter] = modq(
            snip[iter].f_zero_i
                + mul_modq(modq(bit_shares_vec[iter] - snip[iter].f_zero_i), rand_pt),
        );
        if iter == 0 {
            gr_i[iter] = modq(
                snip[iter].g_zero_i
                    + mul_modq(
                        modq(bit_shares_vec[iter] - 1 - snip[iter].g_zero_i),
                        rand_pt,
                    ),
            );
        } else {
            gr_i[iter] = modq(
                snip[iter].g_zero_i
                    + mul_modq(modq(bit_shares_vec[iter] - snip[iter].g_zero_i), rand_pt),
            );
        }
        hr_i[iter] = modq(
            snip[iter].h0_i
                + mul_modq(snip[iter].h1_i, rand_pt)
                + mul_modq(mul_modq(snip[iter].h2_i, rand_pt), rand_pt),
        );

        // Beaver Tiple multiplication
        (d_i[iter], e_i[iter]) = mul_shares_p1(
            fr_i[iter],
            gr_i[iter],
            snip[iter].a_i,
            snip[iter].b_i,
            snip[iter].c_i,
        );
    }
}

#[allow(dead_code)]
pub fn server_pt1_spread(
    bit_shares_vec: &[i32],
    start_index: usize,
    rand_pt: i32,
    snip: &[SnipI],
    fr_i: &mut [i32],
    gr_i: &mut [i32],
    hr_i: &mut [i32],
    d_i: &mut [i32],
    e_i: &mut [i32],
) {
    for iter in 0..NUM_SERVERS {
        fr_i[iter] = barrett_reduce(
            snip[iter].f_zero_i
                + mul_mod_mont(
                    barrett_reduce(
                        bit_shares_vec[iter * N_PARAM + start_index] - snip[iter].f_zero_i,
                    ),
                    rand_pt,
                ),
            //+ mul_mod_mont(barrett_reduce(bit_shares_vec[iter*N_PARAM+start_index] - SNIP[iter].f_zero_i), rand_pt),
        );
        if iter == 0 {
            gr_i[iter] = barrett_reduce(
                snip[iter].g_zero_i
                    + mul_mod_mont(
                        barrett_reduce(
                            bit_shares_vec[iter * N_PARAM + start_index] - 1 - snip[iter].g_zero_i,
                        ),
                        rand_pt,
                    ),
            );
        } else {
            gr_i[iter] = barrett_reduce(
                snip[iter].g_zero_i
                    + mul_mod_mont(
                        barrett_reduce(
                            bit_shares_vec[iter * N_PARAM + start_index] - snip[iter].g_zero_i,
                        ),
                        rand_pt,
                    ),
            );
        }
        hr_i[iter] = barrett_reduce(
            snip[iter].h0_i
                + mul_mod_mont(snip[iter].h1_i, rand_pt)
                + mul_mod_mont(mul_mod_mont(snip[iter].h2_i, rand_pt), rand_pt),
        );

        // Beaver Tiple multiplication
        (d_i[iter], e_i[iter]) = mul_shares_p1(
            fr_i[iter],
            gr_i[iter],
            snip[iter].a_i,
            snip[iter].b_i,
            snip[iter].c_i,
        );
    }
}

#[allow(dead_code)]
pub fn server_pt1_spread_rand(
    bit_shares_vec: &[i32],
    start_index: usize,
    s_a: &[i32],
    rand_pt: i32,
    snip: &[SnipI],
    fr_i: &mut [i32],
    gr_i: &mut [i32],
    hr_i: &mut [i32],
    d_i: &mut [i32],
    e_i: &mut [i32],
) {
    for iter in 0..NUM_SERVERS {
        fr_i[iter] = barrett_reduce(
            snip[iter].f_zero_i
                //+ mul_mod_mont(barrett_reduce(bit_shares_vec[iter*N_PARAM+start_index] - SNIP[iter].f_zero_i), rand_pt),
                + mul_mod_mont(barrett_reduce(mul_mod_mont( bit_shares_vec[iter*N_PARAM+start_index], s_a[start_index]) - snip[iter].f_zero_i), rand_pt),
        );
        if iter == 0 {
            gr_i[iter] = barrett_reduce(
                snip[iter].g_zero_i
                    + mul_mod_mont(
                        barrett_reduce(
                            bit_shares_vec[iter * N_PARAM + start_index] - 1 - snip[iter].g_zero_i,
                        ),
                        rand_pt,
                    ),
            );
        } else {
            gr_i[iter] = barrett_reduce(
                snip[iter].g_zero_i
                    + mul_mod_mont(
                        barrett_reduce(
                            bit_shares_vec[iter * N_PARAM + start_index] - snip[iter].g_zero_i,
                        ),
                        rand_pt,
                    ),
            );
        }
        hr_i[iter] = barrett_reduce(
            snip[iter].h0_i
                + mul_mod_mont(snip[iter].h1_i, rand_pt)
                + mul_mod_mont(mul_mod_mont(snip[iter].h2_i, rand_pt), rand_pt),
        );

        // Beaver Tiple multiplication
        (d_i[iter], e_i[iter]) = mul_shares_p1(
            fr_i[iter],
            gr_i[iter],
            snip[iter].a_i,
            snip[iter].b_i,
            snip[iter].c_i,
        );
    }
}

#[allow(dead_code)]
pub fn server_pt1_spread_rand_sub(
    bit_shares_vec: &[i32],
    start_index: usize,
    s_at: &[i32],
    st_index: usize,
    rand_pt: i32,
    snip: &[SnipI],
    fr_i: &mut [i32],
    gr_i: &mut [i32],
    hr_i: &mut [i32],
    d_i: &mut [i32],
    e_i: &mut [i32],
) {
    for iter in 0..NUM_SERVERS {
        fr_i[iter] = barrett_reduce(
            snip[iter].f_zero_i
                //+ mul_mod_mont(barrett_reduce(bit_shares_vec[iter*N_PARAM+start_index] - SNIP[iter].f_zero_i), rand_pt),
                + mul_mod_mont(barrett_reduce(mul_mod_mont( bit_shares_vec[iter*NOISE_LEN * NOISE_BITS +start_index], s_at[st_index]) - snip[iter].f_zero_i), rand_pt),
        );
        if iter == 0 {
            gr_i[iter] = barrett_reduce(
                snip[iter].g_zero_i
                    + mul_mod_mont(
                        barrett_reduce(
                            bit_shares_vec[iter * NOISE_LEN * NOISE_BITS + start_index]
                                - 1
                                - snip[iter].g_zero_i,
                        ),
                        rand_pt,
                    ),
            );
        } else {
            gr_i[iter] = barrett_reduce(
                snip[iter].g_zero_i
                    + mul_mod_mont(
                        barrett_reduce(
                            bit_shares_vec[iter * NOISE_LEN * NOISE_BITS + start_index]
                                - snip[iter].g_zero_i,
                        ),
                        rand_pt,
                    ),
            );
        }
        hr_i[iter] = barrett_reduce(
            snip[iter].h0_i
                + mul_mod_mont(snip[iter].h1_i, rand_pt)
                + mul_mod_mont(mul_mod_mont(snip[iter].h2_i, rand_pt), rand_pt),
        );

        // Beaver Tiple multiplication
        (d_i[iter], e_i[iter]) = mul_shares_p1(
            fr_i[iter],
            gr_i[iter],
            snip[iter].a_i,
            snip[iter].b_i,
            snip[iter].c_i,
        );
    }
}

///////////////////////////////////////
#[allow(dead_code)]
pub fn create_mul_snip(input_a: i32, input_b: i32, snip_out: &mut [SnipI]) {
    let mut snip_rand_vec = vec![0i32; BIT_SNIP_RAND_VAL];

    let mut f_zero: i32 = 0;
    let mut g_zero: i32 = 0;

    let mut h0: i32 = 0;
    let mut h1: i32 = 0;
    let mut h2: i32 = 0;

    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;

    let mut snip_rand_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut snip_rand_vec[..]);
    let rand_values = fill_rand_aes128_modq(&mut snip_rand_vec_u8, BIT_SNIP_RAND_VAL);

    for iter in 0..NUM_SERVERS {
        f_zero += rand_values[iter];
        g_zero += rand_values[NUM_SERVERS + iter];

        h0 += rand_values[2 * NUM_SERVERS + iter];
        h1 += rand_values[3 * NUM_SERVERS + iter];
        h2 += rand_values[4 * NUM_SERVERS + iter];

        a += rand_values[5 * NUM_SERVERS + iter];
        b += rand_values[6 * NUM_SERVERS + iter];
        c += rand_values[7 * NUM_SERVERS + iter];
    }
    f_zero = modq(f_zero);
    g_zero = modq(g_zero);

    // setting the sum of h0_i = f_zero*g_zero
    rand_values[2 * NUM_SERVERS] =
        modq(rand_values[2 * NUM_SERVERS] + mul_modq(f_zero, g_zero) - h0);

    // setting the sum of h1_i = (b-f_zero)*g_zero+(b-1-g_zero)*f_zero
    rand_values[3 * NUM_SERVERS] = modq(
        rand_values[3 * NUM_SERVERS]
            + (mul_modq(modq(input_a - f_zero), g_zero) + mul_modq(modq(input_b - g_zero), f_zero))
            - h1,
    );

    // setting the sum of h2_i = (b-f_zero)*(b-1-g_zero)
    rand_values[4 * NUM_SERVERS] = modq(
        rand_values[4 * NUM_SERVERS] + mul_modq(modq(input_a - f_zero), modq(input_b - g_zero))
            - h2,
    );

    // setting a*b = c
    rand_values[7 * NUM_SERVERS] += (((a as i64) * (b as i64)) % (Q as i64)) as i32 - c;

    for iter in 0..NUM_SERVERS {
        snip_out[iter].f_zero_i = rand_values[iter];
        snip_out[iter].g_zero_i = rand_values[NUM_SERVERS + iter];

        snip_out[iter].h0_i = modq(rand_values[2 * NUM_SERVERS + iter]);
        snip_out[iter].h1_i = modq(rand_values[3 * NUM_SERVERS + iter]);
        snip_out[iter].h2_i = modq(rand_values[4 * NUM_SERVERS + iter]);

        snip_out[iter].a_i = rand_values[5 * NUM_SERVERS + iter];
        snip_out[iter].b_i = rand_values[6 * NUM_SERVERS + iter];
        snip_out[iter].c_i = rand_values[7 * NUM_SERVERS + iter];
    }
}
