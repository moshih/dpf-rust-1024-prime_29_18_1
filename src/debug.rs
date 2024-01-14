use crate::dpf::fill_rand_aes128_modq;
use crate::ntt::barrett_reduce;
use crate::params::{E_BYTES, NUM_SERVERS, Q};
use crate::snip::{mod_inverse, mul_shares_p2};

// only used for debug
pub fn sum_beaver_triple_debug(
    y_shares: &[i32],
    z_shares: &[i32],
    yz_shares: &mut [i32],
    rounds: usize,
) {
    // Create Beaver triples
    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;

    let mut a_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
    let mut b_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
    let mut c_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
    let a_shares = fill_rand_aes128_modq(&mut a_shares_u8, NUM_SERVERS);
    let b_shares = fill_rand_aes128_modq(&mut b_shares_u8, NUM_SERVERS);
    let c_shares = fill_rand_aes128_modq(&mut c_shares_u8, NUM_SERVERS);

    for iter in 0..NUM_SERVERS {
        a += a_shares[iter];
        b += b_shares[iter];
        c += c_shares[iter];
    }

    // setting a*b = c
    c_shares[NUM_SERVERS - 1] += (((a as i128) * (b as i128)) % (Q as i128)) as i32 - c;

    let mut d_shares = [0i32; NUM_SERVERS];
    let mut e_shares = [0i32; NUM_SERVERS];

    let mut d: i32;
    let mut e: i32;

    // one time calculation made at server startup
    let inv_servers = mod_inverse(NUM_SERVERS as i32, Q);

    for round_i in 0..rounds {
        d = 0;
        e = 0;

        for i in 0..NUM_SERVERS {
            d_shares[i] = barrett_reduce(y_shares[i * rounds + round_i] - a_shares[i]);
            e_shares[i] = barrett_reduce(z_shares[i * rounds + round_i] - b_shares[i]);

            d = barrett_reduce(d + d_shares[i]);
            e = barrett_reduce(e + e_shares[i]);
        }

        for iter in 0..NUM_SERVERS {
            yz_shares[iter * rounds + round_i] = mul_shares_p2(
                d,
                e,
                a_shares[iter],
                b_shares[iter],
                c_shares[iter],
                inv_servers,
            );
        }
    }
}

// only used for debug
pub fn sum_beaver_triple_single(y_shares: &[i32], z_shares: &[i32], yz_shares: &mut [i32]) {
    // Create Beaver triples
    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;

    let mut a_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
    let mut b_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
    let mut c_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
    let a_shares = fill_rand_aes128_modq(&mut a_shares_u8, NUM_SERVERS);
    let b_shares = fill_rand_aes128_modq(&mut b_shares_u8, NUM_SERVERS);
    let c_shares = fill_rand_aes128_modq(&mut c_shares_u8, NUM_SERVERS);

    for iter in 0..NUM_SERVERS {
        a += a_shares[iter];
        b += b_shares[iter];
        c += c_shares[iter];
    }

    // setting a*b = c
    c_shares[NUM_SERVERS - 1] += (((a as i128) * (b as i128)) % (Q as i128)) as i32 - c;

    let mut d_shares = [0i32; NUM_SERVERS];
    let mut e_shares = [0i32; NUM_SERVERS];

    let mut d: i32 = 0;
    let mut e: i32 = 0;

    // one time calculation made at server startup
    let inv_servers = mod_inverse(NUM_SERVERS as i32, Q);

    for i in 0..NUM_SERVERS {
        d_shares[i] = barrett_reduce(y_shares[i] - a_shares[i]);
        e_shares[i] = barrett_reduce(z_shares[i] - b_shares[i]);

        d = barrett_reduce(d + d_shares[i]);
        e = barrett_reduce(e + e_shares[i]);
    }

    for iter in 0..NUM_SERVERS {
        yz_shares[iter] = mul_shares_p2(
            d,
            e,
            a_shares[iter],
            b_shares[iter],
            c_shares[iter],
            inv_servers,
        );
    }
}

// only used for debug
pub fn get_sum_mod(input: &[i32]) -> i32 {
    let mut output: i32 = 0;
    for i in 0..input.len() {
        output = barrett_reduce(output + input[i]);
    }

    return output % Q;
}
