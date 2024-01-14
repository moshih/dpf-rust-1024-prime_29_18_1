use rand::Rng;

//mod params;
use crate::params::*;

use crate::inv_zeta::*;
use crate::zeta::*;

const BARRETT_REDUCE_FACTOR: usize = 60;
#[allow(dead_code)]
const ZETA_INV_FINAL: u32 = 465862641;

#[allow(dead_code)]
const MONT: u32 = 535035897;
const MONT_S32: i32 = 535035897;
#[allow(dead_code)]
const QINV_S64: i64 = 3757834241;
const QINV_S128: i128 = 3757834241;
#[allow(dead_code)]
const QINV_S32: i32 = QINV_S64 as i32;

pub fn vec_mul_ntru(a_vec: &[u32], s_vec: &[u32], output: &mut [u32]) {
    for i in 0..N_PARAM {
        output[i] = 0;
    }

    let mut deg: usize;
    let mut temp: u32;
    for i in 0..N_PARAM {
        for j in 0..N_PARAM {
            deg = (i + j) % N_PARAM;
            temp = a_vec[i] * s_vec[j];

            if ((i + j) / N_PARAM) % 2 == 1 {
                temp = 0 - temp;
            }

            output[deg] = output[deg] + temp;
        }
    }
}

pub fn mod_128(input: i128) -> i128 {
    let q128: i128 = Q as i128;
    return ((input % q128) + q128) % q128;
}

pub fn mod_64(input: i64) -> i64 {
    let q64: i64 = Q as i64;
    return ((input % q64) + q64) % q64;
}

#[allow(dead_code)]
pub fn vec_mul_ntru_i32(a_vec: &[i32], s_vec: &[i32], output: &mut [i32]) {
    for i in 0..N_PARAM {
        output[i] = 0;
    }

    let mut deg: usize;
    let mut temp: i64;
    for i in 0..N_PARAM {
        for j in 0..N_PARAM {
            deg = (i + j) % N_PARAM;
            temp = mod_64(a_vec[i] as i64) * mod_64(s_vec[j] as i64);
            temp = mod_64(temp);

            if ((i + j) / N_PARAM) % 2 == 1 {
                temp = mod_64((Q as i64) - temp);
            }

            output[deg] = modq(output[deg] + (temp as i32));
        }
    }
}

pub fn barrett_reduce(a: i32) -> i32 {
    let mut t: i64;
    let v: i64 = ((1 as i64) << BARRETT_REDUCE_FACTOR) / (Q as i64) + 1;

    t = v * (a as i64);
    t >>= BARRETT_REDUCE_FACTOR;
    t *= Q as i64;

    return a - (t as i32);
}

#[allow(dead_code)]
pub fn poly_reduce(r: &mut [i32]) {
    for i in 0..N_PARAM {
        r[i] = barrett_reduce(r[i]);
    }
}

pub fn montgomery_reduce(a: i64) -> i32 {
    let mut t: i64;
    let u: i32;

    u = ((a as i128) * QINV_S128) as i32;

    t = (u as i64) * (Q as i64);
    t = a - t;
    t >>= E_BITS;

    return t as i32;
}

pub fn mul_mod_mont(a: i32, b: i32) -> i32 {
    let prod = (a as i64) * (b as i64);
    let temp32 = montgomery_reduce(prod);
    let temp64 = (temp32 as i64) * (DW_MODQ);
    return montgomery_reduce(temp64);
}

pub fn fqmul(a: i32, b: i32) -> i32 {
    return montgomery_reduce((a as i64) * (b as i64));
}

pub fn basemul(r: &mut [i32], a: &[i32], b: &[i32], zeta: i32) {
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);

    r[1] = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);

    r[0] = barrett_reduce(r[0]);
    r[1] = barrett_reduce(r[1]);
}


pub fn poly_basemul(r: &mut [i32], a: &[i32], b: &[i32]) {
    for i in 0..N_PARAM / 4 {
        basemul(
            &mut r[4 * i..],
            &a[4 * i..],
            &b[4 * i..],
            ZETAS[N_PARAM / 4 + i],
        );
        basemul(
            &mut r[4 * i + 2..],
            &a[4 * i + 2..],
            &b[4 * i + 2..],
            -ZETAS[N_PARAM / 4 + i],
        );
    }
}

pub fn poly_basemul_index(r: &mut [i32], a: &[i32], b: &[i32], _index: usize) {
    for i in 0..N_PARAM / 4 {
        basemul(
            &mut r[4 * i..],
            &a[4 * i..],
            &b[4 * i..],
            ZETAS[N_PARAM / 4 + i],
        );
        basemul(
            &mut r[4 * i + 2..],
            &a[4 * i + 2..],
            &b[4 * i + 2..],
            -ZETAS[N_PARAM / 4 + i],
        );
    }
}

#[allow(dead_code)]
pub fn poly_frommont_one(r: &mut [i32]) {
    for i in 0..N_PARAM {
        r[i] = mul_modq(montgomery_reduce(r[i] as i64), MONT_S32);
    }
}

#[allow(dead_code)]
pub fn ntt(r: &mut [i32]) {
    let mut t: i32;
    let mut zeta: i32;

    let mut j: usize;
    let mut k: usize = 1;

    let mut len: usize = N_PARAM / 2;
    while len >= 2 {
        let mut start: usize = 0;
        while start < N_PARAM {
            zeta = ZETAS[k];
            k += 1;

            j = start;
            while j < (start + len) {
                t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;

                j += 1;
            }
            start = j + len;
        }
        len >>= 1;
    }
}

pub fn invntt(r: &mut [i32]) {

    let mut t: i32;
    let mut zeta: i32;

    let mut j: usize;
    let mut k: usize = 0;

    let mut len: usize = 2;
    while len <= N_PARAM / 2 {
        let mut start: usize = 0;
        while start < N_PARAM {
            zeta = ZETAS_INV[k];
            k += 1;

            j = start;
            while j < (start + len) {
                t = r[j];

                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = t - r[j + len];
                r[j + len] = fqmul(zeta, r[j + len]);

                j += 1;
            }
            start = j + len;
        }
        len <<= 1;
    }

    for iter in 0..N_PARAM {
        r[iter] = fqmul(r[iter], ZETAS_INV[N_PARAM / 2 - 1]);
        r[iter] = montgomery_reduce(r[iter] as i64);
    }
}

pub fn invntt_index(r: &mut [i32], index: usize) {
    let mut t: i32;
    let mut zeta: i32;

    let mut j: usize;
    let mut k: usize = 0;

    let mut len: usize = 2;
    while len <= N_PARAM / 2 {
        let mut start: usize = 0;
        while start < N_PARAM {
            zeta = ZETAS_INV[k];
            k += 1;

            j = start;
            while j < (start + len) {
                t = r[j];

                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = t - r[j + len];
                r[j + len] = fqmul(zeta, r[j + len]);

                if (len == N_PARAM / 2) && (j == index) {
                    r[index] = fqmul(r[index], ZETAS_INV[N_PARAM / 2 - 1]);
                    r[index] = montgomery_reduce(r[index] as i64);
                    return;
                }
                j += 1;
            }
            start = j + len;
        }
        len <<= 1;
    }

    {
        r[index] = fqmul(r[index], ZETAS_INV[N_PARAM / 2 - 1]);
        r[index] = montgomery_reduce(r[index] as i64);
    }
}

#[allow(dead_code)]
pub fn invntt_one(r: &mut [i32]) {
    let mut t: i32;
    let mut zeta: i32;

    let mut j: usize;
    let mut k: usize = 0;

    let mut len: usize = 2;
    while len <= N_PARAM / 2 {
        let mut start: usize = 0;
        while start < N_PARAM {
            zeta = ZETAS_INV[k];
            k += 1;

            j = start;
            while j < (start + len) {
                t = r[j];

                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = t - r[j + len];
                r[j + len] = fqmul(zeta, r[j + len]);

                j += 1;
            }
            start = j + len;
        }
        len <<= 1;
    }

    for iter in 0..N_PARAM {
        r[iter] = fqmul(r[iter], ZETAS_INV[N_PARAM / 2 - 1]);
    }
}


#[allow(dead_code)]
pub fn poly_ntt(r: &mut [i32]) {
    ntt(r);
    poly_reduce(r);
}

pub fn poly_invntt(r: &mut [i32]) {
    invntt(r);
}

pub fn poly_invntt_index(r: &mut [i32], index: usize) {
    invntt_index(r, index);
}

#[allow(dead_code)]
pub fn ntt_base_test() {
    let mut pass: bool = true;
    let mut rng = rand::thread_rng();

    let mut polya = vec![0i32; N_PARAM];
    let mut polyb = vec![0i32; N_PARAM];
    for i in 0..N_PARAM {
        polya[i] = modq(rng.gen::<i32>());
    }

    polyb.copy_from_slice(&polya[0..N_PARAM]);

    poly_ntt(&mut polyb);
    poly_invntt(&mut polyb);
    poly_frommont_one(&mut polyb);

    for i in 0..N_PARAM {
        polya[i] = modq(polya[i]);
        polyb[i] = modq(polyb[i]);
        if polya[i] != polyb[i] {
            println!("error at {} got {} instead of {}", i, polyb[i], polya[i]);
            pass = false;
            if i > 5 {
                break;
            }
        }
    }

    if pass {
        println!("PASSED NTT BASE TEST");
    } else {
        println!("FAILED!!!!!! NTT BASE TEST");
    }
}

#[allow(dead_code)]
pub fn ntt_mul_test() {
    let mut pass = true;
    let mut rng = rand::thread_rng();

    let mut polya = vec![0i32; N_PARAM];
    let mut polyb = vec![0i32; N_PARAM];
    let mut polyc_ntru = vec![0i32; N_PARAM];
    let mut polyc_nttmul = vec![0i32; N_PARAM];
    for i in 0..N_PARAM {
        polya[i] = modq(rng.gen::<i32>());
        polyb[i] = modq(rng.gen::<i32>());

        //polya[i] = 0;
        //polyb[i] = 0;

        //polya[i] = rng.gen::<i32>();
        //polyb[i] = rng.gen::<i32>();
    }
    //polya[0] = Q-1;
    //polyb[0] = Q-1;
    //polya[1] = Q-1;
    //polyb[1] = Q-1;

    vec_mul_ntru_i32(&polya[..], &polyb[..], &mut polyc_ntru[..]);

    poly_ntt(&mut polya[..]);
    poly_ntt(&mut polyb[..]);

    poly_basemul(&mut polyc_nttmul[..], &polya[..], &polyb[..]);

    /*
        poly_frommont_one(&mut polyb);
        for i in 0..N_PARAM {
            polyc_nttmul[i] = polyb[i];
        }
    */
    poly_invntt(&mut polyc_nttmul[..]);
    for i in 0..N_PARAM {
        polyc_nttmul[i] = mul_modq(polyc_nttmul[i], MONT_S32);
    }

    for i in 0..N_PARAM {
        polyc_ntru[i] = modq(polyc_ntru[i]);
        polyc_nttmul[i] = modq(polyc_nttmul[i]);
        if polyc_ntru[i] != polyc_nttmul[i] {
            println!(
                "NTT MUL error at {} got {} instead of {}",
                i, polyc_nttmul[i], polyc_ntru[i]
            );
            pass = false;
            if i > 5 {
                break;
            }
        }
    }

    if pass {
        println!("PASSED NTT MUL TEST");
    } else {
        println!("FAILED!!!!!! NTT MUL TEST");
    }
}

// should be only used for debug
#[allow(dead_code)]
pub fn pos_mod(input: i32) -> i32 {
    (barrett_reduce(input) + Q) % Q
}
