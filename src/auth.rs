use std::time::Instant;
use crate::debug::get_sum_mod;
use crate::dpf::{
    dpf_eval_lwe_block_new_all_sub, dpf_eval_lwe_seed_block_all_sub,
    dpf_eval_lwe_seed_block_get_bs, fill_rand_aes128_modq, fill_rand_aes128_modq_nr,
    fill_rand_aes128_modq_nr_1_by_seed, fill_rand_aes128_modq_nr_3_by_seed,
    fill_rand_aes128_modq_nr_6_by_seed, fill_rand_aes128_nr,
};
use crate::ntt::{barrett_reduce, mul_mod_mont};
use crate::params::{
    BT_INST1, BT_INST2_A, BT_INST2_B, E_BYTES, NOISE_BITS, NOISE_LEN, NUM_BLOCK, NUM_SERVERS,
    N_PARAM, Q, SEED_IV_LEN,
};
use crate::snip::{
    combine_bits, gen_r1_vec_sub, gen_r2_vec_sub, gen_r3_vec_sub, get_rand_coeff_seeds,
    mod_inverse, mul_shares_p2, separate_bits,
};

pub fn set_up_init_vars(
    buffer: i32,
    ori_message: i32,
    index: usize,
) -> (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<i32>,
    Vec<i8>,
    Vec<i32>,
    Vec<u8>,
    Vec<u8>,
    i32,
    usize,
) {
    // Setup of variables
    let mut a_vec = vec![0i32; NUM_BLOCK * N_PARAM];

    let b_vec_1d_u8 = vec![0u8; E_BYTES * N_PARAM];
    let s_vec_1d_u8 = vec![0u8; E_BYTES * N_PARAM * N_PARAM];
    let v_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];
    let noise_i32 = vec![0i32; NOISE_LEN];
    let noise_sign_i8 = vec![0i8; NUM_BLOCK * N_PARAM];

    let mut a_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut a_vec[..]);
    fill_rand_aes128_modq_nr(&mut a_vec_u8, E_BYTES * NUM_BLOCK * N_PARAM);

    let seeds = vec![0u8; SEED_IV_LEN * (NUM_SERVERS - 1)];
    let coeff_seeds = vec![0u8; SEED_IV_LEN];

    let message: i32 = (ori_message << 9) + buffer;

    return (
        b_vec_1d_u8,
        s_vec_1d_u8,
        v_vec_u8,
        noise_i32,
        noise_sign_i8,
        a_vec,
        seeds,
        coeff_seeds,
        message,
        index,
    );
}

pub fn gen_beaver_triples(
    seed: &[u8],
    bt_seeds: &mut [u8],
    correction: &mut [i32],
    instances: usize,
) {
    fill_rand_aes128_modq_nr_1_by_seed(
        &seed[0..16],
        &seed[16..32],
        bt_seeds,
        SEED_IV_LEN * NUM_SERVERS,
    );

    let mut a_sum = vec![0i32; instances];
    let mut b_sum = vec![0i32; instances];
    let mut c_sum = vec![0i32; instances];

    let mut a_temp_u8 = vec![0u8; E_BYTES * instances];
    let mut b_temp_u8 = vec![0u8; E_BYTES * instances];
    let mut c_temp_u8 = vec![0u8; E_BYTES * instances];
    for s_i in 0..NUM_SERVERS {
        //a_temp_u8.fill(0);
        //b_temp_u8.fill(0);
        //c_temp_u8.fill(0);
        for i in 0..a_temp_u8.len() {
            a_temp_u8[i] = 0;
        }
        for i in 0..b_temp_u8.len() {
            b_temp_u8[i] = 0;
        }
        for i in 0..c_temp_u8.len() {
            c_temp_u8[i] = 0;
        }

        fill_rand_aes128_modq_nr_3_by_seed(
            &bt_seeds[s_i * SEED_IV_LEN..s_i * SEED_IV_LEN + 16],
            &bt_seeds[s_i * SEED_IV_LEN + 16..s_i * SEED_IV_LEN + 32],
            &mut a_temp_u8,
            &mut b_temp_u8,
            &mut c_temp_u8,
            E_BYTES * instances,
            E_BYTES * instances,
            E_BYTES * instances,
        );
        let a_temp: &[i32] = bytemuck::cast_slice(&a_temp_u8);

        let b_temp: &[i32] = bytemuck::cast_slice(&b_temp_u8);
        let c_temp: &[i32] = bytemuck::cast_slice(&c_temp_u8);

        for i in 0..instances {
            a_sum[i] = barrett_reduce(a_sum[i] + a_temp[i]);
            b_sum[i] = barrett_reduce(b_sum[i] + b_temp[i]);

            if s_i < (NUM_SERVERS - 1) {
                c_sum[i] = barrett_reduce(c_sum[i] + c_temp[i]);
            }
        }
    }

    for i in 0..instances {
        // setting a*b = c
        correction[i] = barrett_reduce(mul_mod_mont(a_sum[i], b_sum[i]) - c_sum[i]);
    }
}

pub fn gen_beaver_triples2(
    seed: &[u8],
    bt_seeds: &mut [u8],
    correction_a: &mut [i32],
    correction_b: &mut [i32],
    instances_a: usize,
    instances_b: usize,
) {
    fill_rand_aes128_modq_nr_1_by_seed(
        &seed[0..16],
        &seed[16..32],
        bt_seeds,
        SEED_IV_LEN * NUM_SERVERS,
    );

    let mut a_sum_a = vec![0i32; instances_a];
    let mut b_sum_a = vec![0i32; instances_a];
    let mut c_sum_a = vec![0i32; instances_a];
    let mut a_sum_b = vec![0i32; instances_b];
    let mut b_sum_b = vec![0i32; instances_b];
    let mut c_sum_b = vec![0i32; instances_b];

    let mut a_temp_a_u8 = vec![0u8; E_BYTES * instances_a];
    let mut b_temp_a_u8 = vec![0u8; E_BYTES * instances_a];
    let mut c_temp_a_u8 = vec![0u8; E_BYTES * instances_a];
    let mut a_temp_b_u8 = vec![0u8; E_BYTES * instances_b];
    let mut b_temp_b_u8 = vec![0u8; E_BYTES * instances_b];
    let mut c_temp_b_u8 = vec![0u8; E_BYTES * instances_b];

    for s_i in 0..NUM_SERVERS {
        //a_temp_a_u8.fill(0);
        //b_temp_a_u8.fill(0);
        //c_temp_a_u8.fill(0);
        //a_temp_b_u8.fill(0);
        //b_temp_b_u8.fill(0);
        //c_temp_b_u8.fill(0);
        for i in 0..a_temp_a_u8.len() {
            a_temp_a_u8[i] = 0;
        }
        for i in 0..b_temp_a_u8.len() {
            b_temp_a_u8[i] = 0;
        }
        for i in 0..c_temp_a_u8.len() {
            c_temp_a_u8[i] = 0;
        }
        for i in 0..a_temp_b_u8.len() {
            a_temp_b_u8[i] = 0;
        }
        for i in 0..b_temp_b_u8.len() {
            b_temp_b_u8[i] = 0;
        }
        for i in 0..c_temp_b_u8.len() {
            c_temp_b_u8[i] = 0;
        }

        fill_rand_aes128_modq_nr_6_by_seed(
            &bt_seeds[s_i * SEED_IV_LEN..s_i * SEED_IV_LEN + 16],
            &bt_seeds[s_i * SEED_IV_LEN + 16..s_i * SEED_IV_LEN + 32],
            &mut a_temp_a_u8,
            &mut b_temp_a_u8,
            &mut c_temp_a_u8,
            &mut a_temp_b_u8,
            &mut b_temp_b_u8,
            &mut c_temp_b_u8,
            E_BYTES * instances_a,
            E_BYTES * instances_a,
            E_BYTES * instances_a,
            E_BYTES * instances_b,
            E_BYTES * instances_b,
            E_BYTES * instances_b,
        );
        let a_a_temp: &[i32] = bytemuck::cast_slice(&a_temp_a_u8);
        let b_a_temp: &[i32] = bytemuck::cast_slice(&b_temp_a_u8);
        let c_a_temp: &[i32] = bytemuck::cast_slice(&c_temp_a_u8);
        let a_b_temp: &[i32] = bytemuck::cast_slice(&a_temp_b_u8);
        let b_b_temp: &[i32] = bytemuck::cast_slice(&b_temp_b_u8);
        let c_b_temp: &[i32] = bytemuck::cast_slice(&c_temp_b_u8);

        for i in 0..instances_a {
            a_sum_a[i] = barrett_reduce(a_sum_a[i] + a_a_temp[i]);
            b_sum_a[i] = barrett_reduce(b_sum_a[i] + b_a_temp[i]);

            if s_i < (NUM_SERVERS - 1) {
                c_sum_a[i] = barrett_reduce(c_sum_a[i] + c_a_temp[i]);
            }
        }

        for i in 0..instances_b {
            a_sum_b[i] = barrett_reduce(a_sum_b[i] + a_b_temp[i]);
            b_sum_b[i] = barrett_reduce(b_sum_b[i] + b_b_temp[i]);

            if s_i < (NUM_SERVERS - 1) {
                c_sum_b[i] = barrett_reduce(c_sum_b[i] + c_b_temp[i]);
            }
        }
    }

    for i in 0..instances_a {
        // setting a*b = c
        correction_a[i] = barrett_reduce(mul_mod_mont(a_sum_a[i], b_sum_a[i]) - c_sum_a[i]);
    }

    for i in 0..instances_b {
        // setting a*b = c
        correction_b[i] = barrett_reduce(mul_mod_mont(a_sum_b[i], b_sum_b[i]) - c_sum_b[i]);
    }
}

pub fn run_beaver_triple(
    y_shares: &[i32],
    z_shares: &[i32],
    yz_shares: &mut [i32],
    a_shares: &[i32],
    b_shares: &[i32],
    c_shares: &[i32],
    rounds: usize,
    instances: usize,
    inv_servers: i32,
) {
    let mut d_shares = [0i32; NUM_SERVERS];
    let mut e_shares = [0i32; NUM_SERVERS];

    let mut d: i32;
    let mut e: i32;

    for round_i in 0..rounds {
        d = 0;
        e = 0;

        for i in 0..NUM_SERVERS {
            d_shares[i] = barrett_reduce(y_shares[i * rounds + round_i] - a_shares[i * instances]);
            e_shares[i] = barrett_reduce(z_shares[i * rounds + round_i] - b_shares[i * instances]);

            d = barrett_reduce(d + d_shares[i]);
            e = barrett_reduce(e + e_shares[i]);
        }

        for iter in 0..NUM_SERVERS {
            yz_shares[iter * rounds + round_i] = mul_shares_p2(
                d,
                e,
                a_shares[iter * instances],
                b_shares[iter * instances],
                c_shares[iter * instances],
                inv_servers,
            );
        }
    }
}

pub fn client_post_gen(
    noise_i32: &[i32],
    server_noise_bits: &mut [u32],
    bt_seeds_pt1: &mut [u8],
    correction_pt1: &mut [i32],
    bt_seeds_pt2: &mut [u8],
    correction_pt2a: &mut [i32],
    correction_pt2b: &mut [i32],
) {
    // separates the noise bits
    separate_bits(&noise_i32, server_noise_bits);
    let mut rand_seed = vec![0u8; SEED_IV_LEN];
    fill_rand_aes128_nr(&mut rand_seed, SEED_IV_LEN);

    gen_beaver_triples(&rand_seed, bt_seeds_pt1, correction_pt1, BT_INST1);

    fill_rand_aes128_nr(bt_seeds_pt2, SEED_IV_LEN * NUM_SERVERS);

    fill_rand_aes128_nr(&mut rand_seed, SEED_IV_LEN);
    gen_beaver_triples2(
        &rand_seed,
        bt_seeds_pt2,
        correction_pt2a,
        correction_pt2b,
        BT_INST2_A,
        BT_INST2_B,
    );
}

pub fn init_auth_client_vars() -> (Vec<u32>, Vec<u8>, Vec<i32>, Vec<u8>, Vec<i32>, Vec<i32>) {
    let server_noise_bits = vec![0u32; NUM_SERVERS * NOISE_LEN * NOISE_BITS];
    let bt_seeds_pt1 = vec![0u8; SEED_IV_LEN * NUM_SERVERS];
    let correction_pt1 = vec![0i32; BT_INST1];

    let bt_seeds_pt2 = vec![0u8; SEED_IV_LEN * NUM_SERVERS];

    let correction_pt2a = vec![0i32; BT_INST2_A];
    let correction_pt2b = vec![0i32; BT_INST2_B];

    return (
        server_noise_bits,
        bt_seeds_pt1,
        correction_pt1,
        bt_seeds_pt2,
        correction_pt2a,
        correction_pt2b,
    );
}

pub fn servers_auth_init_and_prep_eval(
    bt_seeds_pt1: &Vec<u8>,
    correction_pt1: &Vec<i32>,
    server_noise_bits: &Vec<u32>,
    coeff_seeds: &Vec<u8>,
    a_vec: &Vec<i32>,
    b_vec_1d_u8: &mut Vec<u8>,
    s_vec_1d_u8: &mut Vec<u8>,
    v_vec_u8: &mut Vec<u8>,
    noise_sign_i8: &mut Vec<i8>,
    seeds: &mut Vec<u8>,
    a_bt_u8: &mut Vec<u8>,
    b_bt_u8: &mut Vec<u8>,
    c_bt_u8: &mut Vec<u8>,
) -> (
    i32,
    Vec<i32>,
    Vec<i32>,
    Vec<i32>,
    Vec<i32>,
    Vec<i32>,
    Vec<i32>,
    [u8; 32],
    [u8; 32],
) {
    let start = Instant::now();
    // one time calculation made at server startup
    let inv_servers = mod_inverse(NUM_SERVERS as i32, Q);

    // Servers compute this
    //Compute beaver triples
    for s_i in 0..NUM_SERVERS {
        fill_rand_aes128_modq_nr_3_by_seed(
            &bt_seeds_pt1[s_i * SEED_IV_LEN..s_i * SEED_IV_LEN + 16],
            &bt_seeds_pt1[s_i * SEED_IV_LEN + 16..s_i * SEED_IV_LEN + 32],
            &mut a_bt_u8[s_i * E_BYTES * BT_INST1..(s_i + 1) * E_BYTES * BT_INST1],
            &mut b_bt_u8[s_i * E_BYTES * BT_INST1..(s_i + 1) * E_BYTES * BT_INST1],
            &mut c_bt_u8[s_i * E_BYTES * BT_INST1..(s_i + 1) * E_BYTES * BT_INST1],
            E_BYTES * BT_INST1,
            E_BYTES * BT_INST1,
            E_BYTES * BT_INST1,
        );
    }
    let c_bt: &mut [i32] = bytemuck::cast_slice_mut(c_bt_u8);

    // The correction vector for one server of the beaver triple
    for i in 0..BT_INST1 {
        c_bt[(NUM_SERVERS - 1) * BT_INST1 + i] = correction_pt1[i];
    }

    // step 2. c: Computing the error shares by multiplying bits by gadget
    let mut server_noise = vec![0i32; NUM_SERVERS * NOISE_LEN];
    for s_iter in 0..NUM_SERVERS {
        combine_bits(
            &server_noise_bits
                [s_iter * NOISE_LEN * NOISE_BITS..(s_iter + 1) * NOISE_LEN * NOISE_BITS],
            &mut server_noise[s_iter * NOISE_LEN..(s_iter + 1) * NOISE_LEN],
        );
    }

    // step 2. d: Verify shares add to point function
    let mut r1_seed = [0u8; SEED_IV_LEN];
    let mut r2_seed = [0u8; SEED_IV_LEN];
    let mut r3_seed = [0u8; SEED_IV_LEN];
    get_rand_coeff_seeds(&coeff_seeds, &mut r1_seed, &mut r2_seed, &mut r3_seed);

    let mut t_c0_alpha = vec![0i32; NUM_SERVERS * N_PARAM];
    let mut t_c1_alpha = vec![0i32; NUM_SERVERS * N_PARAM];
    let mut t_c2_alpha = vec![0i32; NUM_SERVERS * N_PARAM];

    let mut r1_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    // calculating eval part
    let mut r_c0_eval = vec![0i32; NUM_SERVERS];
    let mut r_c1_eval = vec![0i32; NUM_SERVERS];
    let mut r_c2_eval = vec![0i32; NUM_SERVERS];

    let mut table_sub = vec![0i32; NUM_BLOCK * N_PARAM];
    let mut b_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM * NUM_SERVERS];
    let mut s_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM * N_PARAM];

    for a_i in 0..N_PARAM {
        let mut r_e_c0_tmp = [0i32; NUM_SERVERS];
        let mut r_e_c1_tmp = [0i32; NUM_SERVERS];
        let mut r_e_c2_tmp = [0i32; NUM_SERVERS];

        //r1_vec_u8.fill(0);
        for i in 0..r1_vec_u8.len() {
            r1_vec_u8[i] = 0;
        }

        gen_r1_vec_sub(&r1_seed, &mut r1_vec_u8[..], a_i);
        let r1_vec: &mut [i32] = bytemuck::cast_slice_mut(&mut r1_vec_u8);

        // Eval code
        let mut server_c0_eval_tmp = [0i32; NUM_SERVERS];
        let mut server_c1_eval_tmp = [0i32; NUM_SERVERS];
        let mut server_c2_eval_tmp = [0i32; NUM_SERVERS];

        //table_sub.fill(0);
        for i in 0..table_sub.len() {
            table_sub[i] = 0;
        }

        dpf_eval_lwe_block_new_all_sub(
            a_i,
            &mut table_sub,
            &a_vec,
            &b_vec_1d_u8,
            &s_vec_1d_u8,
            &v_vec_u8,
        );

        for b_i in 0..NOISE_LEN {
            for server_i in 0..NUM_SERVERS {
                r_e_c0_tmp[server_i] = barrett_reduce(
                    server_noise[server_i * NOISE_LEN + b_i] * (noise_sign_i8[b_i] as i32)
                        + r_e_c0_tmp[server_i],
                );

                let mut temp: i32 = barrett_reduce(mul_mod_mont(
                    server_noise[server_i * NOISE_LEN + b_i] * (noise_sign_i8[b_i] as i32),
                    r1_vec[b_i],
                ));
                r_e_c1_tmp[server_i] = barrett_reduce(temp + r_e_c1_tmp[server_i]);

                temp = barrett_reduce(mul_mod_mont(temp, r1_vec[b_i]));
                r_e_c2_tmp[server_i] = barrett_reduce(temp + r_e_c2_tmp[server_i]);
            }

            // Eval code
            server_c0_eval_tmp[0] = barrett_reduce(server_c0_eval_tmp[0] + table_sub[b_i]);
            let mut temp_eval: i32 = barrett_reduce(mul_mod_mont(table_sub[b_i], r1_vec[b_i]));
            server_c1_eval_tmp[0] = barrett_reduce(server_c1_eval_tmp[0] + temp_eval);

            temp_eval = barrett_reduce(mul_mod_mont(temp_eval, r1_vec[b_i]));
            server_c2_eval_tmp[0] = barrett_reduce(server_c2_eval_tmp[0] + temp_eval);
        }

        for server_i in 0..NUM_SERVERS {
            t_c0_alpha[N_PARAM * server_i + a_i] = r_e_c0_tmp[server_i];
            t_c1_alpha[N_PARAM * server_i + a_i] = r_e_c1_tmp[server_i];
            t_c2_alpha[N_PARAM * server_i + a_i] = r_e_c2_tmp[server_i];
        }

        // Eval code
        for eval_s_iter in 1..NUM_SERVERS {
            //table_sub.fill(0);
            //b_vecs_1d_u8_eval.fill(0);
            //s_vecs_1d_u8_eval.fill(0);
            for i in 0..table_sub.len() {
                table_sub[i] = 0;
            }
            for i in 0..b_vecs_1d_u8_eval.len() {
                b_vecs_1d_u8_eval[i] = 0;
            }
            for i in 0..s_vecs_1d_u8_eval.len() {
                s_vecs_1d_u8_eval[i] = 0;
            }

            dpf_eval_lwe_seed_block_all_sub(
                a_i,
                &mut table_sub,
                &a_vec,
                &mut b_vecs_1d_u8_eval[..],
                &mut s_vecs_1d_u8_eval[..],
                &seeds[32 * (eval_s_iter - 1)..32 * (eval_s_iter)],
                &v_vec_u8,
            );

            for b_i in 0..NOISE_LEN {
                server_c0_eval_tmp[eval_s_iter] =
                    barrett_reduce(server_c0_eval_tmp[eval_s_iter] + table_sub[b_i]);
                let mut temp_eval: i32 = barrett_reduce(mul_mod_mont(table_sub[b_i], r1_vec[b_i]));
                server_c1_eval_tmp[eval_s_iter] =
                    barrett_reduce(server_c1_eval_tmp[eval_s_iter] + temp_eval);

                temp_eval = barrett_reduce(mul_mod_mont(temp_eval, r1_vec[b_i]));
                server_c2_eval_tmp[eval_s_iter] =
                    barrett_reduce(server_c2_eval_tmp[eval_s_iter] + temp_eval)
            }
        }

        for server_i in 0..NUM_SERVERS {
            r_c0_eval[server_i] =
                barrett_reduce(r_c0_eval[server_i] + server_c0_eval_tmp[server_i]);
            r_c1_eval[server_i] =
                barrett_reduce(r_c1_eval[server_i] + server_c1_eval_tmp[server_i]);
            r_c2_eval[server_i] =
                barrett_reduce(r_c2_eval[server_i] + server_c2_eval_tmp[server_i]);
        }
    }

    let total_duration = start.elapsed();
    println!("SAIaPE Total Time elapsed is: {:?}", total_duration);
    return (
        inv_servers,
        r_c0_eval,
        r_c1_eval,
        r_c2_eval,
        t_c0_alpha,
        t_c1_alpha,
        t_c2_alpha,
        r2_seed,
        r3_seed,
    );
}

pub fn servers_message_welformedness_check(
    b_vec_1d_u8: &Vec<u8>,
    seeds: &Vec<u8>,
    inv_servers: i32,
    a_bt: &[i32],
    b_bt: &[i32],
    c_bt: &[i32],
    t_c0_alpha: &Vec<i32>,
    t_c1_alpha: &Vec<i32>,
    t_c2_alpha: &Vec<i32>,
    r_c0_eval: &Vec<i32>,
    r_c1_eval: &Vec<i32>,
    r_c2_eval: &Vec<i32>,
) -> (Vec<u8>, bool) {
    // step 2. d. i. B.: Beaver Triple for Message Well-formedness
    let mut bt_c0_shares = vec![0i32; NUM_SERVERS * N_PARAM];
    let mut bt_c1_shares = vec![0i32; NUM_SERVERS * N_PARAM];
    let mut bt_c2_shares = vec![0i32; NUM_SERVERS * N_PARAM];

    let mut b_vec_1d_u8_total = vec![0u8; E_BYTES * N_PARAM * NUM_SERVERS];
    let mut s_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM * N_PARAM];
    for s_i in 0..(NUM_SERVERS - 1) {
        dpf_eval_lwe_seed_block_get_bs(
            0,
            &mut b_vec_1d_u8_total[E_BYTES * N_PARAM * s_i..E_BYTES * N_PARAM * (s_i + 1)],
            &mut s_vecs_1d_u8_eval[..],
            &seeds[32 * (s_i)..32 * (s_i + 1)],
        );
    }
    for i in 0..E_BYTES * N_PARAM {
        b_vec_1d_u8_total[E_BYTES * N_PARAM * (NUM_SERVERS - 1) + i] = b_vec_1d_u8[i];
    }
    let b_vec_1d_total: &[i32] = bytemuck::cast_slice(&b_vec_1d_u8_total);

    run_beaver_triple(
        &b_vec_1d_total[..],
        &t_c0_alpha,
        &mut bt_c0_shares,
        &a_bt,
        &b_bt,
        &c_bt,
        N_PARAM,
        BT_INST1,
        inv_servers,
    );

    run_beaver_triple(
        &b_vec_1d_total[..],
        &t_c1_alpha,
        &mut bt_c1_shares,
        &a_bt[N_PARAM..],
        &b_bt[N_PARAM..],
        &c_bt[N_PARAM..],
        N_PARAM,
        BT_INST1,
        inv_servers,
    );

    run_beaver_triple(
        &b_vec_1d_total[..],
        &t_c2_alpha,
        &mut bt_c2_shares,
        &a_bt[2 * N_PARAM..],
        &b_bt[2 * N_PARAM..],
        &c_bt[2 * N_PARAM..],
        N_PARAM,
        BT_INST1,
        inv_servers,
    );

    let mut bt_c0_shares_sum = [0i32; NUM_SERVERS];
    let mut bt_c1_shares_sum = [0i32; NUM_SERVERS];
    let mut bt_c2_shares_sum = [0i32; NUM_SERVERS];
    for s_i in 0..NUM_SERVERS {
        for i in 0..N_PARAM {
            bt_c0_shares_sum[s_i] =
                barrett_reduce(bt_c0_shares_sum[s_i] + bt_c0_shares[s_i * N_PARAM + i]);
            bt_c1_shares_sum[s_i] =
                barrett_reduce(bt_c1_shares_sum[s_i] + bt_c1_shares[s_i * N_PARAM + i]);
            bt_c2_shares_sum[s_i] =
                barrett_reduce(bt_c2_shares_sum[s_i] + bt_c2_shares[s_i * N_PARAM + i]);
        }
    }

    let mut m_0_shares = [0i32; NUM_SERVERS];
    let mut m_1_shares = [0i32; NUM_SERVERS];
    let mut m_2_shares = [0i32; NUM_SERVERS];

    for s_i in 0..NUM_SERVERS {
        m_0_shares[s_i] = barrett_reduce(r_c0_eval[s_i] + bt_c0_shares_sum[s_i]);
        m_1_shares[s_i] = barrett_reduce(r_c1_eval[s_i] + bt_c1_shares_sum[s_i]);
        m_2_shares[s_i] = barrett_reduce(r_c2_eval[s_i] + bt_c2_shares_sum[s_i]);
    }

    let mut m_02_shares = [0i32; NUM_SERVERS];
    let mut m_11_shares = [0i32; NUM_SERVERS];
    run_beaver_triple(
        &m_0_shares[..],
        &m_2_shares,
        &mut m_02_shares,
        &a_bt[3 * N_PARAM..],
        &b_bt[3 * N_PARAM..],
        &c_bt[3 * N_PARAM..],
        1,
        BT_INST1,
        inv_servers,
    );
    run_beaver_triple(
        &m_1_shares[..],
        &m_1_shares,
        &mut m_11_shares,
        &a_bt[3 * N_PARAM + 1..],
        &b_bt[3 * N_PARAM + 1..],
        &c_bt[3 * N_PARAM + 1..],
        1,
        BT_INST1,
        inv_servers,
    );

    let mut m_11_02_shares = [0i32; NUM_SERVERS];
    for s_i in 0..NUM_SERVERS {
        m_11_02_shares[s_i] = barrett_reduce(m_11_shares[s_i] - m_02_shares[s_i]);
    }

    let mut passed = true;

    if get_sum_mod(&m_11_02_shares) != 0 {
        println!(
            "M_11_02_shares is NOT ZERO {}",
            get_sum_mod(&m_11_02_shares)
        );
        passed = false;
    }

    return (b_vec_1d_u8_total, passed);
}

pub fn server_b_e_check(
    r2_seed: &[u8],
    r3_seed: &[u8],
    server_noise_bits: &Vec<u32>,
    bt_seeds_pt2: &Vec<u8>,
    correction_pt2a: &Vec<i32>,
    correction_pt2b: &Vec<i32>,
    inv_servers: i32,
    b_vec_1d_total: &[i32],
) -> bool {
    // Part 2 .e. : Verify b and e ̄ are binary-valued:
    //A server creates a secret sharing of 1
    let mut one_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
    fill_rand_aes128_modq(&mut one_shares_u8, NUM_SERVERS - 1);
    let one_shares: &mut [i32] = bytemuck::cast_slice_mut(&mut one_shares_u8);

    one_shares[NUM_SERVERS - 1] = 1;
    for i in 0..NUM_SERVERS - 1 {
        one_shares[NUM_SERVERS - 1] = barrett_reduce(one_shares[NUM_SERVERS - 1] - one_shares[i]);
    }

    let mut r2_vec_u8 = vec![0u8; E_BYTES * N_PARAM];
    gen_r2_vec_sub(&r2_seed, &mut r2_vec_u8);
    let r2_vec: &[i32] = bytemuck::cast_slice(&r2_vec_u8);

    let mut r2_b_shares = vec![0i32; NUM_SERVERS * N_PARAM];
    let mut one_b_shares = vec![0i32; NUM_SERVERS * N_PARAM];

    for i in 0..N_PARAM {
        for s_i in 0..NUM_SERVERS {
            r2_b_shares[s_i * N_PARAM + i] =
                mul_mod_mont(r2_vec[i], b_vec_1d_total[s_i * N_PARAM + i]);
            one_b_shares[s_i * N_PARAM + i] =
                barrett_reduce(one_shares[s_i] - b_vec_1d_total[s_i * N_PARAM + i]);
        }
    }

    let mut r3_vec_u8 = vec![0u8; E_BYTES * NOISE_LEN * NOISE_BITS];
    gen_r3_vec_sub(&r3_seed, &mut r3_vec_u8);
    let r3_vec: &[i32] = bytemuck::cast_slice(&r3_vec_u8);
    // let mut server_noise_bits = vec![0u32; NUM_SERVERS * NOISE_LEN * NOISE_BITS];

    let mut r3_e_shares = vec![0i32; NUM_SERVERS * NOISE_LEN * NOISE_BITS];
    let mut one_e_shares = vec![0i32; NUM_SERVERS * NOISE_LEN * NOISE_BITS];
    for i in 0..NOISE_LEN * NOISE_BITS {
        for s_i in 0..NUM_SERVERS {
            r3_e_shares[s_i * NOISE_LEN * NOISE_BITS + i] = mul_mod_mont(
                r3_vec[i],
                server_noise_bits[s_i * NOISE_LEN * NOISE_BITS + i] as i32,
            );
            one_e_shares[s_i * NOISE_LEN * NOISE_BITS + i] = barrett_reduce(
                one_shares[s_i] - server_noise_bits[s_i * NOISE_LEN * NOISE_BITS + i] as i32,
            );
        }
    }

    let mut b_snip_shares = [0i32; NUM_SERVERS * N_PARAM];
    let mut e_snip_shares = [0i32; NUM_SERVERS * NOISE_LEN * NOISE_BITS];

    let mut a_bt_a_u8 = vec![0u8; E_BYTES * NUM_SERVERS * N_PARAM];
    let mut b_bt_a_u8 = vec![0u8; E_BYTES * NUM_SERVERS * N_PARAM];
    let mut c_bt_a_u8 = vec![0u8; E_BYTES * NUM_SERVERS * N_PARAM];
    let mut a_bt_b_u8 = vec![0u8; E_BYTES * NUM_SERVERS * NOISE_LEN * NOISE_BITS];
    let mut b_bt_b_u8 = vec![0u8; E_BYTES * NUM_SERVERS * NOISE_LEN * NOISE_BITS];
    let mut c_bt_b_u8 = vec![0u8; E_BYTES * NUM_SERVERS * NOISE_LEN * NOISE_BITS];

    for s_i in 0..NUM_SERVERS {
        fill_rand_aes128_modq_nr_6_by_seed(
            &bt_seeds_pt2[s_i * SEED_IV_LEN..s_i * SEED_IV_LEN + 16],
            &bt_seeds_pt2[s_i * SEED_IV_LEN + 16..s_i * SEED_IV_LEN + 32],
            &mut a_bt_a_u8[s_i * E_BYTES * BT_INST2_A..(s_i + 1) * E_BYTES * BT_INST2_A],
            &mut b_bt_a_u8[s_i * E_BYTES * BT_INST2_A..(s_i + 1) * E_BYTES * BT_INST2_A],
            &mut c_bt_a_u8[s_i * E_BYTES * BT_INST2_A..(s_i + 1) * E_BYTES * BT_INST2_A],
            &mut a_bt_b_u8[s_i * E_BYTES * BT_INST2_B..(s_i + 1) * E_BYTES * BT_INST2_B],
            &mut b_bt_b_u8[s_i * E_BYTES * BT_INST2_B..(s_i + 1) * E_BYTES * BT_INST2_B],
            &mut c_bt_b_u8[s_i * E_BYTES * BT_INST2_B..(s_i + 1) * E_BYTES * BT_INST2_B],
            E_BYTES * BT_INST2_A,
            E_BYTES * BT_INST2_A,
            E_BYTES * BT_INST2_A,
            E_BYTES * BT_INST2_B,
            E_BYTES * BT_INST2_B,
            E_BYTES * BT_INST2_B,
        );
    }
    let a_bt_a: &[i32] = bytemuck::cast_slice(&a_bt_a_u8);
    let b_bt_a: &[i32] = bytemuck::cast_slice(&b_bt_a_u8);
    let a_bt_b: &[i32] = bytemuck::cast_slice(&a_bt_b_u8);
    let b_bt_b: &[i32] = bytemuck::cast_slice(&b_bt_b_u8);
    let c_bt_a: &mut [i32] = bytemuck::cast_slice_mut(&mut c_bt_a_u8);
    let c_bt_b: &mut [i32] = bytemuck::cast_slice_mut(&mut c_bt_b_u8);

    for i in 0..BT_INST2_A {
        c_bt_a[(NUM_SERVERS - 1) * BT_INST2_A + i] = correction_pt2a[i];
    }

    for i in 0..BT_INST2_B {
        c_bt_b[(NUM_SERVERS - 1) * BT_INST2_B + i] = correction_pt2b[i];
    }

    run_beaver_triple(
        &r2_b_shares[..],
        &one_b_shares,
        &mut b_snip_shares,
        a_bt_a,
        b_bt_a,
        c_bt_a,
        BT_INST2_A,
        BT_INST2_A,
        inv_servers,
    );

    run_beaver_triple(
        &r3_e_shares[..],
        &one_e_shares,
        &mut e_snip_shares,
        a_bt_b,
        b_bt_b,
        c_bt_b,
        BT_INST2_B,
        BT_INST2_B,
        inv_servers,
    );

    let mut m_sum = [0i32; NUM_SERVERS];
    for s_i in 0..NUM_SERVERS {
        for i in 0..BT_INST2_A {
            m_sum[s_i] = barrett_reduce(m_sum[s_i] + b_snip_shares[s_i * BT_INST2_A + i]);
        }
        for i in 0..BT_INST2_B {
            m_sum[s_i] = barrett_reduce(m_sum[s_i] + e_snip_shares[s_i * BT_INST2_B + i]);
        }
    }

    let mut passed = true;
    if get_sum_mod(&m_sum) != 0 {
        println!("ERROR m_sum sum is {}", get_sum_mod(&m_sum));
        passed = false;
    }

    return passed;
}
