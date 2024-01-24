use crate::auth::{client_post_gen, gen_beaver_triples, gen_beaver_triples2, set_up_init_vars};
use crate::dpf::{dpf_eval_lwe_block_new, dpf_eval_lwe_block_new_all_sub, dpf_eval_lwe_block_new_all_sub_timing, dpf_eval_lwe_seed_block, dpf_eval_lwe_seed_block_all_sub, dpf_eval_lwe_seed_block_all_sub_timing, dpf_eval_lwe_seed_block_get_bs, dpf_gen_lwe_seed_block_new_sq_compact, dpf_gen_lwe_seed_block_new_sq_compact_veri, fill_rand_aes128_modq, fill_rand_aes128_modq_nr_3_by_seed, fill_rand_aes128_modq_nr_6_by_seed, fill_rand_aes128_nr};
use crate::ntt::{barrett_reduce, mul_mod_mont};
use crate::params::{
    BT_INST1, BT_INST2_A, BT_INST2_B, E_BYTES, NOISE_BITS, NOISE_LEN, NUM_BLOCK, NUM_SERVERS,
    N_PARAM, Q, SEED_IV_LEN,
};
use crate::snip::{combine_bits, combine_bits_numblocks, gen_r1_vec_sub, gen_r2_vec_sub, gen_r3_vec_sub, get_rand_coeff_seeds, mod_inverse, mul_shares_p2, separate_bits, separate_bits_single_block};
use std::time::Instant;
use std::{thread, time};

pub fn run_beaver_triple_timing(
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

        // for i in 0..NUM_SERVERS {
        for i in 0..1 {
            d_shares[i] = barrett_reduce(y_shares[i * rounds + round_i] - a_shares[i * instances]);
            e_shares[i] = barrett_reduce(z_shares[i * rounds + round_i] - b_shares[i * instances]);

            d = barrett_reduce(d + d_shares[i]);
            e = barrett_reduce(e + e_shares[i]);
        }

        // for iter in 0..NUM_SERVERS {
        for iter in 0..1 {
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

// Client DPF Gen functions timing, does not produce the error bits or beaver triples
// (thats what is in dpf_gen_lwe_seed_block_new_sq_compact_snip_aftergen_timings)
pub fn dpf_gen_lwe_seed_block_new_sq_compact_snip_timings(gen_iterations: usize) {
    let buffer: i32 = 128;
    let ori_message: i32 = 101;
    let message: i32 = (ori_message << 9) + buffer;
    let index: usize = 0; //2*512*512+13;//2000;

    let (
        mut b_vec_1d_u8,
        mut s_vec_1d_u8,
        mut v_vec_u8,
        mut noise_i32,
        mut noise_sign_i8,
        a_vec,
        mut seeds,
        mut coeff_seeds,
        _message,
        _index,
    ) = set_up_init_vars(buffer, ori_message, index);

    let gen_start = Instant::now();
    for _iter in 0..gen_iterations {
        dpf_gen_lwe_seed_block_new_sq_compact_veri(
            index,
            message,
            &a_vec[..],
            &mut b_vec_1d_u8[..],
            &mut s_vec_1d_u8[..],
            &mut v_vec_u8[..],
            &mut noise_i32[..],
            &mut noise_sign_i8[..],
            &mut seeds[..],
            &mut coeff_seeds[..],
            true,
        );
    }
    let gen_duration = gen_start.elapsed();
    println!("seed_compact GEN Time elapsed is: {:?}", gen_duration);
}

pub fn client_post_gen_timing(
    noise_i32: &[i32],
    server_noise_bits: &mut [u32],
    bt_seeds_pt1: &mut [u8],
    correction_pt1: &mut [i32],
    bt_seeds_pt2: &mut [u8],
    correction_pt2a: &mut [i32],
    correction_pt2b: &mut [i32],
) {
    // separates the noise bits
    for i in 0..NUM_BLOCK {
        separate_bits_single_block(&noise_i32, server_noise_bits);
    }
    let mut rand_seed = vec![0u8; SEED_IV_LEN];
    fill_rand_aes128_nr(&mut rand_seed, SEED_IV_LEN);

    gen_beaver_triples(&rand_seed, bt_seeds_pt1, correction_pt1, BT_INST1);

    fill_rand_aes128_nr(bt_seeds_pt2, SEED_IV_LEN * NUM_SERVERS);

    fill_rand_aes128_nr(&mut rand_seed, SEED_IV_LEN);

    gen_beaver_triples(&rand_seed, bt_seeds_pt2, correction_pt2a, BT_INST2_A);

    for i in 0..NUM_BLOCK {
        gen_beaver_triples(
            &rand_seed,
            bt_seeds_pt2,
            correction_pt2b,
            BT_INST2_B / NUM_BLOCK,
        );
    }
}

pub fn client_post_gen_timing_single(
    noise_i32: &[i32],
    server_noise_bits: &mut [u32],
    bt_seeds_pt1: &mut [u8],
    correction_pt1: &mut [i32],
    bt_seeds_pt2: &mut [u8],
    correction_pt2a: &mut [i32],
    correction_pt2b: &mut [i32],
) {

    let mut rand_seed = vec![0u8; SEED_IV_LEN];
    fill_rand_aes128_nr(&mut rand_seed, SEED_IV_LEN);

    gen_beaver_triples(&rand_seed, bt_seeds_pt1, correction_pt1, BT_INST1);

    fill_rand_aes128_nr(bt_seeds_pt2, SEED_IV_LEN * NUM_SERVERS);

    fill_rand_aes128_nr(&mut rand_seed, SEED_IV_LEN);

    gen_beaver_triples(&rand_seed, bt_seeds_pt2, correction_pt2a, BT_INST2_A);

}

pub fn client_post_gen_timing_numblock(
    noise_i32: &[i32],
    server_noise_bits: &mut [u32],
    bt_seeds_pt1: &mut [u8],
    correction_pt1: &mut [i32],
    bt_seeds_pt2: &mut [u8],
    correction_pt2a: &mut [i32],
    correction_pt2b: &mut [i32],
) {
    // separates the noise bits
    //for i in 0..NUM_BLOCK {
    for i in 0..1 {
        separate_bits_single_block(&noise_i32, server_noise_bits);
    }
    let mut rand_seed = vec![0u8; SEED_IV_LEN];


    //for i in 0..NUM_BLOCK {
    for i in 0..1 {
        gen_beaver_triples(
            &rand_seed,
            bt_seeds_pt2,
            correction_pt2b,
            BT_INST2_B / NUM_BLOCK,
        );
    }
}

pub fn dpf_gen_lwe_seed_block_new_sq_compact_snip_aftergen_timings(gen_iterations: usize) {
    // Setup of variables
    // NOISE_LEN: usize = NUM_BLOCK * N_PARAM;
    let noise_i32 = vec![0i32; NOISE_LEN / NUM_BLOCK];
    let mut server_noise_bits = vec![0u32; NUM_SERVERS * NOISE_LEN / NUM_BLOCK * NOISE_BITS];
    let mut bt_seeds_pt1 = vec![0u8; SEED_IV_LEN * NUM_SERVERS];
    let mut correction_pt1 = vec![0i32; BT_INST1];

    let mut bt_seeds_pt2 = vec![0u8; SEED_IV_LEN * NUM_SERVERS];

    let mut correction_pt2a = vec![0i32; BT_INST2_A];
    let mut correction_pt2b = vec![0i32; BT_INST2_B / NUM_BLOCK];

    ////////////////////////////////////////////////////////////
    /*
    let gen_start = Instant::now();
    for _iter_test in 0..gen_iterations {
        client_post_gen_timing(
            &noise_i32,
            &mut server_noise_bits,
            &mut bt_seeds_pt1,
            &mut correction_pt1,
            &mut bt_seeds_pt2,
            &mut correction_pt2a,
            &mut correction_pt2b,
        );
    }
    let gen_duration = gen_start.elapsed();
    println!("seed_compact AFTER GEN Time elapsed is: {:?}", gen_duration);

     */
    let gen_start = Instant::now();
    for _iter_test in 0..gen_iterations {
        client_post_gen_timing_single(
            &noise_i32,
            &mut server_noise_bits,
            &mut bt_seeds_pt1,
            &mut correction_pt1,
            &mut bt_seeds_pt2,
            &mut correction_pt2a,
            &mut correction_pt2b,
        );
    }
    let gen_duration = gen_start.elapsed();
    println!("seed_compact AFTER GEN Time single elapsed is: {:?}", gen_duration);
    let gen_start_num_block = Instant::now();
    for _iter_test in 0..gen_iterations {
        client_post_gen_timing_numblock(
            &noise_i32,
            &mut server_noise_bits,
            &mut bt_seeds_pt1,
            &mut correction_pt1,
            &mut bt_seeds_pt2,
            &mut correction_pt2a,
            &mut correction_pt2b,
        );
    }
    let gen_duration_num_block = gen_start_num_block.elapsed();
    println!("seed_compact AFTER GEN Time (got numblock: {:?}) elapsed is: {:?}", gen_duration_num_block, gen_duration_num_block* NUM_BLOCK as u32);
}

// The computation of the DPF Eval single for the (n-1) servers that have seeds
pub fn block_compact_timings_client(iterations: usize) {
    // Setup of variables
    let buffer: i32 = 128;
    let ori_message: i32 = 101;
    let message: i32 = (ori_message << 9) + buffer;
    let index: usize = 0; //2*512*512+13;//2000;

    let (
        mut b_vec_1d_u8,
        mut s_vec_1d_u8,
        mut v_vec_u8,
        _noise_i32,
        _noise_sign_i8,
        a_vec,
        mut seeds,
        _coeff_seeds,
        _message,
        _index,
    ) = set_up_init_vars(buffer, ori_message, index);

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..iterations {
        // Servers compute this

        for a_i in 0..1 {
            // Eval code
            // for eval_s_iter in 1..NUM_SERVERS {
            dpf_gen_lwe_seed_block_new_sq_compact(
                a_i,
                message,
                &a_vec[..],
                &mut b_vec_1d_u8[..],
                &mut s_vec_1d_u8[..],
                &mut v_vec_u8[..],
                &mut seeds[..],
            );
        }
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!(
        "seed_compact (no auth or prep) GEN Time elapsed is:  is: {:?}",
        eval_duration
    );
}

// "compact" because (n-1) servers will get seeds to expand on for the majority of the data sents
pub fn block_compact_auth_timings_client(
    iterations: usize,
    bscale: usize,
    ascale: usize,
    wait_time: u64,
) {
    println!("----------------------------------------------------");
    println!("BLOCK SEED (SNIP) compact Block Timing");
    let gen_iterations = iterations * bscale;
    let after_iterations = iterations * ascale;

    println!("gen_iterations: {}", gen_iterations);
    println!("after_iterations: {}", after_iterations);
    dpf_gen_lwe_seed_block_new_sq_compact_snip_timings(gen_iterations);
    thread::sleep(time::Duration::from_secs(wait_time));
    dpf_gen_lwe_seed_block_new_sq_compact_snip_aftergen_timings(after_iterations);

    println!("----------------------------------------------------");
}

// Code that all servers (with seeds or correction word) will have to run
pub fn dpf_eval_every_server_timings(eval_iterations: usize) {
    // Setup of variables
    let noise_sign_i8 = vec![0i8; NUM_BLOCK * N_PARAM];

    let coeff_seeds = [0u8; SEED_IV_LEN];

    let server_noise_bits = vec![0u32; 1 * NOISE_LEN * NOISE_BITS];
    let bt_seeds_pt1 = vec![0u8; SEED_IV_LEN * 1];

    let bt_seeds_pt2 = vec![0u8; SEED_IV_LEN * 1];

    let mut server_noise = vec![0i32; 1 * NOISE_LEN];

    let mut t_c0_alpha = vec![0i32; 1 * N_PARAM];
    let mut t_c1_alpha = vec![0i32; 1 * N_PARAM];
    let mut t_c2_alpha = vec![0i32; 1 * N_PARAM];

    let mut r1_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    // calculating eval part
    let mut r_c0_eval = vec![0i32; 1];
    let mut r_c1_eval = vec![0i32; 1];
    let mut r_c2_eval = vec![0i32; 1];

    let mut bt_c0_shares = vec![0i32; 1 * N_PARAM];
    let mut bt_c1_shares = vec![0i32; 1 * N_PARAM];
    let mut bt_c2_shares = vec![0i32; 1 * N_PARAM];

    let b_vec_1d_u8_total = vec![0u8; E_BYTES * N_PARAM * 1];

    let inv_servers = mod_inverse(NUM_SERVERS as i32, Q);

    let mut r2_b_shares = vec![0i32; 1 * N_PARAM];
    let mut one_b_shares = vec![0i32; 1 * N_PARAM];

    let mut r3_vec_u8 = vec![0u8; E_BYTES * NOISE_LEN * NOISE_BITS];
    let mut r3_e_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];
    let mut one_e_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];

    let mut b_snip_shares = vec![0i32; 1 * N_PARAM];
    let mut e_snip_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this
        //Compute beaver triples

        let mut a_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];
        let mut b_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];
        let mut c_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];

        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
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
        let a_bt: &[i32] = bytemuck::cast_slice(&a_bt_u8);
        let b_bt: &[i32] = bytemuck::cast_slice(&b_bt_u8);
        let c_bt: &mut [i32] = bytemuck::cast_slice_mut(&mut c_bt_u8);

        // step 2. c
        // for s_iter in 0..NUM_SERVERS {
        for s_iter in 0..1 {
            combine_bits(
                &server_noise_bits
                    [s_iter * NOISE_LEN * NOISE_BITS..(s_iter + 1) * NOISE_LEN * NOISE_BITS],
                &mut server_noise[s_iter * NOISE_LEN..(s_iter + 1) * NOISE_LEN],
            );
        }

        // step 2. d
        let mut r1_seed = [0u8; SEED_IV_LEN];
        let mut r2_seed = [0u8; SEED_IV_LEN];
        let mut r3_seed = [0u8; SEED_IV_LEN];
        get_rand_coeff_seeds(&coeff_seeds, &mut r1_seed, &mut r2_seed, &mut r3_seed);

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
            //r1_vec.fill(2);

            // Eval code
            let server_c0_eval_tmp = [0i32; NUM_SERVERS];
            let server_c1_eval_tmp = [0i32; NUM_SERVERS];
            let server_c2_eval_tmp = [0i32; NUM_SERVERS];

            for b_i in 0..NOISE_LEN {
                // for server_i in 0..NUM_SERVERS {
                for server_i in 0..1 {
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
            }

            // for server_i in 0..NUM_SERVERS {
            for server_i in 0..1 {
                t_c0_alpha[N_PARAM * server_i + a_i] = r_e_c0_tmp[server_i];
                t_c1_alpha[N_PARAM * server_i + a_i] = r_e_c1_tmp[server_i];
                t_c2_alpha[N_PARAM * server_i + a_i] = r_e_c2_tmp[server_i];
            }

            // for server_i in 0..NUM_SERVERS {
            for server_i in 0..1 {
                r_c0_eval[server_i] =
                    barrett_reduce(r_c0_eval[server_i] + server_c0_eval_tmp[server_i]);
                r_c1_eval[server_i] =
                    barrett_reduce(r_c1_eval[server_i] + server_c1_eval_tmp[server_i]);
                r_c2_eval[server_i] =
                    barrett_reduce(r_c2_eval[server_i] + server_c2_eval_tmp[server_i]);
            }
        }

        // step 2. d. i. B.
        let b_vec_1d_total: &[i32] = bytemuck::cast_slice(&b_vec_1d_u8_total);

        // one time calculation made at server startup

        run_beaver_triple_timing(
            &b_vec_1d_total[..],
            &t_c0_alpha,
            &mut bt_c0_shares,
            a_bt,
            b_bt,
            c_bt,
            N_PARAM,
            BT_INST1,
            inv_servers,
        );

        run_beaver_triple_timing(
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

        run_beaver_triple_timing(
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

        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
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

        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
            m_0_shares[s_i] = barrett_reduce(r_c0_eval[s_i] + bt_c0_shares_sum[s_i]);
            m_1_shares[s_i] = barrett_reduce(r_c1_eval[s_i] + bt_c1_shares_sum[s_i]);
            m_2_shares[s_i] = barrett_reduce(r_c2_eval[s_i] + bt_c2_shares_sum[s_i]);
        }

        let mut m_02_shares = [0i32; NUM_SERVERS];
        let mut m_11_shares = [0i32; NUM_SERVERS];
        run_beaver_triple_timing(
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
        run_beaver_triple_timing(
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
        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
            m_11_02_shares[s_i] = barrett_reduce(m_11_shares[s_i] - m_02_shares[s_i]);
        }

        ////////////////////////////////////////////////////////////////////////////////////
        // Part 2 .e.

        //A server creates a secret sharing of 1
        let mut one_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
        let one_shares: &mut [i32] = bytemuck::cast_slice_mut(&mut one_shares_u8);

        let mut r2_vec_u8 = vec![0u8; E_BYTES * N_PARAM];
        gen_r2_vec_sub(&r2_seed, &mut r2_vec_u8);
        let r2_vec: &[i32] = bytemuck::cast_slice(&r2_vec_u8);

        for i in 0..N_PARAM {
            // for s_i in 0..NUM_SERVERS {
            for s_i in 0..1 {
                r2_b_shares[s_i * N_PARAM + i] =
                    mul_mod_mont(r2_vec[i], b_vec_1d_total[s_i * N_PARAM + i]);
                one_b_shares[s_i * N_PARAM + i] =
                    barrett_reduce(one_shares[s_i] - b_vec_1d_total[s_i * N_PARAM + i]);
            }
        }

        gen_r3_vec_sub(&r3_seed, &mut r3_vec_u8);
        let r3_vec: &[i32] = bytemuck::cast_slice(&r3_vec_u8);
        // let mut server_noise_bits = vec![0u32; NUM_SERVERS * NOISE_LEN * NOISE_BITS];

        for i in 0..NOISE_LEN * NOISE_BITS {
            // for s_i in 0..NUM_SERVERS {
            for s_i in 0..1 {
                r3_e_shares[s_i * NOISE_LEN * NOISE_BITS + i] = mul_mod_mont(
                    r3_vec[i],
                    server_noise_bits[s_i * NOISE_LEN * NOISE_BITS + i] as i32,
                );
                one_e_shares[s_i * NOISE_LEN * NOISE_BITS + i] = barrett_reduce(
                    one_shares[s_i] - server_noise_bits[s_i * NOISE_LEN * NOISE_BITS + i] as i32,
                );
            }
        }

        {
            let mut a_bt_a_u8 = vec![0u8; E_BYTES * 1 * N_PARAM];
            let mut b_bt_a_u8 = vec![0u8; E_BYTES * 1 * N_PARAM];
            let mut c_bt_a_u8 = vec![0u8; E_BYTES * 1 * N_PARAM];
            let mut a_bt_b_u8 = vec![0u8; E_BYTES * 1 * NOISE_LEN * NOISE_BITS];
            let mut b_bt_b_u8 = vec![0u8; E_BYTES * 1 * NOISE_LEN * NOISE_BITS];
            let mut c_bt_b_u8 = vec![0u8; E_BYTES * 1 * NOISE_LEN * NOISE_BITS];
            // for s_i in 0..NUM_SERVERS {
            for s_i in 0..1 {
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

            run_beaver_triple_timing(
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

            run_beaver_triple_timing(
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
        }

        let mut m_sum = [0i32; NUM_SERVERS];
        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
            for i in 0..BT_INST2_A {
                m_sum[s_i] = barrett_reduce(m_sum[s_i] + b_snip_shares[s_i * BT_INST2_A + i]);
            }
            for i in 0..BT_INST2_B {
                m_sum[s_i] = barrett_reduce(m_sum[s_i] + e_snip_shares[s_i * BT_INST2_B + i]);
            }
        }
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!("EVAL every server time elapsed is: {:?}", eval_duration);
}

// Code that all servers (with seeds or correction word) will have to run
pub fn dpf_eval_every_server_timings_single(eval_iterations: usize) {
    // Setup of variables
    let coeff_seeds = [0u8; SEED_IV_LEN];

    let bt_seeds_pt1 = vec![0u8; SEED_IV_LEN * 1];

    let bt_seeds_pt2 = vec![0u8; SEED_IV_LEN * 1];

    let mut t_c0_alpha = vec![0i32; 1 * N_PARAM];
    let mut t_c1_alpha = vec![0i32; 1 * N_PARAM];
    let mut t_c2_alpha = vec![0i32; 1 * N_PARAM];

    // calculating eval part
    let mut r_c0_eval = vec![0i32; 1];
    let mut r_c1_eval = vec![0i32; 1];
    let mut r_c2_eval = vec![0i32; 1];

    let mut bt_c0_shares = vec![0i32; 1 * N_PARAM];
    let mut bt_c1_shares = vec![0i32; 1 * N_PARAM];
    let mut bt_c2_shares = vec![0i32; 1 * N_PARAM];

    let b_vec_1d_u8_total = vec![0u8; E_BYTES * N_PARAM * 1];

    let inv_servers = mod_inverse(NUM_SERVERS as i32, Q);

    let mut r2_b_shares = vec![0i32; 1 * N_PARAM];
    let mut one_b_shares = vec![0i32; 1 * N_PARAM];

    let mut r3_vec_u8 = vec![0u8; E_BYTES * NOISE_LEN * NOISE_BITS];
    let mut r3_e_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];
    let mut one_e_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];

    let mut b_snip_shares = vec![0i32; 1 * N_PARAM];
    let mut e_snip_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this
        //Compute beaver triples

        let mut a_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];
        let mut b_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];
        let mut c_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];

        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
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
        let a_bt: &[i32] = bytemuck::cast_slice(&a_bt_u8);
        let b_bt: &[i32] = bytemuck::cast_slice(&b_bt_u8);
        let c_bt: &mut [i32] = bytemuck::cast_slice_mut(&mut c_bt_u8);

        /*
        // step 2. c
        // for s_iter in 0..NUM_SERVERS {
        for s_iter in 0..1 {
            combine_bits(
                &server_noise_bits
                    [s_iter * NOISE_LEN * NOISE_BITS..(s_iter + 1) * NOISE_LEN * NOISE_BITS],
                &mut server_noise[s_iter * NOISE_LEN..(s_iter + 1) * NOISE_LEN],
            );
        }

         */

        // step 2. d
        let mut r1_seed = [0u8; SEED_IV_LEN];
        let mut r2_seed = [0u8; SEED_IV_LEN];
        let mut r3_seed = [0u8; SEED_IV_LEN];
        get_rand_coeff_seeds(&coeff_seeds, &mut r1_seed, &mut r2_seed, &mut r3_seed);

        // step 2. d. i. B.
        let b_vec_1d_total: &[i32] = bytemuck::cast_slice(&b_vec_1d_u8_total);

        // one time calculation made at server startup

        run_beaver_triple_timing(
            &b_vec_1d_total[..],
            &t_c0_alpha,
            &mut bt_c0_shares,
            a_bt,
            b_bt,
            c_bt,
            N_PARAM,
            BT_INST1,
            inv_servers,
        );

        run_beaver_triple_timing(
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

        run_beaver_triple_timing(
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


        let mut m_0_shares = [0i32; NUM_SERVERS];
        let mut m_1_shares = [0i32; NUM_SERVERS];
        let mut m_2_shares = [0i32; NUM_SERVERS];

        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
            m_0_shares[s_i] = barrett_reduce(r_c0_eval[s_i] + bt_c0_shares_sum[s_i]);
            m_1_shares[s_i] = barrett_reduce(r_c1_eval[s_i] + bt_c1_shares_sum[s_i]);
            m_2_shares[s_i] = barrett_reduce(r_c2_eval[s_i] + bt_c2_shares_sum[s_i]);
        }

        let mut m_02_shares = [0i32; NUM_SERVERS];
        let mut m_11_shares = [0i32; NUM_SERVERS];
        run_beaver_triple_timing(
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
        run_beaver_triple_timing(
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
        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
            m_11_02_shares[s_i] = barrett_reduce(m_11_shares[s_i] - m_02_shares[s_i]);
        }

        ////////////////////////////////////////////////////////////////////////////////////
        // Part 2 .e.

        //A server creates a secret sharing of 1
        let mut one_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
        let one_shares: &mut [i32] = bytemuck::cast_slice_mut(&mut one_shares_u8);

        let mut r2_vec_u8 = vec![0u8; E_BYTES * N_PARAM];
        gen_r2_vec_sub(&r2_seed, &mut r2_vec_u8);
        let r2_vec: &[i32] = bytemuck::cast_slice(&r2_vec_u8);


        gen_r3_vec_sub(&r3_seed, &mut r3_vec_u8);
        let r3_vec: &[i32] = bytemuck::cast_slice(&r3_vec_u8);
        // let mut server_noise_bits = vec![0u32; NUM_SERVERS * NOISE_LEN * NOISE_BITS];


        {
            let mut a_bt_a_u8 = vec![0u8; E_BYTES * 1 * N_PARAM];
            let mut b_bt_a_u8 = vec![0u8; E_BYTES * 1 * N_PARAM];
            let mut c_bt_a_u8 = vec![0u8; E_BYTES * 1 * N_PARAM];
            let mut a_bt_b_u8 = vec![0u8; E_BYTES * 1 * NOISE_LEN * NOISE_BITS];
            let mut b_bt_b_u8 = vec![0u8; E_BYTES * 1 * NOISE_LEN * NOISE_BITS];
            let mut c_bt_b_u8 = vec![0u8; E_BYTES * 1 * NOISE_LEN * NOISE_BITS];
            // for s_i in 0..NUM_SERVERS {
            for s_i in 0..1 {
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

            run_beaver_triple_timing(
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

            run_beaver_triple_timing(
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
        }

        let mut m_sum = [0i32; NUM_SERVERS];
        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
            for i in 0..BT_INST2_A {
                m_sum[s_i] = barrett_reduce(m_sum[s_i] + b_snip_shares[s_i * BT_INST2_A + i]);
            }
            for i in 0..BT_INST2_B {
                m_sum[s_i] = barrett_reduce(m_sum[s_i] + e_snip_shares[s_i * BT_INST2_B + i]);
            }
        }
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!("EVAL every server (single) time elapsed is: {:?}", eval_duration);
}

// Code that all servers (with seeds or correction word) will have to run
pub fn dpf_eval_every_server_timings_numblock(eval_iterations: usize) {
    // Setup of variables

    let coeff_seeds = [0u8; SEED_IV_LEN];

    let server_noise_bits = vec![0u32; 1 * NOISE_LEN * NOISE_BITS];
    let bt_seeds_pt1 = vec![0u8; SEED_IV_LEN * 1];

    let bt_seeds_pt2 = vec![0u8; SEED_IV_LEN * 1];

    let mut server_noise = vec![0i32; 1 * NOISE_LEN];

    let mut t_c0_alpha = vec![0i32; 1 * N_PARAM];
    let mut t_c1_alpha = vec![0i32; 1 * N_PARAM];
    let mut t_c2_alpha = vec![0i32; 1 * N_PARAM];


    // calculating eval part
    let mut r_c0_eval = vec![0i32; 1];
    let mut r_c1_eval = vec![0i32; 1];
    let mut r_c2_eval = vec![0i32; 1];

    let mut bt_c0_shares = vec![0i32; 1 * N_PARAM];
    let mut bt_c1_shares = vec![0i32; 1 * N_PARAM];
    let mut bt_c2_shares = vec![0i32; 1 * N_PARAM];

    let b_vec_1d_u8_total = vec![0u8; E_BYTES * N_PARAM * 1];

    let inv_servers = mod_inverse(NUM_SERVERS as i32, Q);

    let mut r2_b_shares = vec![0i32; 1 * N_PARAM];
    let mut one_b_shares = vec![0i32; 1 * N_PARAM];

    let mut r3_vec_u8 = vec![0u8; E_BYTES * NOISE_LEN * NOISE_BITS];
    let mut r3_e_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];
    let mut one_e_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];

    let mut b_snip_shares = vec![0i32; 1 * N_PARAM];
    let mut e_snip_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this
        //Compute beaver triples
        let mut c_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];

        // step 2. c
        // for s_iter in 0..NUM_SERVERS {
        for s_iter in 0..1 {
            combine_bits_numblocks(
                &server_noise_bits
                    [s_iter * NOISE_LEN/NUM_BLOCK * NOISE_BITS..(s_iter + 1) * NOISE_LEN /NUM_BLOCK* NOISE_BITS],
                &mut server_noise[s_iter * NOISE_LEN/NUM_BLOCK..(s_iter + 1) * NOISE_LEN/NUM_BLOCK],
            );
        }

    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!("EVAL every server (got num by numblock: {:?}) time elapsed is: {:?}", eval_duration, eval_duration* NUM_BLOCK as u32);
}

// Code that all servers (with seeds or correction word) will have to run
pub fn dpf_eval_every_server_timings_nparam(eval_iterations: usize) {
    // Setup of variables
    let noise_sign_i8 = vec![0i8; NUM_BLOCK * N_PARAM];

    let server_noise_bits = vec![0u32; 1 * NOISE_LEN * NOISE_BITS];

    let mut server_noise = vec![0i32; 1 * NOISE_LEN];

    let mut t_c0_alpha = vec![0i32; 1 * N_PARAM];
    let mut t_c1_alpha = vec![0i32; 1 * N_PARAM];
    let mut t_c2_alpha = vec![0i32; 1 * N_PARAM];

    let mut r1_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    // calculating eval part
    let mut r_c0_eval = vec![0i32; 1];
    let mut r_c1_eval = vec![0i32; 1];
    let mut r_c2_eval = vec![0i32; 1];

    let mut bt_c0_shares = vec![0i32; 1 * N_PARAM];
    let mut bt_c1_shares = vec![0i32; 1 * N_PARAM];
    let mut bt_c2_shares = vec![0i32; 1 * N_PARAM];

    let b_vec_1d_u8_total = vec![0u8; E_BYTES * N_PARAM * 1];


    let mut r2_b_shares = vec![0i32; 1 * N_PARAM];
    let mut one_b_shares = vec![0i32; 1 * N_PARAM];

    let mut r3_vec_u8 = vec![0u8; E_BYTES * NOISE_LEN * NOISE_BITS];
    let mut r3_e_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];
    let mut one_e_shares = vec![0i32; 1 * NOISE_LEN * NOISE_BITS];

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this
        //Compute beaver triples

        let mut a_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];
        let mut b_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];
        let mut c_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];


        let a_bt: &[i32] = bytemuck::cast_slice(&a_bt_u8);
        let b_bt: &[i32] = bytemuck::cast_slice(&b_bt_u8);
        let c_bt: &mut [i32] = bytemuck::cast_slice_mut(&mut c_bt_u8);


        // step 2. d
        let mut r1_seed = [0u8; SEED_IV_LEN];

        //for a_i in 0..N_PARAM {
        for a_i in 0..1 {
            let mut r_e_c0_tmp = [0i32; NUM_SERVERS];
            let mut r_e_c1_tmp = [0i32; NUM_SERVERS];
            let mut r_e_c2_tmp = [0i32; NUM_SERVERS];

            //r1_vec_u8.fill(0);
            for i in 0..r1_vec_u8.len() {
                r1_vec_u8[i] = 0;
            }

            gen_r1_vec_sub(&r1_seed, &mut r1_vec_u8[..], a_i);
            let r1_vec: &mut [i32] = bytemuck::cast_slice_mut(&mut r1_vec_u8);
            //r1_vec.fill(2);

            // Eval code
            let server_c0_eval_tmp = [0i32; NUM_SERVERS];
            let server_c1_eval_tmp = [0i32; NUM_SERVERS];
            let server_c2_eval_tmp = [0i32; NUM_SERVERS];

            for b_i in 0..NOISE_LEN {
                // for server_i in 0..NUM_SERVERS {
                for server_i in 0..1 {
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
            }

            // for server_i in 0..NUM_SERVERS {
            for server_i in 0..1 {
                t_c0_alpha[N_PARAM * server_i + a_i] = r_e_c0_tmp[server_i];
                t_c1_alpha[N_PARAM * server_i + a_i] = r_e_c1_tmp[server_i];
                t_c2_alpha[N_PARAM * server_i + a_i] = r_e_c2_tmp[server_i];
            }

            // for server_i in 0..NUM_SERVERS {
            for server_i in 0..1 {
                r_c0_eval[server_i] =
                    barrett_reduce(r_c0_eval[server_i] + server_c0_eval_tmp[server_i]);
                r_c1_eval[server_i] =
                    barrett_reduce(r_c1_eval[server_i] + server_c1_eval_tmp[server_i]);
                r_c2_eval[server_i] =
                    barrett_reduce(r_c2_eval[server_i] + server_c2_eval_tmp[server_i]);
            }
        }

        // step 2. d. i. B.
        let b_vec_1d_total: &[i32] = bytemuck::cast_slice(&b_vec_1d_u8_total);


        let mut bt_c0_shares_sum = [0i32; NUM_SERVERS];
        let mut bt_c1_shares_sum = [0i32; NUM_SERVERS];
        let mut bt_c2_shares_sum = [0i32; NUM_SERVERS];

        // for s_i in 0..NUM_SERVERS {
        for s_i in 0..1 {
            for i in 0..1 {
            //for i in 0..N_PARAM {
                bt_c0_shares_sum[s_i] =
                    barrett_reduce(bt_c0_shares_sum[s_i] + bt_c0_shares[s_i * N_PARAM + i]);
                bt_c1_shares_sum[s_i] =
                    barrett_reduce(bt_c1_shares_sum[s_i] + bt_c1_shares[s_i * N_PARAM + i]);
                bt_c2_shares_sum[s_i] =
                    barrett_reduce(bt_c2_shares_sum[s_i] + bt_c2_shares[s_i * N_PARAM + i]);
            }
        }


        ////////////////////////////////////////////////////////////////////////////////////
        // Part 2 .e.

        //A server creates a secret sharing of 1
        let mut one_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
        let one_shares: &mut [i32] = bytemuck::cast_slice_mut(&mut one_shares_u8);

        let mut r2_vec_u8 = vec![0u8; E_BYTES * N_PARAM];
        let r2_vec: &[i32] = bytemuck::cast_slice(&r2_vec_u8);

        //for i in 0..N_PARAM {
        for i in 0..1 {
            // for s_i in 0..NUM_SERVERS {
            for s_i in 0..1 {
                r2_b_shares[s_i * N_PARAM + i] =
                    mul_mod_mont(r2_vec[i], b_vec_1d_total[s_i * N_PARAM + i]);
                one_b_shares[s_i * N_PARAM + i] =
                    barrett_reduce(one_shares[s_i] - b_vec_1d_total[s_i * N_PARAM + i]);
            }
        }

        let r3_vec: &[i32] = bytemuck::cast_slice(&r3_vec_u8);
        // let mut server_noise_bits = vec![0u32; NUM_SERVERS * NOISE_LEN * NOISE_BITS];

        //for i in 0..NOISE_LEN * NOISE_BITS {
        for i in 0..NOISE_LEN * NOISE_BITS/N_PARAM {
            // for s_i in 0..NUM_SERVERS {
            for s_i in 0..1 {
                r3_e_shares[s_i * NOISE_LEN * NOISE_BITS + i] = mul_mod_mont(
                    r3_vec[i],
                    server_noise_bits[s_i * NOISE_LEN * NOISE_BITS + i] as i32,
                );
                one_e_shares[s_i * NOISE_LEN * NOISE_BITS + i] = barrett_reduce(
                    one_shares[s_i] - server_noise_bits[s_i * NOISE_LEN * NOISE_BITS + i] as i32,
                );
            }
        }


    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!("EVAL every server (got mul by N_PARAM: {:?}) time elapsed is: {:?}",eval_duration, eval_duration*N_PARAM as u32);
}

// Computation that the single server with the correction words has to do
// Does not include eval_all function, which is by itself
pub fn dpf_eval_long_server_timings(eval_iterations: usize) {
    // Setup of variables
    let b_vec_1d_u8 = vec![0u8; E_BYTES * N_PARAM];

    let correction_pt1 = vec![0i32; BT_INST1];

    let correction_pt2a = vec![0i32; BT_INST2_A];
    let correction_pt2b = vec![0i32; BT_INST2_B];

    let mut c_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * 1];

    let mut r1_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    let table_sub = vec![0i32; NUM_BLOCK * N_PARAM];

    let mut b_vec_1d_u8_total = vec![0u8; E_BYTES * N_PARAM * NUM_SERVERS];

    let mut c_bt_a_u8 = vec![0u8; E_BYTES * NUM_SERVERS * N_PARAM];
    let mut c_bt_b_u8 = vec![0u8; E_BYTES * NUM_SERVERS * NOISE_LEN * NOISE_BITS];

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this
        //Compute beaver triples

        let c_bt: &mut [i32] = bytemuck::cast_slice_mut(&mut c_bt_u8);

        for i in 0..BT_INST1 {
            c_bt[(1 - 1) * BT_INST1 + i] = correction_pt1[i];
        }

        for _a_i in 0..N_PARAM {
            let r1_vec: &mut [i32] = bytemuck::cast_slice_mut(&mut r1_vec_u8);

            // Eval code
            let mut server_c0_eval_tmp = [0i32; NUM_SERVERS];
            let mut server_c1_eval_tmp = [0i32; NUM_SERVERS];
            let mut server_c2_eval_tmp = [0i32; NUM_SERVERS];

            for b_i in 0..NOISE_LEN {
                // Eval code
                server_c0_eval_tmp[0] = barrett_reduce(server_c0_eval_tmp[0] + table_sub[b_i]);
                let mut temp_eval: i32 = barrett_reduce(mul_mod_mont(table_sub[b_i], r1_vec[b_i]));
                server_c1_eval_tmp[0] = barrett_reduce(server_c1_eval_tmp[0] + temp_eval);

                temp_eval = barrett_reduce(mul_mod_mont(temp_eval, r1_vec[b_i]));
                server_c2_eval_tmp[0] = barrett_reduce(server_c2_eval_tmp[0] + temp_eval);
            }
        }

        // step 2. d. i. B.

        for i in 0..E_BYTES * N_PARAM {
            b_vec_1d_u8_total[E_BYTES * N_PARAM * (1 - 1) + i] = b_vec_1d_u8[i];
        }

        ////////////////////////////////////////////////////////////////////////////////////
        // Part 2 .e.

        //A server creates a secret sharing of 1
        let mut one_shares_u8 = [0u8; E_BYTES * NUM_SERVERS];
        fill_rand_aes128_modq(&mut one_shares_u8, NUM_SERVERS - 1);
        let one_shares: &mut [i32] = bytemuck::cast_slice_mut(&mut one_shares_u8);

        one_shares[NUM_SERVERS - 1] = 1;
        for i in 0..NUM_SERVERS - 1 {
            one_shares[NUM_SERVERS - 1] =
                barrett_reduce(one_shares[NUM_SERVERS - 1] - one_shares[i]);
        }

        let c_bt_a: &mut [i32] = bytemuck::cast_slice_mut(&mut c_bt_a_u8);
        let c_bt_b: &mut [i32] = bytemuck::cast_slice_mut(&mut c_bt_b_u8);

        for i in 0..BT_INST2_A {
            c_bt_a[(NUM_SERVERS - 1) * BT_INST2_A + i] = correction_pt2a[i];
        }

        for i in 0..BT_INST2_B {
            c_bt_b[(NUM_SERVERS - 1) * BT_INST2_B + i] = correction_pt2b[i];
        }
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!("EVAL long server Time elapsed is: {:?}", eval_duration);
}

// Computation that the (n-1)) servers with the seeds has to do
// Does not include eval_all function, which is by itself
pub fn dpf_eval_short_server_timings(eval_iterations: usize) {
    // Setup of variables
    let seeds = [0u8; SEED_IV_LEN * (2 - 1)];

    let mut r1_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    let table_sub = vec![0i32; NUM_BLOCK * N_PARAM];

    let mut b_vec_1d_u8_total = vec![0u8; E_BYTES * N_PARAM * 1];
    let mut s_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM * N_PARAM];

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this

        for _a_i in 0..N_PARAM {
            let r1_vec: &mut [i32] = bytemuck::cast_slice_mut(&mut r1_vec_u8);
            //r1_vec.fill(2);

            // Eval code
            let mut server_c0_eval_tmp = [0i32; NUM_SERVERS];
            let mut server_c1_eval_tmp = [0i32; NUM_SERVERS];
            let mut server_c2_eval_tmp = [0i32; NUM_SERVERS];

            // Eval code
            // for eval_s_iter in 1..NUM_SERVERS {
            for eval_s_iter in 1..2 {
                for b_i in 0..NOISE_LEN {
                    server_c0_eval_tmp[eval_s_iter] =
                        barrett_reduce(server_c0_eval_tmp[eval_s_iter] + table_sub[b_i]);
                    let mut temp_eval: i32 =
                        barrett_reduce(mul_mod_mont(table_sub[b_i], r1_vec[b_i]));
                    server_c1_eval_tmp[eval_s_iter] =
                        barrett_reduce(server_c1_eval_tmp[eval_s_iter] + temp_eval);

                    temp_eval = barrett_reduce(mul_mod_mont(temp_eval, r1_vec[b_i]));
                    server_c2_eval_tmp[eval_s_iter] =
                        barrett_reduce(server_c2_eval_tmp[eval_s_iter] + temp_eval)
                }
            }
        }

        // for s_i in 0..(NUM_SERVERS - 1) {
        for s_i in 0..1 {
            dpf_eval_lwe_seed_block_get_bs(
                0,
                &mut b_vec_1d_u8_total[E_BYTES * N_PARAM * s_i..E_BYTES * N_PARAM * (s_i + 1)],
                &mut s_vecs_1d_u8_eval[..],
                &seeds[32 * (s_i)..32 * (s_i + 1)],
            );
        }
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!("EVAL short server Time elapsed is: {:?}", eval_duration);
}

// The computation of the DPF Eval all for the (n-1) servers that have seeds
pub fn dpf_eval_eval_all_from_seed_timings(eval_iterations: usize) {
    // Setup of variables
    let a_vec = vec![0i32; NUM_BLOCK * N_PARAM];

    let v_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    let seeds = [0u8; SEED_IV_LEN * (2 - 1)];

    let mut table_sub = vec![0i32; NUM_BLOCK * N_PARAM];
    let mut b_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM * 1];

    let mut s_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM * N_PARAM];

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this

        for a_i in 0..1 {
            // Eval code
            // for eval_s_iter in 1..NUM_SERVERS {
            for eval_s_iter in 1..2 {
                dpf_eval_lwe_seed_block_all_sub_timing(
                    a_i,
                    &mut table_sub,
                    &a_vec,
                    &mut b_vecs_1d_u8_eval[..],
                    &mut s_vecs_1d_u8_eval[..],
                    &seeds[32 * (eval_s_iter - 1)..32 * (eval_s_iter)],
                    &v_vec_u8,
                );
            }
        }
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!(
        "EVAL eval_all_from_seed (got mul N_PARAM: {:?}) Time elapsed is: {:?}",
        eval_duration,
        eval_duration* N_PARAM as u32
    );
}

// The computation of the DPF Eval single for the (n-1) servers that have seeds
pub fn dpf_eval_single_seed_timings(eval_iterations: usize) {
    // Setup of variables
    let a_vec = vec![0i32; NUM_BLOCK * N_PARAM];

    let v_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    let seeds = [0u8; SEED_IV_LEN * (2 - 1)];

    let mut recovered_message_t: i32 = 0;
    let mut b_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM * 1];

    let mut s_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM * N_PARAM];

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this

        for a_i in 0..1 {
            // Eval code
            // for eval_s_iter in 1..NUM_SERVERS {
            for eval_s_iter in 0..1 {
                dpf_eval_lwe_seed_block(
                    a_i,
                    &mut recovered_message_t,
                    &a_vec,
                    &mut b_vecs_1d_u8_eval[..],
                    &mut s_vecs_1d_u8_eval[..],
                    &seeds[32 * (eval_s_iter)..32 * (eval_s_iter + 1)],
                    &v_vec_u8,
                );
            }
        }
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!(
        "EVAL eval_single_from_seed Time elapsed is: {:?}",
        eval_duration
    );
}

// The computation of the DPF Eval all for the single server that has the correction words
pub fn dpf_eval_eval_all_from_block_timings(eval_iterations: usize) {
    // Setup of variables
    let a_vec = vec![0i32; NUM_BLOCK * N_PARAM];

    let b_vec_1d_u8 = vec![0u8; E_BYTES * N_PARAM];
    let s_vec_1d_u8 = vec![0u8; E_BYTES * N_PARAM * N_PARAM];
    let v_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    let mut table_sub = vec![0i32; NUM_BLOCK * N_PARAM];

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this
        //Compute beaver triples

        for a_i in 0..1 {
            dpf_eval_lwe_block_new_all_sub_timing(
                a_i,
                &mut table_sub,
                &a_vec,
                &b_vec_1d_u8,
                &s_vec_1d_u8,
                &v_vec_u8,
            );
        }
    }

    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!(
        "EVAL eval_all_from_block (got mul N_PARAM: {:?}) Time elapsed is: {:?}",
        eval_duration,
        eval_duration* N_PARAM as u32
    );
}

// The computation of the DPF Eval all for the single server that has the correction words
pub fn dpf_eval_single_block_timings(eval_iterations: usize) {
    // Setup of variables
    let a_vec = vec![0i32; NUM_BLOCK * N_PARAM];

    let b_vec_1d_u8 = vec![0u8; E_BYTES * N_PARAM];
    let s_vec_1d_u8 = vec![0u8; E_BYTES * N_PARAM * N_PARAM];
    let v_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    let mut recovered_message_t: i32 = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////

    let eval_start = Instant::now();
    for _iter_test in 0..eval_iterations {
        // Servers compute this
        //Compute beaver triples

        for a_i in 0..1 {
            dpf_eval_lwe_block_new(
                a_i,
                &mut recovered_message_t,
                &a_vec,
                &b_vec_1d_u8[..],
                &s_vec_1d_u8[..],
                &v_vec_u8,
            );
        }
    }

    //let gen_duration = gen_start.elapsed().as_micros();
    let eval_duration = eval_start.elapsed();
    println!(
        "EVAL eval_single_from_block Time elapsed is: {:?}",
        eval_duration
    );
}
