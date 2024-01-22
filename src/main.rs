use std::time::Instant;
use std::{thread, time};

use bytemuck;
use std::num::Wrapping;

type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
mod params;

use params::*;

mod inv_zeta;
mod ntt;
mod zeta;

mod aes_rng;
mod noise;

mod snip;

mod dpf;
use dpf::*;


use crate::noise::lwe_add_sample_noise_8_1;


mod debug;

mod auth;
use auth::*;

mod timing;
use timing::*;

fn main_check_correctness() {
    //fn main() {
    println!("----Construction 2.14----");

    let start = Instant::now();
    // Setup of variables
    let buffer: i32 = 128;
    let ori_message: i32 = 101;
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
        message,
        index,
    ) = set_up_init_vars(buffer, ori_message, index);

    let setup_duration = start.elapsed();
    println!("setup_duration Time elapsed is: {:?}", setup_duration);

    println!("GEN");
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
    let gen_duration = start.elapsed();
    println!("gen_duration Time elapsed is: {:?}", gen_duration);

    let (
        mut server_noise_bits,
        mut bt_seeds_pt1,
        mut correction_pt1,
        mut bt_seeds_pt2,
        mut correction_pt2a,
        mut correction_pt2b,
    ) = init_auth_client_vars();

    println!("Post GEN");
    // Client creates Auth vars
    client_post_gen(
        &noise_i32,
        &mut server_noise_bits,
        &mut bt_seeds_pt1,
        &mut correction_pt1,
        &mut bt_seeds_pt2,
        &mut correction_pt2a,
        &mut correction_pt2b,
    );

    let post_gen_duration = start.elapsed();
    println!("post_gen_duration Time elapsed is: {:?}", post_gen_duration);

    ////////////////////////////////////////////////////////////////////////////////////////////////
    println!("EVAL 0");
    let mut a_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * NUM_SERVERS];
    let mut b_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * NUM_SERVERS];
    let mut c_bt_u8 = vec![0u8; E_BYTES * BT_INST1 * NUM_SERVERS];
    let (
        inv_servers,
        r_c0_eval,
        r_c1_eval,
        r_c2_eval,
        t_c0_alpha,
        t_c1_alpha,
        t_c2_alpha,
        r2_seed,
        r3_seed,
    ) = servers_auth_init_and_prep_eval(
        &bt_seeds_pt1,
        &correction_pt1,
        &server_noise_bits,
        &coeff_seeds,
        &a_vec,
        &mut b_vec_1d_u8,
        &mut s_vec_1d_u8,
        &mut v_vec_u8,
        &mut noise_sign_i8,
        &mut seeds,
        &mut a_bt_u8,
        &mut b_bt_u8,
        &mut c_bt_u8,
    );
    let a_bt: &[i32] = bytemuck::cast_slice(&a_bt_u8);
    let b_bt: &[i32] = bytemuck::cast_slice(&b_bt_u8);
    let c_bt: &[i32] = bytemuck::cast_slice(&c_bt_u8);

    let eval0_duration = start.elapsed();
    println!("eval0_duration Time elapsed is: {:?}", eval0_duration);

    println!("EVAL 1");
    ////////////////////////////////////////////////////////////////////////////////////
    // step 2. d. i. B.: Beaver Triple for Message Well-formedness
    let (b_vec_1d_u8_total, msg_wf) = servers_message_welformedness_check(
        &b_vec_1d_u8,
        &seeds,
        inv_servers,
        a_bt,
        b_bt,
        c_bt,
        &t_c0_alpha,
        &t_c1_alpha,
        &t_c2_alpha,
        &r_c0_eval,
        &r_c1_eval,
        &r_c2_eval,
    );
    let b_vec_1d_total: &[i32] = bytemuck::cast_slice(&b_vec_1d_u8_total);
    let eval1_duration = start.elapsed();
    println!("eval1_duration Time elapsed is: {:?}", eval1_duration);

    println!("EVAL 2");
    // Part 2 .e. : Verify b and e ̄ are binary-valued:
    let b_e_check = server_b_e_check(
        &r2_seed,
        &r3_seed,
        &server_noise_bits,
        &bt_seeds_pt2,
        &correction_pt2a,
        &correction_pt2b,
        inv_servers,
        &b_vec_1d_total,
    );
    let eval2_duration = start.elapsed();
    println!("eval2_duration Time elapsed is: {:?}", eval2_duration);

    if msg_wf && b_e_check {
        println!("Auth Passed");
    } else {
        println!("ERROR: Auth FAILED");
    }
    println!("CHECK IS DONE");
}

// Get Parameters
fn main_param_block() {
    println!("--------------------------///--------------------------");
    println!(
        "Lattice (RLWE) Parameters are N={}, Q={} noise std dev=10 (base off of 6 bits of noise)",
        N_PARAM, Q
    );
    println!("sqrt array = {}", N_PARAM);
    println!("expansion factor is = {}", NUM_BLOCK);
    println!("num servers: {}", NUM_SERVERS);

    // check fill_rand_aes128_modq_nr_2_by_seed
    //let aes_block:f32 = (4*B_SLICE+4*S_SLICE) as f32;

    //println!("A single AES ctr seed generates {} Bytes ({} KB or {} MB)", aes_block, aes_block/1024.0, aes_block/(1024.0*1024.0));

    // B vec + S vec + V vec
    let sent_to_server_block: f32 =
        (E_BYTES * N_PARAM + E_BYTES * N_PARAM * N_PARAM + E_BYTES * NUM_BLOCK * N_PARAM) as f32;
    println!(
        "A single server gets client DPF data sent {} Bytes ({} KB or {} MB)",
        sent_to_server_block,
        sent_to_server_block / 1024.0,
        sent_to_server_block / (1024.0 * 1024.0)
    );

    // V vec + (B+S)) seed
    let sent_to_server_block_seed: f32 = (E_BYTES * NUM_BLOCK * N_PARAM + 32) as f32;
    println!(
        "Other servers gets client DPF data sent {} Bytes ({} KB or {} MB)",
        sent_to_server_block_seed,
        sent_to_server_block_seed / 1024.0,
        sent_to_server_block_seed / (1024.0 * 1024.0)
    );

    /*
    BT_INST1 = 3*N_PARAM+2
    BT_INST2_A = N_PARAM
    BT_INST2_B = NOISE_LEN * NOISE_BITS
     */
    // (rx,st,sa) seed, noise and sign bit seeds, and BTs
    let snip_sent_to_server_block: f32 = (32+( NUM_BLOCK * N_PARAM * (NOISE_BITS*E_BYTES+1)) + E_BYTES*(BT_INST1+BT_INST2_A+BT_INST2_B)) as f32;
    //(E_BYTES * (E_BYTES * N_PARAM + 2 + NUM_BLOCK * N_PARAM * NOISE_BITS) + 2 * 32) as f32;
    println!(
        "A single server gets SNIP data sent {} Bytes ({} KB or {} MB)",
        snip_sent_to_server_block,
        snip_sent_to_server_block / 1024.0,
        snip_sent_to_server_block / (1024.0 * 1024.0)
    );
    // (rx,st,sa) seed, noise and sign bit seeds, and BT seeds
    let snip_sent_to_server_block_seed: f32 = (32+( NUM_BLOCK * N_PARAM * (NOISE_BITS*E_BYTES+1)) + 2*32) as f32;
    //(2 * 32) as f32;
    println!(
        "Other servers gets client DPF data sent {} Bytes ({} KB or {} MB)",
        snip_sent_to_server_block_seed,
        snip_sent_to_server_block_seed / 1024.0,
        snip_sent_to_server_block_seed / (1024.0 * 1024.0)
    );

    println!("In total:");
    let total_data_sent_to_server_block = sent_to_server_block + snip_sent_to_server_block;
    let total_data_sent_to_server_seed = sent_to_server_block_seed + snip_sent_to_server_block_seed;
    println!(
        "A single block server gets total data sent {} Bytes ({} KB or {} MB)",
        total_data_sent_to_server_block,
        total_data_sent_to_server_block / 1024.0,
        total_data_sent_to_server_block / (1024.0 * 1024.0)
    );

    println!(
        "A single seed server gets total data sent {} Bytes ({} KB or {} MB)",
        total_data_sent_to_server_seed,
        total_data_sent_to_server_seed / 1024.0,
        total_data_sent_to_server_seed / (1024.0 * 1024.0)
    );

    println!("--------------------------///--------------------------");
}

fn block_sq_compact_snip_timings_server(
    iterations: usize,
    escale: usize,
    eval_all: usize,
    wait_time: u64,
) {
    println!("----------------------------------------------------");
    println!("BLOCK SEED (SNIP) compact Block Timing");

    //let iterations:usize = 1;
    let eval_iterations: usize = escale * iterations;

    println!("eval_iterations: {}", eval_iterations);
    println!("eval_all_from_seed iterations: {}", eval_all);

    dpf_eval_every_server_timings(eval_iterations);
    thread::sleep(time::Duration::from_secs(wait_time));
    dpf_eval_long_server_timings(eval_iterations);
    thread::sleep(time::Duration::from_secs(wait_time));
    dpf_eval_short_server_timings(eval_iterations);
    thread::sleep(time::Duration::from_secs(wait_time));
    dpf_eval_eval_all_from_seed_timings(eval_all);
    thread::sleep(time::Duration::from_secs(wait_time));
    dpf_eval_eval_all_from_block_timings(eval_all);

    println!("----------------------------------------------------");
}
fn main_authtiming() {
    println!("num servers: {}", NUM_SERVERS);
    println!("N_PARAM: {}", N_PARAM);
    println!("NUM_BLOCK: {}", NUM_BLOCK);
    let start = Instant::now();
    //main_param_block();

    /*
    let iterations: usize = 1000;
    let bscale: usize = 1000;
    let ascale: usize = 10;
    let escale: usize = 1;

    let eval_all: usize = 10;

     */

    // gen_iterations = iterations * bscale;
    // after_iterations = iterations * ascale;
    // eval_iterations = escale * s_iterations
    // eval_all

    let iterations: usize = 1;
    let bscale: usize = 1;
    let ascale: usize = 1;
    let escale: usize = 1;

    let s_iterations: usize = 1;
    let eval_all: usize = 1;

    let wait_time: u64 = 1;

    thread::sleep(time::Duration::from_secs(wait_time));
    block_compact_auth_timings_client(iterations, bscale, ascale, wait_time);
    thread::sleep(time::Duration::from_secs(wait_time));
    block_sq_compact_snip_timings_server(s_iterations, escale, eval_all, wait_time);

    let duration = start.elapsed();
    println!("Total Time elapsed is: {:?}", duration)
}

fn main_block_sq_new_compact_correctness() {
    println!("----main_block_sq_new_compact_correctness----");
    let mut a_vec = vec![0i32; NUM_BLOCK * N_PARAM];

    let mut b_vec_1d_u8 = vec![0u8; E_BYTES * N_PARAM];
    let mut s_vec_1d_u8 = vec![0u8; E_BYTES * N_PARAM * N_PARAM];
    let mut v_vec_u8 = vec![0u8; E_BYTES * NUM_BLOCK * N_PARAM];

    let mut a_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut a_vec[..]);
    fill_rand_aes128_modq_nr(&mut a_vec_u8, E_BYTES * NUM_BLOCK * N_PARAM);

    let mut seeds = [0u8; 32 * (NUM_SERVERS - 1)];

    let buffer: i32 = 128;
    let ori_message: i32 = 101;
    let message: i32 = (ori_message << 9) + buffer;
    let index: usize = 0; //2*512*512+13;//2000;

    println!("GEN");
    dpf_gen_lwe_seed_block_new_sq_compact(
        index,
        message,
        &a_vec[..],
        &mut b_vec_1d_u8[..],
        &mut s_vec_1d_u8[..],
        &mut v_vec_u8[..],
        &mut seeds[..],
    );

    println!("EVALs");
    {
        let mut recovered_message_t: i32 = 0;
        let mut recovered_message_total: i32 = 0;
        let mut b_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; E_BYTES * N_PARAM * N_PARAM];

        for eval_s_iter in 0..(NUM_SERVERS - 1) {
            //b_vecs_1d_u8_eval.fill(0);
            //s_vecs_1d_u8_eval.fill(0);
            for i in 0..b_vecs_1d_u8_eval.len() {
                b_vecs_1d_u8_eval[i] = 0;
            }
            for i in 0..s_vecs_1d_u8_eval.len() {
                s_vecs_1d_u8_eval[i] = 0;
            }

            dpf_eval_lwe_seed_block(
                index,
                &mut recovered_message_t,
                &a_vec,
                &mut b_vecs_1d_u8_eval[..],
                &mut s_vecs_1d_u8_eval[..],
                &seeds[32 * (eval_s_iter)..32 * (eval_s_iter + 1)],
                &v_vec_u8,
            );
            println!("seed loop partials is {}", recovered_message_t);
            recovered_message_total =
                (Wrapping(recovered_message_total) + Wrapping(recovered_message_t)).0;
        }
        println!("----------dpf_eval_lwe_block_new-----------------");
        for _eval_s_iter in (NUM_SERVERS - 1)..NUM_SERVERS {
            dpf_eval_lwe_block_new(
                index,
                &mut recovered_message_t,
                &a_vec,
                &b_vec_1d_u8[..],
                &s_vec_1d_u8[..],
                &v_vec_u8,
            );
            println!("loop partials is {}", recovered_message_t);
            recovered_message_total =
                (Wrapping(recovered_message_total) + Wrapping(recovered_message_t)).0;
        }

        println!(
            "seed loop recovered is {}, noise is {} or {}",
            (recovered_message_total % Q) >> 9,
            modq(recovered_message_total - message),
            -1 * modq(message - recovered_message_total)
        );
        println!("init is {}", (recovered_message_total % Q));
        println!("//////////////////////////////////////////////");
    }
}

// 2^30, 2^32, 2^34, 2^36, 2^38, 2^40
// has expansion factor of
// 2^10, 2^12, 2^14, 2^16, 2^18, 2^20
fn main() {
    main_param_block();

    // Basic NTT checks
    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();

    // correctness of dpf (no auth or snip)
    //main_block_sq_new_compact_correctness();

    // Checks that Auth DPF Passes
    main_check_correctness();

    // Auth Timings
    //main_authtiming();
}
