// Get Parameters
fn main_param() {
    println!("----------------------------------------------------");
    println!("Lattice (RLWE) Parameters are N={}, Q={} noise std dev=10 (base off of 64 bits of noise), MAX Noise=90", N_PARAM, Q);
    println!("sqrt array = {}", N_PARAM);
    println!("NUM_SERVERS = {}", NUM_SERVERS);

    // check fill_rand_aes128_modq_nr_2_by_seed
    let aes_block:f32 = (4*B_SLICE+4*S_SLICE) as f32;

    println!("A single AES ctr seed generates {} Bytes ({} KB or {} MB)", aes_block, aes_block/1024.0, aes_block/(1024.0*1024.0));

    let sent_to_server_block:f32 = (4*N_PARAM+4*N_PARAM*N_PARAM+4*N_PARAM) as f32;
    println!("A single server gets client data sent {} Bytes ({} KB or {} MB)", sent_to_server_block, sent_to_server_block/1024.0, sent_to_server_block/(1024.0*1024.0));
    let sent_to_server_block_seed:f32 = (4*N_PARAM+32) as f32;
    println!("Other servers gets client data sent {} Bytes ({} KB or {} MB)", sent_to_server_block_seed, sent_to_server_block_seed/1024.0, sent_to_server_block_seed/(1024.0*1024.0));

    println!("(can be compressed from 32=>20 if needed)");

    println!("///////");
    println!("Assuming 6 bits of noise");
    let SNIP_sent_to_server_block:f32 = (32*8*6*512) as f32;
    println!("A single server gets client SNIP sent {} Bytes ({} KB or {} MB)", SNIP_sent_to_server_block, SNIP_sent_to_server_block/1024.0, SNIP_sent_to_server_block/(1024.0*1024.0));
    println!("(can be compressed from 32=>20 if needed)");
    println!("----------------------------------------------------");

}

// Get Parameters
fn main_param_block() {
    println!("--------------------------///--------------------------");
    println!("Lattice (RLWE) Parameters are N={}, Q={} noise std dev=10 (base off of 64 bits of noise), MAX Noise=90", N_PARAM, Q);
    println!("sqrt array = {}", N_PARAM);
    println!("expansion factor is = {}", NUM_BLOCK);

    // check fill_rand_aes128_modq_nr_2_by_seed
    let aes_block:f32 = (4*NUM_BLOCK*B_SLICE+4*NUM_BLOCK*S_SLICE) as f32;

    println!("A single AES ctr seed generates {} Bytes ({} KB or {} MB)", aes_block, aes_block/1024.0, aes_block/(1024.0*1024.0));

    let sent_to_server_block:f32 = (4*NUM_BLOCK*N_PARAM+4*NUM_BLOCK*N_PARAM*N_PARAM+4*NUM_BLOCK*N_PARAM) as f32;
    println!("A single server gets client data sent {} Bytes ({} KB or {} MB)", sent_to_server_block, sent_to_server_block/1024.0, sent_to_server_block/(1024.0*1024.0));
    let sent_to_server_block_seed:f32 = (4*NUM_BLOCK*N_PARAM+32) as f32;
    println!("Other servers gets client data sent {} Bytes ({} KB or {} MB)", sent_to_server_block_seed, sent_to_server_block_seed/1024.0, sent_to_server_block_seed/(1024.0*1024.0));

    println!("(can be compressed from 32=>20 if needed)");

    println!("///////");
    println!("Assuming 6 bits of noise");
    let SNIP_sent_to_server_block:f32 = (32*8*6*512) as f32;
    println!("A single server gets client SNIP sent {} Bytes ({} KB or {} MB)", SNIP_sent_to_server_block, SNIP_sent_to_server_block/1024.0, SNIP_sent_to_server_block/(1024.0*1024.0));
    println!("(can be compressed from 32=>20 if needed)");
    println!("--------------------------///--------------------------");

}

fn main_old() {
    println!("Hello, world!");
    let iterations:usize = 1000;

    let mut test = vec![0u8; 4*N_PARAM];
    {
        let gen_start = Instant::now();
        for iter_test in 0..iterations {
             fill_rand_aes128_modq(&mut test, N_PARAM);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("New Time elapsed is: {:?}", gen_duration);
    }
}

fn main_single() {
//fn main() {
    let mut A_vec = vec![0i32; N_PARAM];
    //let mut b_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM];
    //let mut s_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM*N_PARAM];
    let mut b_vecs_1d_u8 = vec![0u8; 4*NUM_SERVERS*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];
    let mut v_vec_u8 = vec![0u8; 4*N_PARAM];

    let mut A_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut A_vec[..]);
    fill_rand_aes128_modq_nr(&mut A_vec_u8, 4*N_PARAM);


    let mut seeds = [0u8; 32*NUM_SERVERS];
    let buffer:i32 = 128;
    let mut message:i32 = (0 <<9)+buffer;

    /////////////////////////////////////////////////////////////////////////////////////////

    let iterations:usize = 1;
    let gen_iterations:usize = iterations;
    let eval_iterations:usize = iterations;
    let all_eval_iterations:usize = iterations;

    println!("gen_iterations: {}", gen_iterations);
    println!("eval_iterations: {}", eval_iterations);
    println!("all_eval_iterations: {}", all_eval_iterations);

    {
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {

            dpf_gen_lwe_seed(5, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }


 
    //////////////////////////////////////////////////////////////////////////////
    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

        //println!("---------------------------");
        for eval_s_iter in 0..NUM_SERVERS {
            dpf_eval_lwe(5, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-buffer), -1*ntt::mod_32(buffer-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }

    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();
    //////////////////////////////////////////////////////////////////////////////
}

fn main_multiple() {
//fn main() {
    let mut A_vec = vec![0i32; N_PARAM];
    //let mut b_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM];
    //let mut s_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM*N_PARAM];
    let mut b_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM*N_PARAM];
    let mut v_vec_u8 = vec![0u8; 4*NUM_BLOCK*N_SQRT_DIM];

    let mut A_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut A_vec[..]);
    fill_rand_aes128_modq_nr(&mut A_vec_u8, 4*N_PARAM);


    let mut seeds = [0u8; 32*NUM_SERVERS*NUM_BLOCK];
    let buffer:i32 = 128;
    let ori_message:i32 = 13;
    let shift:usize = 9;
    let padded_message:i32 = (ori_message <<9);
    let mut message:i32 = padded_message+buffer;
    let index:usize = 2000;

    /////////////////////////////////////////////////////////////////////////////////////////

    let iterations:usize = 1;
    let gen_iterations:usize = iterations;
    let eval_iterations:usize = iterations;
    let all_eval_iterations:usize = iterations;

    println!("gen_iterations: {}", gen_iterations);
    println!("eval_iterations: {}", eval_iterations);
    println!("all_eval_iterations: {}", all_eval_iterations);
{
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {

            dpf_gen_lwe_seed_block(index, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }


 
    //////////////////////////////////////////////////////////////////////////////
    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

/*
        for eval_s_iter in 0..NUM_SERVERS {
            dpf_eval_lwe(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }
*/
        recovered_message_total = dpf_eval_lwe_block(index, &mut recovered_message_t, &A_vec,
            &mut b_vecs_1d_u8[..],&mut s_vecs_1d_u8[..], &mut v_vec_u8[..]);

        println!("loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, 
            ntt::mod_32(recovered_message_total-padded_message-buffer), 
            -1*ntt::mod_32(padded_message+buffer-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }

    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();
    //////////////////////////////////////////////////////////////////////////////
}

fn main_single_timings() {
//fn main() {
    let mut A_vec = vec![0i32; N_PARAM];
    //let mut b_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM];
    //let mut s_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM*N_PARAM];
    let mut b_vecs_1d_u8 = vec![0u8; 4*NUM_SERVERS*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];
    let mut v_vec_u8 = vec![0u8; 4*N_SQRT_DIM];

    let mut A_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut A_vec[..]);
    fill_rand_aes128_modq_nr(&mut A_vec_u8, 4*N_PARAM);


    let mut seeds = [0u8; 32*NUM_SERVERS];
    let buffer:i32 = 128;
    let mut message:i32 = (0 <<9)+buffer;

    /////////////////////////////////////////////////////////////////////////////////////////

    let iterations:usize = 1000;
    let gen_iterations:usize = iterations;
    let eval_iterations:usize = iterations;
    let all_eval_iterations:usize = iterations;

    println!("gen_iterations: {}", gen_iterations);
    println!("eval_iterations: {}", eval_iterations);
    println!("all_eval_iterations: {}", all_eval_iterations);

    {
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {

            dpf_gen_lwe_seed(5, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }


 
    //////////////////////////////////////////////////////////////////////////////
    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe(5, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval Time elapsed is: {:?}", eval_duration);
    }

    //////////////////////////////////////////////////////////////////////////////
    {
        let mut all_messages = vec![0i32; N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_iterations {

            dpf_eval_lwe_all_base(&mut all_messages, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL Eval Time elapsed is: {:?}", all_eval_duration);
    }
 
    //////////////////////////////////////////////////////////////////////////////

    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

        //println!("---------------------------");
        for eval_s_iter in 0..NUM_SERVERS {
            dpf_eval_lwe(5, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-buffer), -1*ntt::mod_32(buffer-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }

    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();
    //////////////////////////////////////////////////////////////////////////////
}

fn main_multiple_timings() {
//fn main() {
    let mut A_vec = vec![0i32; N_PARAM];
    //let mut b_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM];
    //let mut s_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM*N_PARAM];
    let mut b_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM*N_PARAM];
    let mut v_vec_u8 = vec![0u8; 4*NUM_BLOCK*N_SQRT_DIM];

    let mut A_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut A_vec[..]);
    fill_rand_aes128_modq_nr(&mut A_vec_u8, 4*N_PARAM);


    let mut seeds = [0u8; SEED_BLOCK*NUM_BLOCK];
    let buffer:i32 = 128;
    let ori_message:i32 = 13;
    let shift:usize = 9;
    let padded_message:i32 = (ori_message <<9);
    let mut message:i32 = padded_message+buffer;
    let index:usize = 2000;

    /////////////////////////////////////////////////////////////////////////////////////////

    let iterations:usize = 1;
    let gen_iterations:usize = iterations;
    let eval_iterations:usize = iterations;
    let all_eval_iterations:usize = iterations;

    println!("gen_iterations: {}", gen_iterations);
    println!("eval_iterations: {}", eval_iterations);
    println!("all_eval_iterations: {}", all_eval_iterations);

    {
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {

            dpf_gen_lwe_seed_block(index, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }

    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe(5, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval Time elapsed is: {:?}", eval_duration);
    }

    {
        let mut all_messages = vec![0i32; NUM_BLOCK*N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_iterations {
            for block_iter in 0..NUM_BLOCK {
                dpf_eval_lwe_all_base(&mut all_messages[block_iter*N_PARAM*N_PARAM..(block_iter+1)*N_PARAM*N_PARAM], &A_vec
                    , &b_vecs_1d_u8[(block_iter*B_BLOCK_SLICEb+4*b_s(eval_s_iter))..(block_iter*B_BLOCK_SLICEb+4*b_s(eval_s_iter+1))]
                    , &s_vecs_1d_u8[(block_iter*S_BLOCK_SLICEb+4*s_s(eval_s_iter))..(block_iter*S_BLOCK_SLICEb+4*s_s(eval_s_iter+1))]
                    ,  &v_vec_u8[block_iter*V_BLOCK_SLICEb..(block_iter+1)*V_BLOCK_SLICEb]);
            }
        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL Eval Time elapsed is: {:?}", all_eval_duration);
    }

 
    //////////////////////////////////////////////////////////////////////////////
    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

     recovered_message_total = dpf_eval_lwe_block(index, &mut recovered_message_t, &A_vec,
            &mut b_vecs_1d_u8[..],&mut s_vecs_1d_u8[..], &mut v_vec_u8[..]);

        println!("loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, 
            ntt::mod_32(recovered_message_total-padded_message-buffer), 
            -1*ntt::mod_32(padded_message+buffer-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }

    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();
    //////////////////////////////////////////////////////////////////////////////
}


pub fn mul_shares_p1(in_y: i32, in_z: i32, bt_a: i32, bt_b: i32, bt_c: i32) -> (i32, i32) {
    let d_out:i32 = in_y-bt_a;
    let e_out:i32 = in_z-bt_b;

    return (d_out, e_out);
}

pub fn gcdExtended(a: i32, b: i32, x: &mut i32, y: &mut i32) -> i32 {
    if a == 0 {
        *x = 0;
        *y = 1;

        return b;
    }

    let mut x1:i32 = 0;
    let mut y1:i32 = 0;

    //println!("{} % {} = {}", b, a, (b % a));
    //println!("{} / {} = {}", b, a, (b / a));
    let gcd = gcdExtended(b % a, a, &mut x1, &mut y1);

    *x = y1 - (b/a) * x1;
    *y = x1;

    return gcd;
}

pub fn modInverse(a: i32, b: i32) -> i32 {
    let mut x:i32 = 0;
    let mut y:i32 = 0;

    let g = gcdExtended(a, b, &mut x, &mut y); 
    if g != 1 {
        println!("No Inverse Exists!");
    }

    let inv = ((x % b) +b) % b;
    return inv;
}

pub fn mul_shares_p2(in_d: i32, in_e: i32, bt_a: i32, bt_b: i32, bt_c: i32, inv_s: i32) -> i32 {
    //let output:i64 = (in_d as i64)*in_e*inv_s + in_d*bt_b + in_e*bt_a + bt_c;
    let output:i64 = (in_d as i64)*(in_e as i64)*(inv_s as i64) + 
    (in_d as i64)*(bt_b as i64) + 
    (in_e as i64)*(bt_a as i64) + (bt_c as i64);

    return (output%Q as i64) as i32;
}


// SNIP Bit test
fn main_debug() {
    let mut bit_shares_vec = vec![0i32; NUM_SERVERS];
    let mut bit_shares_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut bit_shares_vec[..]);
    let bit_shares = fill_rand_aes128_modq(&mut bit_shares_vec_u8, NUM_SERVERS);

    let mut bit_sum:i32 = 0;
    for iter in 0..NUM_SERVERS {
        bit_sum += bit_shares[iter];
    }

    bit_shares[0] += 1-bit_sum;
    bit_sum= 1;

    let mut bit_temp:i32 = 0;
    for iter in 0..NUM_SERVERS {
        println!("b values are {}", bit_shares[iter]);
        bit_temp += bit_shares[iter];
    }
    println!("b sums up to {} {}", bit_temp, bit_sum);


    ///////////////////////////////
    // SNIP Creation
    // Input: b
    // Output: SNIP_out
    ///////////////////////////////

    let mut SNIP_rand_vec = vec![0i32; BIT_SNIP_RAND_VAL];
    let mut SNIP_out = vec![SNIP_i { f_zero_i: 0, g_zero_i: 0, h0_i: 0, h1_i: 0, h2_i: 0, a_i: 0, b_i: 0, c_i: 0 }; NUM_SERVERS];

    let mut f_zero:i32 = 0;
    let mut g_zero:i32 = 0;

    let mut h0:i32 = 0;
    let mut h1:i32 = 0;
    let mut h2:i32 = 0;

    let mut a:i32 = 0;
    let mut b:i32 = 0;
    let mut c:i32 = 0;

    println!("SNIP_rand_vec length is {}", SNIP_rand_vec.len());
    let mut SNIP_rand_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut SNIP_rand_vec[..]);
    println!("SNIP_rand_vec length is {}", SNIP_rand_vec_u8.len());
    let mut rand_values = fill_rand_aes128_modq(&mut SNIP_rand_vec_u8, BIT_SNIP_RAND_VAL);

    for iter in 0..NUM_SERVERS {
        f_zero += rand_values[iter];
        g_zero += rand_values[NUM_SERVERS+iter];

        h0 += rand_values[2*NUM_SERVERS+iter];
        h1 += rand_values[3*NUM_SERVERS+iter];
        h2 += rand_values[4*NUM_SERVERS+iter];

        a += rand_values[5*NUM_SERVERS+iter];
        b += rand_values[6*NUM_SERVERS+iter];
        c += rand_values[7*NUM_SERVERS+iter];
    }
    f_zero=modq(f_zero);
    g_zero=modq(g_zero);

    // setting the sum of h0_i = f_zero*g_zero
    println!("{} * {} fg[0] = {}", modq(f_zero), modq(g_zero), modq(mul_modq(f_zero,g_zero)));
    rand_values[2*NUM_SERVERS] = modq(rand_values[2*NUM_SERVERS]+
        mul_modq(f_zero,g_zero)-h0);

    // setting the sum of h1_i = (b-f_zero)*g_zero+(b-1-g_zero)*f_zero
    rand_values[3*NUM_SERVERS] = modq(rand_values[3*NUM_SERVERS]+ 
        (mul_modq(modq(bit_sum-f_zero), g_zero)+
        mul_modq(modq(bit_sum-1-g_zero),f_zero))-h1);
    println!("h1 target is {}", modq((mul_modq(modq(bit_sum-f_zero), g_zero)+
        mul_modq(modq(bit_sum-1-g_zero),f_zero))));

    // setting the sum of h2_i = (b-f_zero)*(b-1-g_zero)
    rand_values[4*NUM_SERVERS] = modq(rand_values[4*NUM_SERVERS]+
        mul_modq(modq(bit_sum-f_zero), modq(bit_sum-1-g_zero))-h2);
    println!("h2 target is {}" ,mul_modq(modq(bit_sum-f_zero), modq(bit_sum-1-g_zero)));

    // setting a*b = c
    rand_values[7*NUM_SERVERS] += (((a as i64)*(b as i64)) % (Q as i64)) as i32 -c;

    for iter in 0..NUM_SERVERS {

        SNIP_out[iter].f_zero_i = rand_values[iter];
        SNIP_out[iter].g_zero_i = rand_values[NUM_SERVERS+iter];

        SNIP_out[iter].h0_i = modq(rand_values[2*NUM_SERVERS+iter]);
        SNIP_out[iter].h1_i = modq(rand_values[3*NUM_SERVERS+iter]);
        SNIP_out[iter].h2_i = modq(rand_values[4*NUM_SERVERS+iter]);

        SNIP_out[iter].a_i = rand_values[5*NUM_SERVERS+iter];
        SNIP_out[iter].b_i = rand_values[6*NUM_SERVERS+iter];
        SNIP_out[iter].c_i = rand_values[7*NUM_SERVERS+iter];
    }

    let mut a_temp:i32 = 0;
    let mut b_temp:i32 = 0;
    let mut c_temp:i32 = 0;

    for iter in 0..NUM_SERVERS {
        a_temp += SNIP_out[iter].a_i;
        b_temp += SNIP_out[iter].b_i;
        c_temp += SNIP_out[iter].c_i;
    }

    a_temp = ((a_temp%Q)+Q) % Q;
    b_temp = ((b_temp%Q)+Q) % Q;
    let ab_prod:i32 = (((a_temp as i64) * (b_temp as i64)) % (Q as i64)) as i32;
    c_temp = ((c_temp%Q)+Q) % Q;
    println!("{} *{} = {}",a_temp, b_temp, c_temp);
    if ab_prod == c_temp {
        println!("Proper Beaver Triple!");
    } else {
        println!("FAILLL Beaver Triple!");
    }

    let mut h0_temp:i32 = 0;
    let mut h1_temp:i32 = 0;
    let mut h2_temp:i32 = 0;
    for iter in 0..NUM_SERVERS {
        h0_temp += SNIP_out[iter].h0_i;
        h1_temp += SNIP_out[iter].h1_i;
        h2_temp += SNIP_out[iter].h2_i;
    }
    println!("h: {} {} {} => {}",modq(h0_temp), modq(h1_temp), modq(h2_temp), 
        modq(h0_temp+ h1_temp+ h2_temp));



    ///////////////////////////////
    // SNIP Verification
    // Input: SNIP_out
    // Output: Pass or Fail
    ///////////////////////////////

    // 1 Server picks a random point
    let mut rand_point_vec = vec![0i32; 1];

    let mut rand_point_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut rand_point_vec[..]);
    let mut rand_value = fill_rand_aes128_modq(&mut rand_point_vec_u8, 1);
    //rand_value[0] = 0;
    println!("rand point is {}", rand_value[0]);

    // Calculate [f(r)]_i and [g(r)]_i
    let mut fr_i = vec![0i32; NUM_SERVERS];
    let mut gr_i = vec![0i32; NUM_SERVERS];
    let mut hr_i = vec![0i32; NUM_SERVERS];
    for iter in 0..NUM_SERVERS {
        fr_i[iter] = modq(SNIP_out[iter].f_zero_i + 
            mul_modq(modq(bit_shares[iter]-SNIP_out[iter].f_zero_i), rand_value[0]));
        gr_i[iter] = modq(SNIP_out[iter].g_zero_i + 
            mul_modq(modq(bit_shares[iter]-SNIP_out[iter].g_zero_i), rand_value[0]));
        hr_i[iter] = modq(SNIP_out[iter].h0_i + 
        mul_modq(SNIP_out[iter].h1_i, rand_value[0]) + 
        mul_modq(mul_modq(SNIP_out[iter].h2_i, rand_value[0]), rand_value[0]));
    }
    gr_i[0] = modq(SNIP_out[0].g_zero_i + 
            mul_modq(modq(bit_shares[0]-1-SNIP_out[0].g_zero_i), rand_value[0]));

    let mut fr:i32 = 0;
    let mut gr:i32 = 0;
    let mut hr:i32 = 0;
    for iter in 0..NUM_SERVERS {
        fr += fr_i[iter];
        gr += gr_i[iter];
        hr += hr_i[iter];
    }
    fr = modq(fr);
    gr = modq(gr);
    hr = modq(hr);
    println!("fr: {} * gr: {} ", fr, gr);

    let fgr_mul:i32 = mul_modq(fr, gr);
    if hr != fgr_mul {println!("NOT EQUAL!!!!----------------------------");}
    println!("{} ?= {}",fgr_mul, hr);


    // Beaver Tiple multiplication
    let (mut d, mut e) = mul_shares_p1(fr_i[0], gr_i[0], SNIP_out[0].a_i, SNIP_out[0].b_i, SNIP_out[0].c_i);
    for iter in 1..NUM_SERVERS {
        let (di, ei) = mul_shares_p1(fr_i[iter], gr_i[iter], SNIP_out[iter].a_i, SNIP_out[iter].b_i, SNIP_out[iter].c_i);
        d += di;
        e += ei;
    }

    let inv_servers:i32 = modInverse(NUM_SERVERS as i32, Q);

    let mut sigma_total:i32 = 0;
    for iter in 0..NUM_SERVERS {
        println!("{} {} = {}", SNIP_out[iter].a_i, SNIP_out[iter].b_i, SNIP_out[iter].c_i);
        let sigma_i = mul_shares_p2(d, e, 
            SNIP_out[iter].a_i, SNIP_out[iter].b_i, SNIP_out[iter].c_i, inv_servers);
        sigma_total += mul_modq(rand_value[0],(sigma_i-hr_i[iter]));
    }

    println!("sigma_total {}", ((sigma_total % Q)+Q)%Q);


/*
    let (mut d, mut e) = mul_shares_p1(b_i[0], b_i[0]-1, SNIP_out[0].a_i, SNIP_out[0].b_i, SNIP_out[0].c_i);
    for iter in 1..NUM_SERVERS {
        let (di, ei) = mul_shares_p1(b_i[iter], b_i[iter], SNIP_out[iter].a_i, SNIP_out[iter].b_i, SNIP_out[iter].c_i);
        d += di;
        e += ei;
    }

    let inv_servers:i32 = modInverse(NUM_SERVERS as i32, Q);

    let mut sigma_total:i32 = 0;
    for iter in 0..NUM_SERVERS {
        println!("{} {} = {}", SNIP_out[iter].a_i, SNIP_out[iter].b_i, SNIP_out[iter].c_i);
        let sigma_i = mul_shares_p2(d, e, 
            SNIP_out[iter].a_i, SNIP_out[iter].b_i, SNIP_out[iter].c_i, inv_servers);
        sigma_total += sigma_i;
    }

    println!("sigma_total {}", ((sigma_total % Q)+Q)%Q);

    // if sigma_total = 0, then passed test
*/
}

fn create_bit_shares(bit_value:i32, bit_shares_vec: &mut [i32]) {
    let mut bit_shares_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut bit_shares_vec[..]);
    let bit_shares = fill_rand_aes128_modq(&mut bit_shares_vec_u8, NUM_SERVERS);

    let mut bit_sum:i32 = 0;
    for iter in 0..NUM_SERVERS {
        bit_sum += bit_shares[iter];
    }

    bit_shares[0] += bit_value-bit_sum;
}

fn create_bit_snip (bit_value:i32, SNIP_out: &mut [SNIP_i]) {
    let mut SNIP_rand_vec = vec![0i32; BIT_SNIP_RAND_VAL];
    
    let mut f_zero:i32 = 0;
    let mut g_zero:i32 = 0;

    let mut h0:i32 = 0;
    let mut h1:i32 = 0;
    let mut h2:i32 = 0;

    let mut a:i32 = 0;
    let mut b:i32 = 0;
    let mut c:i32 = 0;

    let mut SNIP_rand_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut SNIP_rand_vec[..]);
    let mut rand_values = fill_rand_aes128_modq(&mut SNIP_rand_vec_u8, BIT_SNIP_RAND_VAL);

    for iter in 0..NUM_SERVERS {
        f_zero += rand_values[iter];
        g_zero += rand_values[NUM_SERVERS+iter];

        h0 += rand_values[2*NUM_SERVERS+iter];
        h1 += rand_values[3*NUM_SERVERS+iter];
        h2 += rand_values[4*NUM_SERVERS+iter];

        a += rand_values[5*NUM_SERVERS+iter];
        b += rand_values[6*NUM_SERVERS+iter];
        c += rand_values[7*NUM_SERVERS+iter];
    }
    f_zero=modq(f_zero);
    g_zero=modq(g_zero);

    // setting the sum of h0_i = f_zero*g_zero
    rand_values[2*NUM_SERVERS] = modq(rand_values[2*NUM_SERVERS]+
        mul_modq(f_zero,g_zero)-h0);

    // setting the sum of h1_i = (b-f_zero)*g_zero+(b-1-g_zero)*f_zero
    rand_values[3*NUM_SERVERS] = modq(rand_values[3*NUM_SERVERS]+ 
        (mul_modq(modq(bit_value-f_zero), g_zero)+
        mul_modq(modq(bit_value-1-g_zero),f_zero))-h1);

    // setting the sum of h2_i = (b-f_zero)*(b-1-g_zero)
    rand_values[4*NUM_SERVERS] = modq(rand_values[4*NUM_SERVERS]+
        mul_modq(modq(bit_value-f_zero), modq(bit_value-1-g_zero))-h2);

    // setting a*b = c
    rand_values[7*NUM_SERVERS] += (((a as i64)*(b as i64)) % (Q as i64)) as i32 -c;

    for iter in 0..NUM_SERVERS {

        SNIP_out[iter].f_zero_i = rand_values[iter];
        SNIP_out[iter].g_zero_i = rand_values[NUM_SERVERS+iter];

        SNIP_out[iter].h0_i = modq(rand_values[2*NUM_SERVERS+iter]);
        SNIP_out[iter].h1_i = modq(rand_values[3*NUM_SERVERS+iter]);
        SNIP_out[iter].h2_i = modq(rand_values[4*NUM_SERVERS+iter]);

        SNIP_out[iter].a_i = rand_values[5*NUM_SERVERS+iter];
        SNIP_out[iter].b_i = rand_values[6*NUM_SERVERS+iter];
        SNIP_out[iter].c_i = rand_values[7*NUM_SERVERS+iter];
    }
}

fn gen_rand_pt () -> i32 {
    let mut rand_pt:i32 = thread_rng().gen();
    while (rand_pt as u32) > MAX_RAND {
        rand_pt = thread_rng().gen();
    }
    return modq(rand_pt);
}

fn server_pt1 (bit_shares_vec: &[i32], rand_pt:i32, SNIP: & [SNIP_i], fr_i: &mut [i32], gr_i: &mut [i32], hr_i: &mut [i32],
    d_i: &mut [i32], e_i: &mut [i32]) {
    for iter in 0..NUM_SERVERS {
        fr_i[iter] = modq(SNIP[iter].f_zero_i + 
            mul_modq(modq(bit_shares_vec[iter]-SNIP[iter].f_zero_i), rand_pt));
        if iter == 0 {
            gr_i[iter] = modq(SNIP[iter].g_zero_i + 
                mul_modq(modq(bit_shares_vec[iter]-1-SNIP[iter].g_zero_i), rand_pt));
        } else {
            gr_i[iter] = modq(SNIP[iter].g_zero_i + 
                mul_modq(modq(bit_shares_vec[iter]-SNIP[iter].g_zero_i), rand_pt));
        }
        hr_i[iter] = modq(SNIP[iter].h0_i + 
            mul_modq(SNIP[iter].h1_i, rand_pt) + 
            mul_modq(mul_modq(SNIP[iter].h2_i, rand_pt), rand_pt));

        // Beaver Tiple multiplication
        (d_i[iter], e_i[iter]) = mul_shares_p1(fr_i[iter], gr_i[iter], 
            SNIP[iter].a_i, SNIP[iter].b_i, SNIP[iter].c_i);
    }
}

const CLIENT_ROUNDS:usize = 1;
const SERVER_ROUNDS:usize = 1;

// SNIP Perf Numbers
fn main_snip() {
    println!("----------------------------------------------------");
    println!("SNIP SINGLE BIT TIMING");
    println!("CLIENT_ROUNDS: {}", CLIENT_ROUNDS);
    println!("SERVER_ROUNDS: {}", SERVER_ROUNDS);

    let bit_actual_value:i32 = 1;

    let mut bit_shares_vec = vec![0i32; NUM_SERVERS];
    let mut SNIP_out = vec![SNIP_i { f_zero_i: 0, g_zero_i: 0, h0_i: 0, h1_i: 0, h2_i: 0, a_i: 0, b_i: 0, c_i: 0 }; NUM_SERVERS];

let client_start = Instant::now();
for iter_test in 0..CLIENT_ROUNDS {
    create_bit_shares(bit_actual_value, &mut bit_shares_vec[..]);

    ///////////////////////////////
    // SNIP Creation
    // Input: b
    // Output: SNIP_out
    ///////////////////////////////
    create_bit_snip (bit_actual_value, &mut SNIP_out);
}
let client_duration = client_start.elapsed();
println!("Client SNIP Creation is: {:?}", client_duration);

    ///////////////////////////////
    // SNIP Verification
    // Input: SNIP_out
    // Output: Pass or Fail
    ///////////////////////////////

    // 1 Server picks a random point
    let mut rand_pt:i32 = 0;
let mut server_start = Instant::now();
for iter_test in 0..SERVER_ROUNDS {
    rand_pt = gen_rand_pt();
}
let mut server_duration = server_start.elapsed();
println!("Server Randpoint is: {:?}", server_duration);    

    // Calculate [f(r)]_i and [g(r)]_i
    let mut fr_i = vec![0i32; NUM_SERVERS];
    let mut gr_i = vec![0i32; NUM_SERVERS];
    let mut hr_i = vec![0i32; NUM_SERVERS];

    let mut d:i32 = 0;
    let mut e:i32 = 0;
    let mut d_i = vec![0i32; NUM_SERVERS];
    let mut e_i = vec![0i32; NUM_SERVERS];

let mut server_start = Instant::now();
for iter_test in 0..SERVER_ROUNDS {

    // Parallel Server Computation
    server_pt1 (& bit_shares_vec, rand_pt, & SNIP_out, &mut fr_i, &mut gr_i, &mut hr_i,
    &mut d_i,&mut e_i);
}
server_duration += (server_start.elapsed()/NUM_SERVERS as u32);
println!("Server Parallel pt1 is: {:?}", server_duration);

let mut inv_servers:i32 = 0;
inv_servers = modInverse(NUM_SERVERS as i32, Q);

server_start = Instant::now();
for iter_test in 0..SERVER_ROUNDS {
    // Each Server Computes
    for iter in 0..NUM_SERVERS {
        d+=d_i[iter];
        e+=e_i[iter];
    }

    
}
server_duration += server_start.elapsed();
println!("Server each pt1 is: {:?}", server_duration);

    let mut sigma_i = vec![0i32; NUM_SERVERS];

server_start = Instant::now();
for iter_test in 0..SERVER_ROUNDS {
    // Parallel Server Computation    
    for iter in 0..NUM_SERVERS {
        sigma_i[iter] = mul_shares_p2(d, e, 
            SNIP_out[iter].a_i, SNIP_out[iter].b_i, SNIP_out[iter].c_i, inv_servers);

    }
}
server_duration += (server_start.elapsed()/NUM_SERVERS as u32);
println!("Server Parallel pt2 is: {:?}", server_duration);

    // Each Server Computes
    let mut sigma_total:i32 = 0;

server_start = Instant::now();
for iter_test in 0..SERVER_ROUNDS {
    for iter in 0..NUM_SERVERS {
        sigma_total += mul_modq(rand_pt,(sigma_i[iter]-hr_i[iter]));
    }
    sigma_total = modq(sigma_total);
}
server_duration += server_start.elapsed();
println!("Server each pt2 is: {:?}", server_duration);

    if sigma_total != 0 {
        println!("Schwartz-Zippel FAILLLLLLLLLLLLLLLLLLED VALIDATION");
    }

    //  Evaluate h(1) to see if it is equal to 0
    let mut h_one_i = vec![0i32; NUM_SERVERS];
server_start = Instant::now();
for iter_test in 0..SERVER_ROUNDS {
    for iter in 0..NUM_SERVERS {
        h_one_i[iter] = modq(SNIP_out[iter].h0_i + 
        SNIP_out[iter].h1_i + 
        SNIP_out[iter].h2_i);
    }
}
server_duration += (server_start.elapsed()/NUM_SERVERS as u32);
println!("Server Parallel pt3 is: {:?}", server_duration);

    // Sum h(1)
    let mut h_one_total:i32 = 0;
server_start = Instant::now();
for iter_test in 0..SERVER_ROUNDS {
    for iter in 0..NUM_SERVERS {
        h_one_total += h_one_i[iter];
    }
    h_one_total = modq(h_one_total);
}
server_duration += server_start.elapsed();
println!("Server each pt3 is: {:?}", server_duration);
    if h_one_total != 0 {
        println!("SNIP FAILLLLLLLLLLLLLLLLLLED VALIDATION");
    }


println!("----------------------------------------------------");
}


fn single_block_seed_main() {
    println!("----------------------------------------------------");
    println!("Single SEED Block Timing");
    let mut A_vec = vec![0i32; N_PARAM];
    //let mut b_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM];
    //let mut s_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM*N_PARAM];
    let mut b_vecs_1d_u8 = vec![0u8; 4*NUM_SERVERS*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];
    let mut v_vec_u8 = vec![0u8; 4*N_PARAM];

    let mut A_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut A_vec[..]);
    fill_rand_aes128_modq_nr(&mut A_vec_u8, 4*N_PARAM);


    let mut seeds = [0u8; 32*NUM_SERVERS];
    let buffer:i32 = 128;
    let ori_message = 13;
    let mut message:i32 = (ori_message <<9)+buffer;
    let index:usize = 5;

    /////////////////////////////////////////////////////////////////////////////////////////
/*
    let iterations:usize = 1000000;
    let gen_iterations:usize = iterations/100;
    let eval_iterations:usize = iterations;
    let eval_seed_iterations:usize = iterations/50;
    let all_eval_iterations:usize = iterations/500;
    let all_eval_seed_iterations:usize = iterations/500;
*/

    let iterations:usize = 1;
    let gen_iterations:usize = iterations;
    let eval_iterations:usize = iterations;
    let eval_seed_iterations:usize = iterations;
    let all_eval_iterations:usize = 0;
    let all_eval_seed_iterations:usize = 0;

    println!("gen_iterations: {}", gen_iterations);
    println!("eval_iterations: {}", eval_iterations);
    println!("eval_seed_iterations: {}", eval_seed_iterations);
    println!("all_eval_iterations: {}", all_eval_iterations);
    println!("all_eval_seed_iterations: {}", all_eval_seed_iterations);

    {
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {
            dpf_gen_lwe_seed(index, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }


 
    //////////////////////////////////////////////////////////////////////////////
    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval Time elapsed is: {:?}", eval_duration);
    }

    {
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];

        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_seed_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe_seed(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("seed Eval Time elapsed is: {:?}", eval_duration);
    }

    //////////////////////////////////////////////////////////////////////////////
    {
        let mut all_messages = vec![0i32; N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_iterations {

            dpf_eval_lwe_all_base(&mut all_messages, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL Eval Time elapsed is: {:?}", all_eval_duration);
    }

    {
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];

        let mut all_messages = vec![0i32; N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_seed_iterations {

            dpf_eval_lwe_seed_all_base(&mut all_messages, &A_vec
                , &mut b_vecs_1d_u8_eval[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("seed ALL (seed) Eval Time elapsed is: {:?}", all_eval_duration);
    }
 
    //////////////////////////////////////////////////////////////////////////////

    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

        //println!("---------------------------");
        for eval_s_iter in 0..NUM_SERVERS {
            dpf_eval_lwe(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }

    {
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];

        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

        for eval_s_iter in 0..(NUM_SERVERS-1) {
            dpf_eval_lwe_seed(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("-loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }
        //println!("---------------------------");
        for eval_s_iter in (NUM_SERVERS-1)..NUM_SERVERS {
            dpf_eval_lwe(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("-loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("seed loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }

    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();
    //////////////////////////////////////////////////////////////////////////////
    println!("----------------------------------------------------");
}

fn single_block_seed_sq_main() {
    println!("----------------------------------------------------");
    println!("Single SEED Block Timing");
    let mut A_vec = vec![0i32; N_PARAM];
    //let mut b_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM];
    //let mut s_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM*N_PARAM];
    let mut b_vecs_1d_u8 = vec![0u8; 4*NUM_SERVERS*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];
    let mut v_vec_u8 = vec![0u8; 4*N_PARAM];

    let mut A_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut A_vec[..]);
    fill_rand_aes128_modq_nr(&mut A_vec_u8, 4*N_PARAM);


    let mut seeds = [0u8; 32*NUM_SERVERS];
    let buffer:i32 = 128;
    let ori_message = 13;
    let mut message:i32 = (ori_message <<9)+buffer;
    let index:usize = 5;

    /////////////////////////////////////////////////////////////////////////////////////////
/*
    let iterations:usize = 1000000;
    let gen_iterations:usize = iterations/100;
    let eval_iterations:usize = iterations;
    let eval_seed_iterations:usize = iterations/50;
    let all_eval_iterations:usize = iterations/500;
    let all_eval_seed_iterations:usize = iterations/500;
*/

    let iterations:usize = 1;
    let gen_iterations:usize = iterations;
    let eval_iterations:usize = iterations;
    let eval_seed_iterations:usize = iterations;
    let all_eval_iterations:usize = 0;
    let all_eval_seed_iterations:usize = 0;

    println!("gen_iterations: {}", gen_iterations);
    println!("eval_iterations: {}", eval_iterations);
    println!("eval_seed_iterations: {}", eval_seed_iterations);
    println!("all_eval_iterations: {}", all_eval_iterations);
    println!("all_eval_seed_iterations: {}", all_eval_seed_iterations);

    {
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {
            dpf_gen_lwe_seed_sq(index, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }
/*
    {
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {
            dpf_gen_lwe_seed(index, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }
*/

    //////////////////////////////////////////////////////////////////////////////
    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval Time elapsed is: {:?}", eval_duration);
    }

 
    {
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];

        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_seed_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe_seed(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("seed Eval Time elapsed is: {:?}", eval_duration);
    }

    {
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];

        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_seed_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe_seed_sq(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("sq seed Eval Time elapsed is: {:?}", eval_duration);
    }
/*
    //////////////////////////////////////////////////////////////////////////////
    {
        let mut all_messages = vec![0i32; N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_iterations {

            dpf_eval_lwe_all_base(&mut all_messages, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL Eval Time elapsed is: {:?}", all_eval_duration);
    }


    {
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];

        let mut all_messages = vec![0i32; N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_seed_iterations {

            dpf_eval_lwe_seed_all_base(&mut all_messages, &A_vec
                , &mut b_vecs_1d_u8_eval[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("seed ALL (seed) Eval Time elapsed is: {:?}", all_eval_duration);
    }
*/ 
    //////////////////////////////////////////////////////////////////////////////

    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

        //println!("---------------------------");
        for eval_s_iter in 0..NUM_SERVERS {
            dpf_eval_lwe(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }

    {
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*N_PARAM*N_PARAM];

        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

        for eval_s_iter in 0..(NUM_SERVERS-1) {
            dpf_eval_lwe_seed_sq(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("-loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }
        //println!("---------------------------");
        for eval_s_iter in (NUM_SERVERS-1)..NUM_SERVERS {
            dpf_eval_lwe(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*b_s(eval_s_iter)..4*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*s_s(eval_s_iter)..4*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("-loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("seed loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }

    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();
    //////////////////////////////////////////////////////////////////////////////
    println!("----------------------------------------------------");
}


fn main_block_timings_new() {
    println!("----------------------------------------------------");
    println!("BLOCK SEED Block Timing");
    let mut A_vec = vec![0i32; NUM_BLOCK*N_PARAM];
    //let mut b_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM];
    //let mut s_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM*N_PARAM];
    let mut b_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM*N_PARAM];
    let mut v_vec_u8 = vec![0u8; 4*NUM_BLOCK*N_PARAM];

    let mut A_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut A_vec[..]);
    fill_rand_aes128_modq_nr(&mut A_vec_u8, 4*NUM_BLOCK*N_PARAM);


    let mut seeds = [0u8; 32*NUM_SERVERS];
    let buffer:i32 = 128;
    let mut ori_message:i32 = 101;
    let mut message:i32 = (ori_message <<9)+buffer;
    let index:usize = 512*512+13;//2000;

    /////////////////////////////////////////////////////////////////////////////////////////
    let iterations:usize = 1;
    let gen_iterations:usize = iterations;
    let eval_iterations:usize = iterations;
    let eval_seed_iterations:usize = iterations;
    let all_eval_iterations:usize = iterations;
    let all_eval_seed_iterations:usize = iterations;
/*
    let iterations:usize = 20;
    let gen_iterations:usize = iterations*3;
    let eval_iterations:usize = iterations*1000;
    let eval_seed_iterations:usize = iterations*10;
    let all_eval_iterations:usize = iterations;
    let all_eval_seed_iterations:usize = iterations;
*/
    println!("gen_iterations: {}", gen_iterations);
    println!("eval_iterations: {}", eval_iterations);
    println!("eval_seed_iterations: {}", eval_seed_iterations);
    println!("all_eval_iterations: {}", all_eval_iterations);
    println!("all_eval_seed_iterations: {}", all_eval_seed_iterations);

    {
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {

            dpf_gen_lwe_seed_block_new(index, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }


 
    //////////////////////////////////////////////////////////////////////////////
    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe_block_new(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval Time elapsed is: {:?}", eval_duration);
    }

    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM*N_PARAM];

        let eval_start = Instant::now();
        for iter_test in 0..eval_seed_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe_seed_block(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval seed Time elapsed is: {:?}", eval_duration);
    }

    //////////////////////////////////////////////////////////////////////////////

    {
        let mut all_messages = vec![0i32; NUM_BLOCK*N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_iterations {

            dpf_eval_lwe_all_base_block(&mut all_messages, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL Eval Time elapsed is: {:?}", all_eval_duration);
    }
    {
        let mut all_messages = vec![0i32; NUM_BLOCK*N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM*N_PARAM];

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_seed_iterations {

            dpf_eval_lwe_all_base_block_seed(&mut all_messages, &A_vec
                , &mut b_vecs_1d_u8_eval[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL (seed) Eval Time elapsed is: {:?}", all_eval_duration);
    }
 
    //////////////////////////////////////////////////////////////////////////////

    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

        //println!("---------------------------");
        for eval_s_iter in 0..NUM_SERVERS {
            dpf_eval_lwe_block_new(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }


    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM*N_PARAM];

        for eval_s_iter in 0..(NUM_SERVERS-1) {
            dpf_eval_lwe_seed_block(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }
        //println!("---------------------------");
        for eval_s_iter in (NUM_SERVERS-1)..NUM_SERVERS {
            dpf_eval_lwe_block_new(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("seed loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
    }

    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();
    //////////////////////////////////////////////////////////////////////////////
    println!("----------------------------------------------------");
}

/*
This function generated the array of seeds by individual seeds
Runs faster than generating all from a singel seed
 */
 /*
pub fn fill_rand_aes128_modq_nr_2_by_seed_sq(key:&[u8], iv:&[u8], 
        input1: &mut [u8], input2: &mut [u8], 
        len1:usize, len2:usize) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());
    cipher.apply_keystream(&mut input1[0.. len1]);
    //cipher.apply_keystream(&mut input2[0.. len2]);

    let mut output1: &mut [i32] = bytemuck::cast_slice_mut(input1);
    

    let mut temp = [0u8; 4];
    let mut temp_value:u32 = 0;

    for i in 0..(len1/4) {
        while (output1[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0) 
            | ((temp[1] as u32) << 8) 
            | ((temp[2] as u32) << 16)
            | ((temp[3] as u32) << 24);
            temp_value = temp_value%Qu;
            output1[i] = temp_value as i32;
        }
        output1[i] = output1[i]%Q;
    }

    const SEED_LEN:usize = 32;
    let mut temp_seeds = vec![0u8; SEED_LEN*N_PARAM];
    cipher.apply_keystream(&mut temp_seeds);

    let iterations:usize = len2/(4*512);
    for iter in 0..iterations {
        let mut seed_cipher = Aes128Ctr64LE::new((&temp_seeds[32*iter..32*iter+16]).into(), (&temp_seeds[32*iter+16..32*iter+32]).into());
        seed_cipher.apply_keystream(&mut input2[4*512*iter.. 4*512*(iter+1)]);
    }
    let mut output2: &mut [i32] = bytemuck::cast_slice_mut(input2);
    
    for i in 0..(len2/4) {

        if i%512 == 0 {
            cipher =  Aes128Ctr64LE::new((&temp_seeds[32*(i>>9)+16..32*(i>>9)+32]).into(), (&temp_seeds[32*(i>>9)..32*(i>>9)+16]).into());
            temp = [0,0,0,0];
        }

        while (output2[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0) 
            | ((temp[1] as u32) << 8) 
            | ((temp[2] as u32) << 16)
            | ((temp[3] as u32) << 24);
            temp_value = temp_value%Qu;
            output2[i] = temp_value as i32;
        }

        output2[i] = output2[i]%Q;
    }

}
*/

/*
This function gets only the seed from the queried index of the array of seeds (for the s vector)
 */
 /*
pub fn fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(key:&[u8], iv:&[u8], 
        input1: &mut [u8], input2: &mut [u8], 
        len1:usize, len2:usize, seed_index:usize) {
    //let mut input = vec![0u8; 4*NUM_SERVERS*N_SQRT_DIM];

    type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;
    let mut cipher = Aes128Ctr64LE::new((&key[0..16]).into(), (&iv[0..16]).into());
    cipher.apply_keystream(&mut input1[0.. len1]);
    //cipher.apply_keystream(&mut input2[0.. len2]);

    let mut output1: &mut [i32] = bytemuck::cast_slice_mut(input1);
    

    let mut temp = [0u8; 4];
    let mut temp_value:u32 = 0;

    for i in 0..(len1/4) {
        while (output1[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0) 
            | ((temp[1] as u32) << 8) 
            | ((temp[2] as u32) << 16)
            | ((temp[3] as u32) << 24);
            temp_value = temp_value%Qu;
            output1[i] = temp_value as i32;
        }
        output1[i] = output1[i]%Q;
    }

    const SEED_LEN:usize = 32;
    let mut temp_seeds = vec![0u8; SEED_LEN*N_PARAM];
    cipher.apply_keystream(&mut temp_seeds);
    {
        let mut seed_cipher = Aes128Ctr64LE::new((&temp_seeds[32*seed_index..32*seed_index+16]).into(), (&temp_seeds[32*seed_index+16..32*seed_index+32]).into());
        seed_cipher.apply_keystream(&mut input2[0.. 4*512]);
    }
    let mut output2: &mut [i32] = bytemuck::cast_slice_mut(input2);

    cipher =  Aes128Ctr64LE::new((&temp_seeds[32*seed_index+16..32*seed_index+32]).into(), (&temp_seeds[32*seed_index..32*seed_index+16]).into());
    for i in 0..(len2/4) {

        while (output2[i] as u32) > MAX_RAND {
            //println!("{} HIT {} > {}", i,output[i], Q);
            cipher.apply_keystream(&mut temp);
            temp_value = ((temp[0] as u32) << 0) 
            | ((temp[1] as u32) << 8) 
            | ((temp[2] as u32) << 16)
            | ((temp[3] as u32) << 24);
            temp_value = temp_value%Qu;
            output2[i] = temp_value as i32;
        }

        output2[i] = output2[i]%Q;
    }

}
*/

fn main_block_sq_timings_new() {
    println!("----------------------------------------------------");
    println!("BLOCK SEED Block Timing");
    let mut A_vec = vec![0i32; NUM_BLOCK*N_PARAM];
    //let mut b_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM];
    //let mut s_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM*N_PARAM];
    let mut b_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM*N_PARAM];
    let mut v_vec_u8 = vec![0u8; 4*NUM_BLOCK*N_PARAM];

    let mut A_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut A_vec[..]);
    fill_rand_aes128_modq_nr(&mut A_vec_u8, 4*NUM_BLOCK*N_PARAM);


    let mut seeds = [0u8; 32*NUM_SERVERS];
    let buffer:i32 = 128;
    let mut ori_message:i32 = 101;
    let mut message:i32 = (ori_message <<9)+buffer;
    let index:usize = 512*512+13;//2000;

    /////////////////////////////////////////////////////////////////////////////////////////
    let iterations:usize = 1;
    let gen_iterations:usize = iterations;
    let eval_iterations:usize = iterations;
    let eval_seed_iterations:usize = iterations;
    let all_eval_iterations:usize = 0;
    let all_eval_seed_iterations:usize = 0;
/*
    let iterations:usize = 20;
    let gen_iterations:usize = iterations*3;
    let eval_iterations:usize = iterations*1000;
    let eval_seed_iterations:usize = iterations*10;
    let all_eval_iterations:usize = iterations;
    let all_eval_seed_iterations:usize = iterations;
*/
    println!("gen_iterations: {}", gen_iterations);
    println!("eval_iterations: {}", eval_iterations);
    println!("eval_seed_iterations: {}", eval_seed_iterations);
    println!("all_eval_iterations: {}", all_eval_iterations);
    println!("all_eval_seed_iterations: {}", all_eval_seed_iterations);

    {
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {

            dpf_gen_lwe_seed_block_new_sq(index, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }


 
    //////////////////////////////////////////////////////////////////////////////
    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe_block_new(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval Time elapsed is: {:?}", eval_duration);
    }

    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM*N_PARAM];

        let eval_start = Instant::now();
        for iter_test in 0..eval_seed_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe_seed_block(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval seed Time elapsed is: {:?}", eval_duration);
    }

    //////////////////////////////////////////////////////////////////////////////
/*
    {
        let mut all_messages = vec![0i32; NUM_BLOCK*N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_iterations {

            dpf_eval_lwe_all_base_block(&mut all_messages, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL Eval Time elapsed is: {:?}", all_eval_duration);
    }
    {
        let mut all_messages = vec![0i32; NUM_BLOCK*N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM*N_PARAM];

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_seed_iterations {

            dpf_eval_lwe_all_base_block_seed(&mut all_messages, &A_vec
                , &mut b_vecs_1d_u8_eval[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL (seed) Eval Time elapsed is: {:?}", all_eval_duration);
    }
 */
    //////////////////////////////////////////////////////////////////////////////

    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

        //println!("---------------------------");
        for eval_s_iter in 0..NUM_SERVERS {
            dpf_eval_lwe_block_new(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
        println!("//////////////////////////////////////////////");
    }


    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM*N_PARAM];

        for eval_s_iter in 0..(NUM_SERVERS-1) {
            dpf_eval_lwe_seed_block(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }
        //println!("---------------------------");
        for eval_s_iter in (NUM_SERVERS-1)..NUM_SERVERS {
            dpf_eval_lwe_block_new(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("seed loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
        println!("//////////////////////////////////////////////");
    }

    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();
    //////////////////////////////////////////////////////////////////////////////
    println!("----------------------------------------------------");
}


fn main_block_sq_timings_new_double_expand() {
    println!("----------------------------------------------------");
    println!("BLOCK SEED Block Timing");
    let mut A_vec = vec![0i32; NUM_BLOCK*N_PARAM];
    //let mut b_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM];
    //let mut s_vecs_1d_arr_u8 = [0u8; 4*NUM_SERVERS*N_SQRT_DIM*N_PARAM];
    let mut b_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*NUM_BLOCK*NUM_SERVERS*N_PARAM*N_PARAM];
    let mut v_vec_u8 = vec![0u8; 4*NUM_BLOCK*N_PARAM];

    let mut A_vec_u8: &mut [u8] = bytemuck::cast_slice_mut(&mut A_vec[..]);
    fill_rand_aes128_modq_nr(&mut A_vec_u8, 4*NUM_BLOCK*N_PARAM);


    let mut seeds = [0u8; 32*NUM_SERVERS];
    let buffer:i32 = 128;
    let mut ori_message:i32 = 101;
    let mut message:i32 = (ori_message <<9)+buffer;
    let index:usize = 2*512*512+13;//2000;

    /////////////////////////////////////////////////////////////////////////////////////////
    let iterations:usize = 1;
    let gen_iterations:usize = iterations;
    let eval_iterations:usize = iterations;
    let eval_seed_iterations:usize = iterations;
    let all_eval_iterations:usize = 0;
    let all_eval_seed_iterations:usize = 0;
/*
    let iterations:usize = 20;
    let gen_iterations:usize = iterations*3;
    let eval_iterations:usize = iterations*1000;
    let eval_seed_iterations:usize = iterations*10;
    let all_eval_iterations:usize = iterations;
    let all_eval_seed_iterations:usize = iterations;
*/
    println!("gen_iterations: {}", gen_iterations);
    println!("eval_iterations: {}", eval_iterations);
    println!("eval_seed_iterations: {}", eval_seed_iterations);
    println!("all_eval_iterations: {}", all_eval_iterations);
    println!("all_eval_seed_iterations: {}", all_eval_seed_iterations);

    {
        let gen_start = Instant::now();
        for iter_test in 0..gen_iterations {

            dpf_gen_lwe_seed_block_new_sq_double_expand(index, message, &A_vec[..], &mut b_vecs_1d_u8[..], 
                &mut s_vecs_1d_u8[..], &mut v_vec_u8[..], &mut seeds[..]);
        }
        //let gen_duration = gen_start.elapsed().as_micros();
        let gen_duration = gen_start.elapsed();
        println!("GEN Time elapsed is: {:?}", gen_duration);
    }


 
    //////////////////////////////////////////////////////////////////////////////
    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let eval_start = Instant::now();
        for iter_test in 0..eval_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe_block_new(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval Time elapsed is: {:?}", eval_duration);
    }

    {
        let mut recovered_message_t:i32 = 0;
        let eval_s_iter:usize = 0;

        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM*N_PARAM];

        let eval_start = Instant::now();
        for iter_test in 0..eval_seed_iterations {
        //for iter_test in 0..1 {
            let mut recovered_message_t:i32 = 0;
            let mut recovered_message_total:i32 = 0;

            dpf_eval_lwe_seed_block_double_expand(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            //recovered_message_total = recovered_message_total + recovered_message_t;

        }
        let eval_duration = eval_start.elapsed();
        println!("Eval seed Time elapsed is: {:?}", eval_duration);
    }

    //////////////////////////////////////////////////////////////////////////////

    {
        let mut all_messages = vec![0i32; NUM_BLOCK*N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_iterations {

            dpf_eval_lwe_all_base_block(&mut all_messages, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL Eval Time elapsed is: {:?}", all_eval_duration);
    }
    {
        let mut all_messages = vec![0i32; NUM_BLOCK*N_PARAM*N_PARAM];
        let eval_s_iter:usize = 0;
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM*N_PARAM];

        let all_eval_start = Instant::now();
        for iter_test in 0..all_eval_seed_iterations {

            dpf_eval_lwe_all_base_block_seed(&mut all_messages, &A_vec
                , &mut b_vecs_1d_u8_eval[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);

        }
        let all_eval_duration = all_eval_start.elapsed();
        println!("ALL (seed) Eval Time elapsed is: {:?}", all_eval_duration);
    }
 
    //////////////////////////////////////////////////////////////////////////////

    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;

        //println!("---------------------------");
        for eval_s_iter in 0..NUM_SERVERS {
            dpf_eval_lwe_block_new(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
        println!("//////////////////////////////////////////////");
    }


    {
        let mut recovered_message_t:i32 = 0;
        let mut recovered_message_total:i32 = 0;
        let mut b_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM];
        let mut s_vecs_1d_u8_eval = vec![0u8; 4*NUM_SERVERS*NUM_BLOCK*N_PARAM*N_PARAM];

        for eval_s_iter in 0..(NUM_SERVERS-1) {
            dpf_eval_lwe_seed_block_double_expand(index, &mut recovered_message_t, &A_vec
                , &mut b_vecs_1d_u8_eval[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &mut s_vecs_1d_u8_eval[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                , &seeds[32*(eval_s_iter)..32*(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }
        //println!("---------------------------");
        for eval_s_iter in (NUM_SERVERS-1)..NUM_SERVERS {
            dpf_eval_lwe_block_new(index, &mut recovered_message_t, &A_vec
                , &b_vecs_1d_u8[4*NUM_BLOCK*b_s(eval_s_iter)..4*NUM_BLOCK*b_s(eval_s_iter+1)]
                , &s_vecs_1d_u8[4*NUM_BLOCK*s_s(eval_s_iter)..4*NUM_BLOCK*s_s(eval_s_iter+1)]
                ,  &v_vec_u8);
            //println!("loop partials is {}", recovered_message_t);
            recovered_message_total = recovered_message_total + recovered_message_t;
        }

        println!("seed loop recovered is {}, noise is {} or {}",(recovered_message_total%Q) >>9, ntt::mod_32(recovered_message_total-message), -1*ntt::mod_32(message-recovered_message_total));
        println!("init is {}",(recovered_message_total%Q));
        println!("//////////////////////////////////////////////");
    }

    //ntt::ntt_base_test();
    //ntt::ntt_mul_test();
    //////////////////////////////////////////////////////////////////////////////
    println!("----------------------------------------------------");
}


fn main_gen_tests() {
    println!("----------------------------------------------------");
    println!("SEED Block Timing");
    let mut b_vecs_1d_u8 = vec![0u8; 4*N_PARAM];
    let mut s_vecs_1d_u8 = vec![0u8; 4*N_PARAM*N_PARAM];

    let mut s_vecs_1d_u8_single = vec![0u8; 4*N_PARAM];

    let mut seed = [0u8; 32];
    fill_rand_aes128_nr(&mut seed, 32);
    println!("first seed: {:?}", seed);
    let iterations:usize = 1;

    let gen_start = Instant::now();
    for iter_test in 0..iterations {

    fill_rand_aes128_modq_nr_2_by_seed(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8,
            4*B_SLICE, 4*S_SLICE);
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let gen_duration = gen_start.elapsed();
    println!("   GEN Time {}: elapsed is: {:?}", iterations, gen_duration);

    b_vecs_1d_u8.fill(0);
    s_vecs_1d_u8.fill(0);

    let gen_sq_start = Instant::now();
    for iter_test in 0..iterations {

    fill_rand_aes128_modq_nr_2_by_seed_sq(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8,
            4*B_SLICE, 4*S_SLICE);
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let gen_sq_duration = gen_sq_start.elapsed();
    println!("SQ GEN Time {}: elapsed is: {:?}", iterations, gen_sq_duration);

    let query_index:usize = 100;

    //println!("s_vecs_1d_u8        test values are {} {} {}", s_vecs_1d_u8[4*512*query_index+0], s_vecs_1d_u8[4*512*query_index+1], s_vecs_1d_u8[4*512*query_index+2]);
    //println!("b_vecs_1d_u8        test values are {} {} {}", b_vecs_1d_u8[0], b_vecs_1d_u8[1], b_vecs_1d_u8[2]);
    

    b_vecs_1d_u8.fill(0);
    //s_vecs_1d_u8.fill(0);
    s_vecs_1d_u8_single.fill(0);
    fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8_single,
            4*B_SLICE, 4*N_PARAM, query_index, N_PARAM);
    //fill_rand_aes128_modq_nr_2_by_seed(&seed[0..16], &seed[16..32], 
    //        &mut b_vecs_1d_u8, &mut s_vecs_1d_u8,
    //        4*B_SLICE, 4*S_SLICE);

    for big_iter in 0..512 {
        b_vecs_1d_u8.fill(0);
        s_vecs_1d_u8_single.fill(0);
        fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8_single,
            4*B_SLICE, 4*N_PARAM, big_iter, N_PARAM);
        for iter in 0..4*512 {
            if s_vecs_1d_u8[4*512*big_iter+iter] != s_vecs_1d_u8_single[iter] {
                println!("{} ERROR: at {} got {} instead of {}", big_iter, iter, s_vecs_1d_u8_single[iter], s_vecs_1d_u8[4*512*big_iter+iter]);
                break;
            }
        }
    }

    //println!("s_vecs_1d_u8_single test values are {} {} {}", s_vecs_1d_u8_single[0], s_vecs_1d_u8_single[1], s_vecs_1d_u8_single[2]);
    //println!("b_vecs_1d_u8        test values are {} {} {}", b_vecs_1d_u8[0], b_vecs_1d_u8[1], b_vecs_1d_u8[2])



}

/*
This function creates seeds for each ntt poly (512*NUM_BLOCK)
*/
fn main_gen_block_tests() {
    println!("----------------------------------------------------");
    println!("BLOCK SEED Block Timing");
    let mut b_vecs_1d_u8 = vec![0u8; 4*N_PARAM*NUM_BLOCK];
    let mut s_vecs_1d_u8 = vec![0u8; 4*N_PARAM*N_PARAM*NUM_BLOCK];

    let mut s_vecs_1d_u8_single = vec![0u8; 4*N_PARAM];

    let mut seed = [0u8; 32];
    fill_rand_aes128_nr(&mut seed, 32);
    let iterations:usize = 1;

    let gen_start = Instant::now();
    for iter_test in 0..iterations {

    fill_rand_aes128_modq_nr_2_by_seed(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8,
            4*B_SLICE*NUM_BLOCK, 4*S_SLICE*NUM_BLOCK);
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let gen_duration = gen_start.elapsed();
    println!("   GEN Time {}: elapsed is: {:?}", iterations, gen_duration);

    b_vecs_1d_u8.fill(0);
    s_vecs_1d_u8.fill(0);

    let gen_sq_start = Instant::now();
    for iter_test in 0..iterations {

    fill_rand_aes128_modq_nr_2_by_seed_sq(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8,
            4*B_SLICE*NUM_BLOCK, 4*S_SLICE*NUM_BLOCK);
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let gen_sq_duration = gen_sq_start.elapsed();
    println!("SQ GEN Time {}: elapsed is: {:?}", iterations, gen_sq_duration);

    let query_index:usize = 100;

    println!("s_vecs_1d_u8        test values are {} {} {}", s_vecs_1d_u8[4*N_PARAM*query_index+0], 
        s_vecs_1d_u8[4*N_PARAM*query_index+1], 
        s_vecs_1d_u8[4*N_PARAM*query_index+2]);
    println!("b_vecs_1d_u8        test values are {} {} {}", b_vecs_1d_u8[0], b_vecs_1d_u8[1], b_vecs_1d_u8[2]);
    

    b_vecs_1d_u8.fill(0);
    //s_vecs_1d_u8.fill(0);
    s_vecs_1d_u8_single.fill(0);

    fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8_single,
            4*B_SLICE*NUM_BLOCK, 4*N_PARAM, query_index, NUM_BLOCK*N_PARAM);

    for big_iter in 0..NUM_BLOCK*N_PARAM {
    //for big_iter in 0..50 {
        b_vecs_1d_u8.fill(0);
        s_vecs_1d_u8_single.fill(0);
        fill_rand_aes128_modq_nr_2_by_seed_sq_getsub(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8_single,
            4*B_SLICE*NUM_BLOCK, 4*N_PARAM, big_iter, NUM_BLOCK*N_PARAM);
        for iter in 0..4*512 {
            if s_vecs_1d_u8[4*N_PARAM*big_iter+iter] != s_vecs_1d_u8_single[iter] {
                println!("{} ERROR: at {} got {} instead of {}", big_iter, iter, s_vecs_1d_u8_single[iter], s_vecs_1d_u8[4*N_PARAM*big_iter+iter]);
                break; 
            }
        }
    }

    println!("s_vecs_1d_u8_single test values are {} {} {}", s_vecs_1d_u8_single[0], s_vecs_1d_u8_single[1], s_vecs_1d_u8_single[2]);
    println!("b_vecs_1d_u8        test values are {} {} {}", b_vecs_1d_u8[0], b_vecs_1d_u8[1], b_vecs_1d_u8[2])
}



/*
This function creates seeds for each block, then for each ntt poly (512)
*/
fn main_gen_block_tests_double_expand() {
    println!("----------------------------------------------------");
    println!("BLOCK SEED Block Timing");
    let mut b_vecs_1d_u8 = vec![0u8; 4*N_PARAM*NUM_BLOCK];
    let mut s_vecs_1d_u8 = vec![0u8; 4*N_PARAM*N_PARAM*NUM_BLOCK];

    let mut s_vecs_1d_u8_single = vec![0u8; 4*N_PARAM];

    let mut seed = [0u8; 32];
    fill_rand_aes128_nr(&mut seed, 32);
    let iterations:usize = 1;

    let gen_start = Instant::now();
    for iter_test in 0..iterations {

    fill_rand_aes128_modq_nr_2_by_seed(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8,
            4*B_SLICE*NUM_BLOCK, 4*S_SLICE*NUM_BLOCK);
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let gen_duration = gen_start.elapsed();
    println!("   GEN Time {}: elapsed is: {:?}", iterations, gen_duration);

    b_vecs_1d_u8.fill(0);
    s_vecs_1d_u8.fill(0);

    let gen_sq_start = Instant::now();
    for iter_test in 0..iterations {

    fill_rand_aes128_modq_nr_2_by_seed_sq_block(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8,
            4*B_SLICE*NUM_BLOCK, 4*S_SLICE*NUM_BLOCK);
    }
    //let gen_duration = gen_start.elapsed().as_micros();
    let gen_sq_duration = gen_sq_start.elapsed();
    println!("SQ GEN Time {}: elapsed is: {:?}", iterations, gen_sq_duration);


    let query_index:usize = 1000;

    println!("s_vecs_1d_u8        test values are {} {} {}", s_vecs_1d_u8[4*N_PARAM*query_index+0], 
        s_vecs_1d_u8[4*N_PARAM*query_index+1], 
        s_vecs_1d_u8[4*N_PARAM*query_index+2]);
    println!("b_vecs_1d_u8        test values are {} {} {}", b_vecs_1d_u8[0], b_vecs_1d_u8[1], b_vecs_1d_u8[2]);
    

    b_vecs_1d_u8.fill(0);
    //s_vecs_1d_u8.fill(0);
    s_vecs_1d_u8_single.fill(0);


    fill_rand_aes128_modq_nr_2_by_seed_sq_block_getsub(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8_single,
            4*B_SLICE*NUM_BLOCK, 4*N_PARAM, query_index);

    for big_iter in 0..NUM_BLOCK*N_PARAM {
    //for big_iter in 0..50 {
        b_vecs_1d_u8.fill(0);
        s_vecs_1d_u8_single.fill(0);
        fill_rand_aes128_modq_nr_2_by_seed_sq_block_getsub(&seed[0..16], &seed[16..32], 
            &mut b_vecs_1d_u8, &mut s_vecs_1d_u8_single,
            4*B_SLICE*NUM_BLOCK, 4*N_PARAM, big_iter);
        for iter in 0..4*512 {
            if s_vecs_1d_u8[4*N_PARAM*big_iter+iter] != s_vecs_1d_u8_single[iter] {
                println!("{} ERROR: at {} got {} instead of {}", big_iter, iter, s_vecs_1d_u8_single[iter], s_vecs_1d_u8[4*N_PARAM*big_iter+iter]);
                break; 
            }
        }
    }

    println!("s_vecs_1d_u8_single test values are {} {} {}", s_vecs_1d_u8_single[0], s_vecs_1d_u8_single[1], s_vecs_1d_u8_single[2]);
    println!("b_vecs_1d_u8        test values are {} {} {}", b_vecs_1d_u8[0], b_vecs_1d_u8[1], b_vecs_1d_u8[2])

}
