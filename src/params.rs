pub const NUM_SERVERS: usize = 3;
pub const N_PARAM: usize = 1024;

pub const ROWS: usize = 2;
pub const N_ROWS: usize = N_PARAM*ROWS;
pub const BLOCKS: usize = 4;
pub const N_BLOCKS: usize = N_PARAM*BLOCKS;
pub const N_PARAM_LOG2: usize = 10;
pub const DB_SIZE: usize = N_PARAM * N_PARAM * ROWS*BLOCKS;

pub const B_SLICE: usize = N_ROWS;
pub const B_SLICE_BYTES: usize = E_BYTES * N_ROWS;
pub const S_SLICE: usize = N_PARAM * N_ROWS;
pub const S_SLICE_BYTES: usize = E_BYTES * N_PARAM * N_ROWS;
pub const A_SLICE: usize = N_PARAM;
pub const A_SLICE_BYTES: usize = E_BYTES * N_PARAM;
pub const V_SLICE: usize = N_BLOCKS;
pub const V_SLICE_BYTES: usize = E_BYTES * N_BLOCKS;

pub const M_SLICE: usize = N_PARAM * N_ROWS;
pub const M_SLICE_BYTES: usize = E_BYTES * N_PARAM * N_ROWS;

pub const NUM_BLOCK: usize = 32; //65536;
//pub const B_BLOCK_SLICE: usize = NUM_SERVERS * B_SLICE;
//pub const S_BLOCK_SLICE: usize = NUM_SERVERS * S_SLICE;
pub const V_BLOCK_SLICE: usize = N_BLOCKS;

//pub const B_BLOCK_SLICE_B: usize = E_BYTES * B_BLOCK_SLICE;

//pub const S_BLOCK_SLICE_B: usize = E_BYTES * S_BLOCK_SLICE;
//pub const V_BLOCK_SLICE_B: usize = E_BYTES * V_BLOCK_SLICE;

pub const SEED_IV_LEN: usize = 32;
pub const SEED_BLOCK: usize = SEED_IV_LEN * (NUM_SERVERS - 1);

pub const Q: i32 = 537133057;
pub const Q_64: i64 = Q as i64;
pub const QU: u32 = 537133057;

// Size of elements in modulo Q
pub const E_BYTES: usize = 4;
pub const E_BITS: usize = 8*E_BYTES;

// DW_MODQ: 119749i64 is (2^32)^2 mod q
pub const DW_MODQ: i64 = 34594884;

pub const POW2I32: [i32; 16] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
];

// includes the sign bit
pub const NOISE_BITS: usize = 7;
pub const NOISE_MAX: usize = usize::pow(2, NOISE_BITS as u32) - 1;
pub const NOISE_LEN: usize = BLOCKS*B_SLICE;

pub const BIT_SNIP_RAND_VAL: usize = 8 * NUM_SERVERS;

// largest multiple of Q under u32
// this is Q*7-1
pub const MAX_RAND: u32 = 3759931398;

pub const BT_INST1: usize = 3 * B_SLICE + 2;
pub const BT_INST2_A: usize = B_SLICE;
pub const BT_INST2_B: usize = NOISE_LEN * NOISE_BITS;

#[derive(Clone)]
pub struct SnipI {
    pub f_zero_i: i32,
    pub g_zero_i: i32,
    pub h0_i: i32,
    pub h1_i: i32,
    pub h2_i: i32,
    pub a_i: i32,
    pub b_i: i32,
    pub c_i: i32,
}

pub fn mul_modq(a: i32, b: i32) -> i32 {
    return (((a as i64) * (b as i64)) % (Q as i64)) as i32;
}


pub fn modq(a: i32) -> i32 {
    return ((a % Q) + Q) % Q;
}

pub fn modq_64(a: i64) -> i64 {
    return ((a % Q_64) + Q_64) % Q_64;
}

#[allow(dead_code)]
pub fn get_min_max(input: &[i32]) -> (i32, i32) {
    let mut min: i32 = 0;
    let mut max: i32 = 0;

    for iter in 0..input.len() {
        if input[iter] < min {
            min = input[iter];
        }
        if input[iter] > max {
            max = input[iter];
        }
    }

    return (min, max);
}

#[allow(dead_code)]
pub fn get_min_max_u32(input: &[u32]) -> (u32, u32) {
    let mut min: u32 = 0;
    let mut max: u32 = 0;

    for iter in 0..input.len() {
        if input[iter] < min {
            min = input[iter];
        }
        if input[iter] > max {
            max = input[iter];
        }
    }

    return (min, max);
}
