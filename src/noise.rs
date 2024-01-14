use crate::params::{N_PARAM, NOISE_MAX};
use rand::RngCore;
use std::num::Wrapping;

// Std Dev 3
const LWE_CDF_TABLE_LENGTH: usize = 28;
const LWE_CDF_TABLE: [u64; LWE_CDF_TABLE_LENGTH] = [
    1226531024457883741,
3547028297445585071,
5511286831688180654,
6999144174533085348,
8007628132219100786,
8619304572384007220,
8951290419571008070,
9112526578651292993,
9182599524534147094,
9209850582343645935,
9219333924321925828,
9222287067587446825,
9223109978228784028,
9223315172814827801,
9223360957915673339,
9223370099627139237,
9223371732964522204,
9223371994102088255,
9223372031462173573,
9223372036245074933,
9223372036792998584,
9223372036849167201,
9223372036854319635,
9223372036854742573,
9223372036854773639,
9223372036854775681,
9223372036854775801,
9223372036854775807,
];

#[allow(arithmetic_overflow)]
pub fn lwe_add_sample_noise_8_1() -> i32 {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;

    let mut temp_vec = vec![0u8; RNDLEN];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    let data_rand: u64 = (temp_vec[0] as u64)
        | ((temp_vec[1] as u64) << 8)
        | ((temp_vec[2] as u64) << 16)
        | ((temp_vec[3] as u64) << 24)
        | ((temp_vec[4] as u64) << 32)
        | ((temp_vec[5] as u64) << 40)
        | ((temp_vec[6] as u64) << 48)
        | (((temp_vec[7] & 127) as u64) << 56);
    let sign: u8 = temp_vec[RNDLEN - 1] >> 7;

    let mut sample: u8 = 0;
    let mut temp: u64;
    for i in 0..LWE_CDF_TABLE_LENGTH {
        temp = (LWE_CDF_TABLE[i] as u64) - data_rand;
        sample += (temp >> 63) as u8;
    }

    let final_sample: u32 = ((0u32 - (sign as u32)) ^ (sample as u32)) + (sign as u32);
    //println!("sample is {}, final is {}", sample, final_sample);

    return final_sample as i32;
}

#[allow(arithmetic_overflow)]
pub fn lwe_add_pos_sample_noise_8_1() -> i32 {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;

    let mut temp_vec = vec![0u8; RNDLEN];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    let data_rand: u64 = (temp_vec[0] as u64)
        | ((temp_vec[1] as u64) << 8)
        | ((temp_vec[2] as u64) << 16)
        | ((temp_vec[3] as u64) << 24)
        | ((temp_vec[4] as u64) << 32)
        | ((temp_vec[5] as u64) << 40)
        | ((temp_vec[6] as u64) << 48)
        | (((temp_vec[7] & 127) as u64) << 56);

    let mut sample: u8 = 0;
    let mut temp: u64;
    for i in 0..LWE_CDF_TABLE_LENGTH {
        temp = (LWE_CDF_TABLE[i] as u64) - data_rand;
        sample += (temp >> 63) as u8;
    }

    return sample as i32;
}

#[allow(arithmetic_overflow)]
pub fn lwe_add_sample_noise_8_1_decompose() -> (i32, i32) {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;

    let mut temp_vec = vec![0u8; RNDLEN];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    let data_rand: u64 = (temp_vec[0] as u64)
        | ((temp_vec[1] as u64) << 8)
        | ((temp_vec[2] as u64) << 16)
        | ((temp_vec[3] as u64) << 24)
        | ((temp_vec[4] as u64) << 32)
        | ((temp_vec[5] as u64) << 40)
        | ((temp_vec[6] as u64) << 48)
        | (((temp_vec[0] & 127) as u64) << 56);
    let sign: u8 = temp_vec[RNDLEN - 1] >> 7;

    let mut sample: u8 = 0;
    let mut temp: u64;
    for i in 0..LWE_CDF_TABLE_LENGTH {
        temp = (Wrapping(LWE_CDF_TABLE[i] as u64) - Wrapping(data_rand)).0;
        sample += (temp >> 63) as u8;
    }

    //let final_sample:u32 = ((0u32 - (sign as u32)) ^ (sample as u32)) + (sign as u32);
    //println!("sample is {}, final is {}", sample, final_sample);

    return ((sign as i32), (sample as i32));
}

pub fn add_noise(input: &mut [i32]) {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;
    const INSTANCES: usize = N_PARAM;
    const RNDSOURCE_LEN: usize = RNDLEN * INSTANCES;

    let mut temp_vec = vec![0u8; RNDSOURCE_LEN];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    for iter in 0..INSTANCES {
        let data_rand: u64 = (temp_vec[iter * RNDLEN] as u64)
            | ((temp_vec[iter * RNDLEN + 1] as u64) << 8)
            | ((temp_vec[iter * RNDLEN + 2] as u64) << 16)
            | ((temp_vec[iter * RNDLEN + 3] as u64) << 24)
            | ((temp_vec[iter * RNDLEN + 4] as u64) << 32)
            | ((temp_vec[iter * RNDLEN + 5] as u64) << 40)
            | ((temp_vec[iter * RNDLEN + 6] as u64) << 48)
            | (((temp_vec[iter * RNDLEN + 7] & 127) as u64) << 56);
        let sign: u8 = temp_vec[iter * RNDLEN + 7] >> 7;

        let mut sample: u8 = 0;
        let mut temp: u64;
        for i in 0..LWE_CDF_TABLE_LENGTH {
            temp = (Wrapping(LWE_CDF_TABLE[i] as u64) - Wrapping(data_rand)).0;
            sample += (temp >> 63) as u8;
        }

        let mut wrapped_sample: Wrapping<u64> = Wrapping(0u64) - Wrapping(sign as u64);
        wrapped_sample = (wrapped_sample ^ Wrapping(sample as u64)) + Wrapping(sign as u64);
        input[iter] += wrapped_sample.0 as i32;
    }
}

pub fn add_pos_noise(input: &mut [i32]) {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;
    const INSTANCES: usize = N_PARAM;
    const RNDSOURCE_LEN: usize = RNDLEN * INSTANCES;

    let mut temp_vec = vec![0u8; RNDSOURCE_LEN];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    for iter in 0..INSTANCES {
        let data_rand: u64 = (temp_vec[iter * RNDLEN] as u64)
            | ((temp_vec[iter * RNDLEN + 1] as u64) << 8)
            | ((temp_vec[iter * RNDLEN + 2] as u64) << 16)
            | ((temp_vec[iter * RNDLEN + 3] as u64) << 24)
            | ((temp_vec[iter * RNDLEN + 4] as u64) << 32)
            | ((temp_vec[iter * RNDLEN + 5] as u64) << 40)
            | ((temp_vec[iter * RNDLEN + 6] as u64) << 48)
            | (((temp_vec[iter * RNDLEN + 7] & 127) as u64) << 56);

        let mut sample: u8 = 0;
        let mut temp: u64;
        for i in 0..LWE_CDF_TABLE_LENGTH {
            temp = (Wrapping(LWE_CDF_TABLE[i] as u64) - Wrapping(data_rand)).0;
            sample += (temp >> 63) as u8;
        }
        input[iter] += sample as i32;
        /*
               let mut wrapped_sample: Wrapping<u32> = (Wrapping(0u32) - Wrapping(sign as u32));
               wrapped_sample = (wrapped_sample ^ Wrapping(sample as u32)) + Wrapping(sign as u32);

               input[iter] += wrapped_sample.0 as i32;

        */
    }
}

pub fn add_pos_noise_len(input: &mut [i32], length: usize) {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;
    let instances: usize = length;
    let rndsource_len: usize = RNDLEN * instances;

    let mut temp_vec = vec![0u8; rndsource_len];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    for iter in 0..instances {
        let data_rand: u64 = (temp_vec[iter * RNDLEN] as u64)
            | ((temp_vec[iter * RNDLEN + 1] as u64) << 8)
            | ((temp_vec[iter * RNDLEN + 2] as u64) << 16)
            | ((temp_vec[iter * RNDLEN + 3] as u64) << 24)
            | ((temp_vec[iter * RNDLEN + 4] as u64) << 32)
            | ((temp_vec[iter * RNDLEN + 5] as u64) << 40)
            | ((temp_vec[iter * RNDLEN + 6] as u64) << 48)
            | (((temp_vec[iter * RNDLEN + 7] & 127) as u64) << 56);

        let mut sample: u8 = 0;
        let mut temp: u64;
        for i in 0..LWE_CDF_TABLE_LENGTH {
            temp = (Wrapping(LWE_CDF_TABLE[i] as u64) - Wrapping(data_rand)).0;
            sample += (temp >> 63) as u8;
        }
        input[iter] += sample as i32;
        /*
               let mut wrapped_sample: Wrapping<u32> = (Wrapping(0u32) - Wrapping(sign as u32));
               wrapped_sample = (wrapped_sample ^ Wrapping(sample as u32)) + Wrapping(sign as u32);

               input[iter] += wrapped_sample.0 as i32;

        */
    }
}

pub fn add_noise_output(input: &mut [i32], output: &mut [i32]) {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;
    const INSTANCES: usize = N_PARAM;
    const RNDSOURCE_LEN: usize = RNDLEN * INSTANCES;

    let mut temp_vec = vec![0u8; RNDSOURCE_LEN];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    for iter in 0..INSTANCES {
        let data_rand: u64 = (temp_vec[iter * RNDLEN] as u64)
            | ((temp_vec[iter * RNDLEN + 1] as u64) << 8)
            | ((temp_vec[iter * RNDLEN + 2] as u64) << 16)
            | ((temp_vec[iter * RNDLEN + 3] as u64) << 24)
            | ((temp_vec[iter * RNDLEN + 4] as u64) << 32)
            | ((temp_vec[iter * RNDLEN + 5] as u64) << 40)
            | ((temp_vec[iter * RNDLEN + 6] as u64) << 48)
            | (((temp_vec[iter * RNDLEN + 7] & 127) as u64) << 56);
        let sign: u8 = temp_vec[iter * RNDLEN + 7] >> 7;

        let mut sample: u8 = 0;
        let mut temp: u64;
        for i in 0..LWE_CDF_TABLE_LENGTH {
            temp = (LWE_CDF_TABLE[i] as u64) - data_rand;
            sample += (temp >> 63) as u8;
        }

        let final_sample: i32 = (((0u32 - (sign as u32)) ^ (sample as u32)) + (sign as u32)) as i32;
        output[iter] = final_sample;
        input[iter] += final_sample;
    }
}

pub fn add_noise_output_sign(input: &mut [i32], output: &mut [i32], sign_out: &mut [i8]) {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;
    const INSTANCES: usize = N_PARAM;
    const RNDSOURCE_LEN: usize = RNDLEN * INSTANCES;

    let mut temp_vec = vec![0u8; RNDSOURCE_LEN];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    for iter in 0..512 {
        let data_rand: u64 = (temp_vec[iter * RNDLEN] as u64)
            | ((temp_vec[iter * RNDLEN + 1] as u64) << 8)
            | ((temp_vec[iter * RNDLEN + 2] as u64) << 16)
            | ((temp_vec[iter * RNDLEN + 3] as u64) << 24)
            | ((temp_vec[iter * RNDLEN + 4] as u64) << 32)
            | ((temp_vec[iter * RNDLEN + 5] as u64) << 40)
            | ((temp_vec[iter * RNDLEN + 6] as u64) << 48)
            | (((temp_vec[iter * RNDLEN + 7] & 127) as u64) << 56);
        let sign: u8 = temp_vec[iter * RNDLEN + 7] >> 7;

        let mut sample: u8 = 0;
        let mut temp: u64;
        for i in 0..LWE_CDF_TABLE_LENGTH {
            temp = (LWE_CDF_TABLE[i] as u64) - data_rand;
            sample += (temp >> 63) as u8;
        }

        let final_sample: i32 = (((0u32 - (sign as u32)) ^ (sample as u32)) + (sign as u32)) as i32;

        output[iter] = sample as i32;
        let sign_i8 = sign as i8;
        sign_out[iter] = -1i8 * sign_i8 + 1i8 * (1 - sign_i8);

        input[iter] += final_sample;
    }
}

pub fn add_pos_noise_output(input: &mut [i32], output: &mut [i32]) {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;
    const INSTANCES: usize = N_PARAM;
    const RNDSOURCE_LEN: usize = RNDLEN * INSTANCES;

    let mut temp_vec = vec![0u8; RNDSOURCE_LEN];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    for iter in 0..INSTANCES {
        let data_rand: u64 = (temp_vec[iter * RNDLEN] as u64)
            | ((temp_vec[iter * RNDLEN + 1] as u64) << 8)
            | ((temp_vec[iter * RNDLEN + 2] as u64) << 16)
            | ((temp_vec[iter * RNDLEN + 3] as u64) << 24)
            | ((temp_vec[iter * RNDLEN + 4] as u64) << 32)
            | ((temp_vec[iter * RNDLEN + 5] as u64) << 40)
            | ((temp_vec[iter * RNDLEN + 6] as u64) << 48)
            | (((temp_vec[iter * RNDLEN + 7] & 127) as u64) << 56);

        let mut sample: u8 = 0;
        let mut temp: u64;
        for i in 0..LWE_CDF_TABLE_LENGTH {
            if i > NOISE_MAX {
                break;
            }
            temp = (LWE_CDF_TABLE[i] as u64) - data_rand;
            sample += (temp >> 63) as u8;
        }
        /*
               let final_sample: i32 = (((0u32 - (sign as u32)) ^ (sample as u32)) + (sign as u32)) as i32;
               output[iter] = final_sample;
               input[iter] += final_sample;

        */
        output[iter] = sample as i32;
        input[iter] += sample as i32;
    }
}

pub fn get_noise_output(output: &mut [i32], instances: usize) {
    // 64 rand bits per noise element
    const RNDLEN: usize = 8;
    //const INSTANCES:usize = N_PARAM;
    let rndsource_len: usize = RNDLEN * instances;

    let mut temp_vec = vec![0u8; rndsource_len];
    rand::thread_rng().fill_bytes(&mut temp_vec);

    for iter in 0..instances {
        let data_rand: u64 = (temp_vec[iter * RNDLEN] as u64)
            | ((temp_vec[iter * RNDLEN + 1] as u64) << 8)
            | ((temp_vec[iter * RNDLEN + 2] as u64) << 16)
            | ((temp_vec[iter * RNDLEN + 3] as u64) << 24)
            | ((temp_vec[iter * RNDLEN + 4] as u64) << 32)
            | ((temp_vec[iter * RNDLEN + 5] as u64) << 40)
            | ((temp_vec[iter * RNDLEN + 6] as u64) << 48)
            | (((temp_vec[iter * RNDLEN + 7] & 127) as u64) << 56);
        let sign: u8 = temp_vec[iter * RNDLEN + 7] >> 7;

        let mut sample: u8 = 0;
        let mut temp: u64;
        for i in 0..LWE_CDF_TABLE_LENGTH {
            temp = (LWE_CDF_TABLE[i] as u64) - data_rand;
            sample += (temp >> 63) as u8;
        }

        let final_sample: i32 = (((0u32 - (sign as u32)) ^ (sample as u32)) + (sign as u32)) as i32;
        output[iter] = final_sample;
    }
}
