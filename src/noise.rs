use crate::params::{N_PARAM, NOISE_MAX};
use rand::RngCore;
use std::num::Wrapping;

// Std Dev 11
const LWE_CDF_TABLE_LENGTH: usize = 90;
const LWE_CDF_TABLE: [u64; LWE_CDF_TABLE_LENGTH] = [
    334508461215786537,
    1000766554895104179,
    1658816234439706806,
    2303409339123867888,
    2929624270133587229,
    3532977956781802568,
    4109520437539034179,
    4655908803617495559,
    5169458366788766021,
    5648170102130344803,
    6090734601196271237,
    6496513876517608957,
    6865503319050305638,
    7198276875326295063,
    7495919047219790798,
    7759947609779231362,
    7992230995226716380,
    8194904124142984497,
    8370286111449028905,
    8520802777770107908,
    8648916303799251693,
    8757063724770131585,
    8847605319457495470,
    8922783342517400198,
    8984691011534348018,
    9035251212611109250,
    9076204042962910945,
    9109102069118737091,
    9135312040709729639,
    9156021752178881144,
    9172250773684368762,
    9184863861302800139,
    9194585988055385764,
    9202018094730703631,
    9207652828220094957,
    9211889702858457771,
    9215049277634802445,
    9217386082517417826,
    9219100146598197146,
    9220347077667541919,
    9221246717400050246,
    9221890450141467327,
    9222347278818999734,
    9222668801717835633,
    9222893231892745779,
    9223048599821640144,
    9223155272277678495,
    9223227908625871155,
    9223276961730386510,
    9223309815846278546,
    9223331639319013740,
    9223346016333996982,
    9223355409767812224,
    9223361496592922226,
    9223365408315590319,
    9223367901509626473,
    9223369477504829954,
    9223370465522001967,
    9223371079828180895,
    9223371458633495842,
    9223371690297219930,
    9223371830808371332,
    9223371915331261921,
    9223371965756583773,
    9223371995592117144,
    9223372013099842404,
    9223372023288956582,
    9223372029169993753,
    9223372032536521585,
    9223372034447788243,
    9223372035523934123,
    9223372036124875075,
    9223372036457690344,
    9223372036640494252,
    9223372036740075714,
    9223372036793875718,
    9223372036822702549,
    9223372036838021263,
    9223372036846094700,
    9223372036850314632,
    9223372036852502208,
    9223372036853626895,
    9223372036854200366,
    9223372036854490368,
    9223372036854635814,
    9223372036854708160,
    9223372036854743849,
    9223372036854761310,
    9223372036854769783,
    9223372036854773860
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
