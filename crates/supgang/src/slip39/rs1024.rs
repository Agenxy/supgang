//! SLIP-39 RS1024 checksum over 10-bit word indices.

pub(super) const CHECKSUM_WORDS: usize = 3;

const GENERATORS: [u32; 10] = [
    0x00E0_E040,
    0x01C1_C080,
    0x0383_8100,
    0x0707_0200,
    0x0E0E_0009,
    0x1C0C_2412,
    0x3808_6C24,
    0x3090_FC48,
    0x21B1_F890,
    0x03F3_F120,
];

fn polymod(customization: &[u8], values: &[u16], trailing_zeros: usize) -> u32 {
    let mut chk = 1_u32;
    let step = |chk: &mut u32, value: u32| {
        let top = *chk >> 20;
        *chk = ((*chk & 0x000F_FFFF) << 10) ^ value;
        for (bit, &generator) in GENERATORS.iter().enumerate() {
            if ((top >> bit) & 1) != 0 {
                *chk ^= generator;
            }
        }
    };
    for &byte in customization {
        step(&mut chk, u32::from(byte));
    }
    for &word in values {
        step(&mut chk, u32::from(word));
    }
    for _ in 0..trailing_zeros {
        step(&mut chk, 0);
    }
    chk
}

pub(super) fn create_checksum(data: &[u16], customization: &[u8]) -> [u16; CHECKSUM_WORDS] {
    let residue = polymod(customization, data, CHECKSUM_WORDS) ^ 1;
    [
        u16::try_from((residue >> 20) & 0x3FF).unwrap_or(0),
        u16::try_from((residue >> 10) & 0x3FF).unwrap_or(0),
        u16::try_from(residue & 0x3FF).unwrap_or(0),
    ]
}

pub(super) fn verify_checksum(data: &[u16], customization: &[u8]) -> bool {
    polymod(customization, data, 0) == 1
}
