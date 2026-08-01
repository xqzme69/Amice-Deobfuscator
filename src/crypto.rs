use amice_vm::ProfilePackage;

pub const DESCRIPTOR_FIELD_COUNT: usize = 8;

const DESC_GUARD: usize = 7;
const FN_TOKEN_MUL: u64 = 0x9e37_79b9_7f4a_7c15;
const FN_TOKEN_MUL_INV: u64 = 0xf1de_83e1_9937_733d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorFields {
    pub code_offset: u64,
    pub code_len: u64,
    pub const_pool_offset: u64,
    pub const_pool_len: u64,
    pub bytecode_key: u64,
    pub native_base: u64,
    pub native_count: u64,
    pub guard: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescriptorFieldKey {
    mask: u64,
    add: u64,
    rot: u32,
}

pub fn splitmix64(value: u64) -> u64 {
    let mut z = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

pub fn safe_symbol_suffix(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub fn descriptor_table_seed(profile: &ProfilePackage, safe_names: &[String]) -> u64 {
    let mut state = splitmix64(0x8f2f_0e37_6c91_f0d5 ^ profile.manifest.version as u64);
    state = stable_mix_bytes(state, profile.manifest.name.as_bytes());
    state = stable_mix_bytes(state, format!("{:?}", profile.runtime.scope).as_bytes());
    state = stable_mix_bytes(state, format!("{:?}", profile.runtime.entry).as_bytes());
    state = stable_mix_bytes(state, format!("{:?}", profile.runtime.dispatch).as_bytes());
    state = stable_mix_bytes(state, format!("{:?}", profile.bytecode.scope).as_bytes());
    for name in safe_names {
        state = stable_mix_bytes(state, name.as_bytes());
    }
    splitmix64(state ^ safe_names.len() as u64)
}

fn stable_mix_bytes(mut state: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        state ^= u64::from(*byte);
        state = splitmix64(state);
    }
    state
}

pub fn obfuscated_fn_token(seed: u64, fn_index: usize) -> u64 {
    let mixed = (fn_index as u64)
        .wrapping_mul(FN_TOKEN_MUL)
        .wrapping_add(token_add(seed))
        ^ token_xor(seed);
    mixed.rotate_left(token_rot(seed))
}

pub fn obfuscated_fn_token_parts(seed: u64, fn_index: usize) -> [u64; 2] {
    let token = obfuscated_fn_token(seed, fn_index);
    let split_a = splitmix64(seed ^ ((fn_index as u64) << 1) ^ 0x2b99_2ddf_a232_49d6);
    let split_b = token.rotate_right(13).wrapping_sub(split_a);
    [split_a, split_b]
}

pub fn decode_fn_token(seed: u64, token: u64) -> u64 {
    let unrotated = token.rotate_right(token_rot(seed));
    let unxor = unrotated ^ token_xor(seed);
    let unsub = unxor.wrapping_sub(token_add(seed));
    unsub.wrapping_mul(FN_TOKEN_MUL_INV)
}

pub fn descriptor_guard(seed: u64, fn_index: usize) -> u64 {
    splitmix64(seed ^ (fn_index as u64).wrapping_mul(0xd1b5_4a32_d192_ed03) ^ 0xa826_9d7b_5a21_1f4d)
}

pub fn decrypt_descriptor_words(
    seed: u64,
    fn_index: usize,
    row: &[u64],
) -> Option<DescriptorFields> {
    if row.len() != DESCRIPTOR_FIELD_COUNT {
        return None;
    }

    let plain = (0..DESCRIPTOR_FIELD_COUNT)
        .map(|field_index| decrypt_descriptor_field(seed, fn_index, field_index, row[field_index]))
        .collect::<Vec<_>>();
    if plain[DESC_GUARD] != descriptor_guard(seed, fn_index) {
        return None;
    }

    Some(DescriptorFields {
        code_offset: plain[0],
        code_len: plain[1],
        const_pool_offset: plain[2],
        const_pool_len: plain[3],
        bytecode_key: plain[4],
        native_base: plain[5],
        native_count: plain[6],
        guard: plain[7],
    })
}

pub fn encrypt_descriptor_field(seed: u64, fn_index: usize, field_index: usize, plain: u64) -> u64 {
    let key = descriptor_field_key(seed, fn_index, field_index);
    (plain.rotate_left(key.rot) ^ key.mask).wrapping_add(key.add)
}

pub fn decrypt_descriptor_field(
    seed: u64,
    fn_index: usize,
    field_index: usize,
    encrypted: u64,
) -> u64 {
    let key = descriptor_field_key(seed, fn_index, field_index);
    (encrypted.wrapping_sub(key.add) ^ key.mask).rotate_right(key.rot)
}

fn descriptor_field_key(seed: u64, fn_index: usize, field_index: usize) -> DescriptorFieldKey {
    let index_component = (fn_index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
    let with_seed = index_component ^ seed;
    let base = with_seed ^ (field_index as u64).wrapping_mul(0xa5a3_56e5_2c1b_4f27);
    let mask = splitmix64(base ^ 0x7069_9d5f_3d13_a7c9);
    let add = splitmix64(base ^ 0x9bf1_2f8d_a3e7_4c55);
    let raw_rot = splitmix64(base ^ 0xc2b2_ae35_87b1_1d09) & 63;
    let rot = if raw_rot == 0 { 1 } else { raw_rot as u32 };
    DescriptorFieldKey { mask, add, rot }
}

fn token_add(seed: u64) -> u64 {
    splitmix64(seed ^ 0x4f1b_6d86_32c7_49e1)
}

fn token_xor(seed: u64) -> u64 {
    splitmix64(seed ^ 0xb204_9f63_a8ce_9d35)
}

fn token_rot(seed: u64) -> u32 {
    ((splitmix64(seed ^ 0x63d2_97f8_9b44_0c11) & 63).max(1)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_symbol_suffix_matches_amice_source() {
        assert_eq!(safe_symbol_suffix("main"), "main");
        assert_eq!(safe_symbol_suffix("foo-bar$baz"), "foo_bar_baz");
        assert_eq!(
            safe_symbol_suffix("_ZN4core..fmt17h00E"),
            "_ZN4core..fmt17h00E"
        );
    }

    #[test]
    fn descriptor_field_roundtrip_keeps_guard() {
        let seed = 0x356b_517d_6b1d_db25;
        let mut row = [0_u64; DESCRIPTOR_FIELD_COUNT];
        for (field_index, plain) in [
            0_u64,
            16,
            16,
            8,
            0xfeed_beef,
            3,
            2,
            descriptor_guard(seed, 0),
        ]
        .into_iter()
        .enumerate()
        {
            row[field_index] = encrypt_descriptor_field(seed, 0, field_index, plain);
        }

        let fields = decrypt_descriptor_words(seed, 0, &row).expect("guard should match");
        assert_eq!(fields.code_offset, 0);
        assert_eq!(fields.code_len, 16);
        assert_eq!(fields.bytecode_key, 0xfeed_beef);
    }

    #[test]
    fn fn_token_roundtrip_matches_inverse() {
        let seed = 0x356b_517d_6b1d_db25;
        for fn_index in 0..8 {
            let token = obfuscated_fn_token(seed, fn_index);
            assert_eq!(decode_fn_token(seed, token), fn_index as u64);
        }
    }

    #[test]
    fn fn_token_parts_match_amice_wrapper_ir() {
        assert_eq!(
            obfuscated_fn_token_parts(0xfbf4_30d5_3137_ed45, 0),
            [0x8985_1687_bacf_2cf8, 0x1a32_e9ec_0c9d_566f]
        );
    }
}
