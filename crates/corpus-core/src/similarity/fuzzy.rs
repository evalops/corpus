//! ssdeep-compatible fuzzy hashing, ported from the pure-Python ppdeep
//! reference (itself a SpamSum port). Digests match ppdeep exactly, which
//! is what the known-vector tests assert. ~200 lines, no C bindings.
//!
//! Byte fuzzy hashes are candidate generators only — never sufficient
//! family evidence alone (spec 16.2).

const BLOCKSIZE_MIN: u32 = 3;
const SPAMSUM_LENGTH: usize = 64;
const ROLL_WINDOW: u32 = 7;
const HASH_INIT: u32 = 0x27;
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[rustfmt::skip]
const F_TABLE: [u32; 64] = [
    0x00, 0x13, 0x26, 0x39, 0x0c, 0x1f, 0x32, 0x05,
    0x18, 0x2b, 0x3e, 0x11, 0x24, 0x37, 0x0a, 0x1d,
    0x30, 0x03, 0x16, 0x29, 0x3c, 0x0f, 0x22, 0x35,
    0x08, 0x1b, 0x2e, 0x01, 0x14, 0x27, 0x3a, 0x0d,
    0x20, 0x33, 0x06, 0x19, 0x2c, 0x3f, 0x12, 0x25,
    0x38, 0x0b, 0x1e, 0x31, 0x04, 0x17, 0x2a, 0x3d,
    0x10, 0x23, 0x36, 0x09, 0x1c, 0x2f, 0x02, 0x15,
    0x28, 0x3b, 0x0e, 0x21, 0x34, 0x07, 0x1a, 0x2d,
];

#[inline]
fn byte_hash(h: u32, b: u8) -> u32 {
    F_TABLE[h as usize & 0x3f] ^ (b as u32 & 0x3f)
}

struct Roll {
    window: [u32; ROLL_WINDOW as usize],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl Roll {
    fn new() -> Roll {
        Roll {
            window: [0; ROLL_WINDOW as usize],
            h1: 0,
            h2: 0,
            h3: 0,
            n: 0,
        }
    }
    fn update(&mut self, b: u8) -> u32 {
        let b = b as u32;
        self.h2 = self.h2.wrapping_sub(self.h1).wrapping_add(ROLL_WINDOW * b);
        self.h1 = self.h1.wrapping_add(b).wrapping_sub(self.window[self.n]);
        self.window[self.n] = b;
        self.n = (self.n + 1) % ROLL_WINDOW as usize;
        self.h3 = (self.h3 << 5) ^ b;
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

/// Compute the ssdeep-compatible fuzzy digest: "blocksize:hash1:hash2".
pub fn fuzzy_hash(data: &[u8]) -> String {
    let mut block_size = BLOCKSIZE_MIN;
    while (block_size as usize * SPAMSUM_LENGTH) < data.len() {
        block_size *= 2;
    }
    loop {
        let (hs1, hs2, tail1, tail2, rh) = hash_with_block(data, block_size);
        if block_size > BLOCKSIZE_MIN && hs1.len() < SPAMSUM_LENGTH / 2 {
            block_size /= 2;
            continue;
        }
        let (hs1, hs2) = if rh != 0 {
            (
                format!("{hs1}{}", B64[tail1 as usize] as char),
                format!("{hs2}{}", B64[tail2 as usize] as char),
            )
        } else {
            (hs1, hs2)
        };
        return format!("{block_size}:{hs1}:{hs2}");
    }
}

/// Returns (hash_string1, hash_string2, last_char1, last_char2, last rolling hash).
fn hash_with_block(data: &[u8], block_size: u32) -> (String, String, u32, u32, u32) {
    let mut roll = Roll::new();
    let mut bh1 = HASH_INIT;
    let mut bh2 = HASH_INIT;
    let mut hs1 = String::new();
    let mut hs2 = String::new();
    let mut last1 = 0u32;
    let mut last2 = 0u32;
    let mut rh = 0u32;
    for &b in data {
        bh1 = byte_hash(bh1, b);
        bh2 = byte_hash(bh2, b);
        rh = roll.update(b);
        if rh % block_size == block_size - 1 {
            last1 = bh1 & 0x3f;
            if hs1.len() < SPAMSUM_LENGTH - 1 {
                hs1.push(B64[(bh1 & 0x3f) as usize] as char);
                bh1 = HASH_INIT;
                last1 = HASH_INIT & 0x3f;
            }
            if rh % (block_size * 2) == (block_size * 2) - 1 {
                last2 = bh2 & 0x3f;
                if hs2.len() < SPAMSUM_LENGTH / 2 - 1 {
                    hs2.push(B64[(bh2 & 0x3f) as usize] as char);
                    bh2 = HASH_INIT;
                    last2 = HASH_INIT & 0x3f;
                }
            }
        }
    }
    let (tail1, tail2) = if rh != 0 {
        (bh1 & 0x3f, bh2 & 0x3f)
    } else {
        (last1, last2)
    };
    (hs1, hs2, tail1, tail2, rh)
}

fn strip_sequences(s: &str) -> String {
    let b = s.as_bytes();
    let mut r: Vec<u8> = b.iter().take(3).copied().collect();
    for i in 3..b.len() {
        if b[i] != b[i - 1] || b[i] != b[i - 2] || b[i] != b[i - 3] {
            r.push(b[i]);
        }
    }
    String::from_utf8(r).unwrap_or_default()
}

fn levenshtein(s: &[u8], t: &[u8]) -> usize {
    if s == t {
        return 0;
    }
    if s.is_empty() {
        return t.len();
    }
    if t.is_empty() {
        return s.len();
    }
    let mut v0: Vec<usize> = (0..=t.len()).collect();
    let mut v1: Vec<usize> = vec![0; t.len() + 1];
    for (i, &sc) in s.iter().enumerate() {
        v1[0] = i + 1;
        for (j, &tc) in t.iter().enumerate() {
            let cost = if sc == tc { 0 } else { 1 };
            v1[j + 1] = (v1[j] + 1).min(v0[j + 1] + 1).min(v0[j] + cost);
        }
        std::mem::swap(&mut v0, &mut v1);
    }
    v0[t.len()]
}

fn common_substring(s1: &[u8], s2: &[u8]) -> bool {
    for i in 0..s1.len() {
        for j in 0..s2.len() {
            let mut cur = 0;
            while i + cur < s1.len() && j + cur < s2.len() && s1[i + cur] == s2[j + cur] {
                cur += 1;
            }
            if cur >= ROLL_WINDOW as usize {
                return true;
            }
        }
    }
    false
}

fn score_strings(s1: &str, s2: &str, block_size: u32) -> i32 {
    if !common_substring(s1.as_bytes(), s2.as_bytes()) {
        return 0;
    }
    let dist = levenshtein(s1.as_bytes(), s2.as_bytes());
    let mut score = (dist * SPAMSUM_LENGTH) / (s1.len() + s2.len());
    score = (100 * score) / SPAMSUM_LENGTH;
    let mut score = 100 - score as i32;
    let cap = (block_size / BLOCKSIZE_MIN) as i32 * s1.len().min(s2.len()) as i32;
    if score > cap {
        score = cap;
    }
    score
}

/// Compare two fuzzy digests; score 0-100. Returns 0 for malformed input.
pub fn compare(hash1: &str, hash2: &str) -> i32 {
    let parse = |h: &str| -> Option<(u32, String, String)> {
        let mut parts = h.splitn(3, ':');
        let bs: u32 = parts.next()?.parse().ok()?;
        Some((bs, parts.next()?.to_string(), parts.next()?.to_string()))
    };
    let (bs1, s1a, s1b) = match parse(hash1) {
        Some(v) => v,
        None => return 0,
    };
    let (bs2, s2a, s2b) = match parse(hash2) {
        Some(v) => v,
        None => return 0,
    };
    if bs1 != bs2 && bs1 != bs2 * 2 && bs2 != bs1 * 2 {
        return 0;
    }
    let s1a = strip_sequences(&s1a);
    let s1b = strip_sequences(&s1b);
    let s2a = strip_sequences(&s2a);
    let s2b = strip_sequences(&s2b);
    if bs1 == bs2 && s1a == s2a {
        return 100;
    }
    if bs1 == bs2 {
        score_strings(&s1a, &s2a, bs1).max(score_strings(&s1b, &s2b, bs2 * 2))
    } else if bs1 == bs2 * 2 {
        score_strings(&s1a, &s2b, bs1)
    } else {
        score_strings(&s1b, &s2a, bs2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known vectors generated with ppdeep (pure-Python ssdeep port).
    #[test]
    fn ppdeep_known_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "3::"),
            (b"a", "3:E:E"),
            (b"hello world", "3:iKFSMPn:rJPn"),
            (b"hello world!", "3:iKFSMPE:rJPE"),
        ];
        for (input, expected) in cases {
            assert_eq!(&fuzzy_hash(input), expected);
        }
        let fox = b"The quick brown fox jumps over the lazy dog".repeat(10);
        assert_eq!(
            fuzzy_hash(&fox),
            "3:FJKKIUKacmuJKKIUKacmuJKKIUKacmuJKKIUKacmuJKKIUKacmuJKKIUKacmuJKA:FHIGYIGYIGYIGYIGYIGYIGYIGYIGYIGi"
        );
        let range: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        assert_eq!(
            fuzzy_hash(&range),
            "24:X+OmvmLeO22LSeKufL6uS+iv+7ym2/eL+u2/m7muTL2fvmT+OmvmLeO22LSeKufj:XDfLTTLTDfLTTf7fTL377fTL3TDfLTTn"
        );
    }

    #[test]
    fn compare_scores_match_ppdeep() {
        let mut a = b"A".repeat(4096);
        a.extend_from_slice(&b"COMMONMARKER".repeat(100));
        a.extend_from_slice(&b"B".repeat(4096));
        let mut b = b"C".repeat(4096);
        b.extend_from_slice(&b"COMMONMARKER".repeat(100));
        b.extend_from_slice(&b"D".repeat(4096));
        let c: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let (ha, hb, hc) = (fuzzy_hash(&a), fuzzy_hash(&b), fuzzy_hash(&c));
        assert_eq!(compare(&ha, &ha), 100);
        assert_eq!(compare(&ha, &hb), 97, "ppdeep scored A/B as 97");
        assert_eq!(compare(&ha, &hc), 0, "unrelated content must score 0");
        assert_eq!(compare("garbage", &ha), 0);
    }
}
