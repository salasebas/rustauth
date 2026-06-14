//! Constant-time byte comparison helpers.

/// Compare two byte-like values without early returns based on content.
pub fn constant_time_equal<A, B>(a: A, b: B) -> bool
where
    A: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let a = a.as_ref();
    let b = b.as_ref();
    let mut diff = a.len() ^ b.len();
    let length = a.len().max(b.len());

    for index in 0..length {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }

    diff == 0
}
