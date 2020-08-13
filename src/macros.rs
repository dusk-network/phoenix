#[macro_export]
macro_rules! chunk_of {
    ($n:expr; $b:expr) => {{
        let mut buf = [0u8; $n];
        let len = std::cmp::min($b.len(), $n);
        (&mut buf[..len]).copy_from_slice(&$b[..len]);
        buf
    }};
}
