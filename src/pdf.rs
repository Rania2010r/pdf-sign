use anyhow::{Context, Result};

const PGP_SIG_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
const PGP_SIG_END: &[u8] = b"-----END PGP SIGNATURE-----";

pub(crate) fn find_eof_offset(data: &[u8]) -> Result<usize> {
    data.windows(5)
        .rposition(|w| w == b"%%EOF")
        .map(|pos| pos + 5)
        .context("PDF does not contain %%EOF marker")
}

fn find_subslice(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|pos| start + pos)
}

/// Extract all ASCII-armored PGP signature blocks from `data` (in order).
pub(crate) fn extract_armored_signatures(data: &[u8]) -> Vec<Vec<u8>> {
    let mut sigs = Vec::new();
    let mut i = 0;
    while let Some(begin) = find_subslice(data, PGP_SIG_BEGIN, i) {
        let Some(end) = find_subslice(data, PGP_SIG_END, begin) else {
            break;
        };
        let mut end_pos = end + PGP_SIG_END.len();
        // Include at most one trailing newline after the END marker if present.
        if end_pos < data.len() && data[end_pos] == b'\n' {
            end_pos += 1;
        }
        sigs.push(data[begin..end_pos].to_vec());
        i = end_pos;
    }
    sigs
}


