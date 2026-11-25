//! Embedded, SHA-256-pinned 1024-word SLIP-39 wordlist.

use std::sync::OnceLock;

use super::Slip39Error;

const RAW_WORDLIST: &str = include_str!("../slip39_wordlist.txt");
pub(super) const WORD_COUNT: usize = 1_024;
const MAX_WORD_LEN: usize = 16;

static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();

fn words() -> Result<&'static [&'static str], Slip39Error> {
    let table = WORDS.get_or_init(|| RAW_WORDLIST.lines().collect());
    if table.len() != WORD_COUNT {
        return Err(Slip39Error::CorruptWordlist);
    }
    Ok(table.as_slice())
}

pub(super) fn word_at(index: u16) -> Result<&'static str, Slip39Error> {
    words()?
        .get(usize::from(index))
        .copied()
        .ok_or(Slip39Error::InvalidWordIndex)
}

pub(super) fn index_of(candidate: &str) -> Result<u16, Slip39Error> {
    if candidate.is_empty() || candidate.len() > MAX_WORD_LEN || !candidate.is_ascii() {
        return Err(Slip39Error::InvalidWord);
    }
    let mut lower = [0_u8; MAX_WORD_LEN];
    for (slot, byte) in lower.iter_mut().zip(candidate.bytes()) {
        *slot = byte.to_ascii_lowercase();
    }
    let normalized = std::str::from_utf8(lower.get(..candidate.len()).ok_or(Slip39Error::InvalidWord)?)
        .map_err(|_| Slip39Error::InvalidWord)?;
    let position = words()?
        .binary_search(&normalized)
        .map_err(|_| Slip39Error::InvalidWord)?;
    u16::try_from(position).map_err(|_| Slip39Error::InvalidWord)
}
