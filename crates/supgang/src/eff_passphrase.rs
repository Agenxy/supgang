//! Seven unbiased EFF large-wordlist draws for an offline escrow passphrase.

use zeroize::Zeroizing;

const WORDLIST: &str = include_str!("eff_large_wordlist.txt");
const WORD_COUNT: usize = 7_776;
const WORDS_PER_PASSPHRASE: usize = 7;
const REJECTION_CEILING: u16 = 62_208; // floor(65536 / 7776) * 7776
const MAX_DRAWS_PER_WORD: usize = 64;

fn index_from_draw(draw: u16) -> Option<usize> {
    (draw < REJECTION_CEILING).then_some(usize::from(draw) % WORD_COUNT)
}

/// Draw seven independent EFF words with bounded rejection sampling.
pub fn generate() -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut phrase = Zeroizing::new(Vec::with_capacity(WORDS_PER_PASSPHRASE * 10));
    for position in 0..WORDS_PER_PASSPHRASE {
        let mut selected = None;
        for _ in 0..MAX_DRAWS_PER_WORD {
            let mut random = Zeroizing::new([0_u8; 2]);
            getrandom::fill(random.as_mut()).map_err(|_| "could not obtain operating-system randomness")?;
            if let Some(index) = index_from_draw(u16::from_be_bytes(*random)) {
                selected = Some(index);
                break;
            }
        }
        let index = selected.ok_or("could not draw an unbiased EFF word")?;
        let line = WORDLIST
            .lines()
            .nth(index)
            .ok_or("embedded EFF wordlist is incomplete")?;
        let (_, word) = line.split_once('\t').ok_or("embedded EFF wordlist is malformed")?;
        if position != 0 {
            phrase.push(b' ');
        }
        phrase.extend_from_slice(word.as_bytes());
    }
    Ok(phrase)
}

#[cfg(test)]
mod tests {
    use super::{REJECTION_CEILING, WORD_COUNT, WORDLIST, generate, index_from_draw};

    #[test]
    fn wordlist_and_rejection_boundary_are_exact() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(WORDLIST.lines().count(), WORD_COUNT);
        assert_eq!(index_from_draw(0), Some(0));
        assert_eq!(index_from_draw(REJECTION_CEILING - 1), Some(WORD_COUNT - 1));
        assert_eq!(index_from_draw(REJECTION_CEILING), None);
        assert_eq!(index_from_draw(u16::MAX), None);
        let phrase = generate()?;
        assert_eq!(phrase.split(|byte| *byte == b' ').count(), 7);
        Ok(())
    }
}
