//! One-fault canonical CBOR refusals for each signed authority record.

use std::path::Path;

use super::{TestResult, save};

pub(super) fn write(output: &Path, records: &mut Vec<serde_json::Value>, record: &str, canonical: &[u8]) -> TestResult {
    let header = *canonical.first().ok_or_else(|| std::io::Error::other("empty record"))?;
    if !(0x80..=0x96).contains(&header) || canonical.get(1) != Some(&1) {
        return Err(std::io::Error::other("unexpected CBOR vector layout").into());
    }
    let mut nonminimal = vec![header, 0x18, 0x01];
    nonminimal.extend_from_slice(
        canonical
            .get(2..)
            .ok_or_else(|| std::io::Error::other("short record"))?,
    );
    save(
        output,
        records,
        &format!("refuse-{record}-nonminimal-integer.cbor"),
        &nonminimal,
        "reject: equivalent version integer uses non-shortest encoding",
    )?;

    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(
        canonical
            .get(1..)
            .ok_or_else(|| std::io::Error::other("short record"))?,
    );
    indefinite.push(0xff);
    save(
        output,
        records,
        &format!("refuse-{record}-indefinite.cbor"),
        &indefinite,
        "reject: indefinite outer array",
    )?;

    let mut tagged = vec![0xc0];
    tagged.extend_from_slice(canonical);
    save(
        output,
        records,
        &format!("refuse-{record}-tag.cbor"),
        &tagged,
        "reject: tagged outer record",
    )?;

    let mut trailing = canonical.to_vec();
    trailing.push(0);
    save(
        output,
        records,
        &format!("refuse-{record}-trailing.cbor"),
        &trailing,
        "reject: trailing CBOR item",
    )?;

    let mut extra = canonical.to_vec();
    *extra.first_mut().ok_or_else(|| std::io::Error::other("empty record"))? = header + 1;
    extra.push(0xf6);
    save(
        output,
        records,
        &format!("refuse-{record}-extra-field.cbor"),
        &extra,
        "reject: additional outer field",
    )?;
    Ok(())
}
