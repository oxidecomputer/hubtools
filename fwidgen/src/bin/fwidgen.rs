use anyhow::{Context, Result};
use hubtools::RawHubrisArchive;
use clap::Parser;

/// This tool calculates what we call the FWID for supported hubris images and
/// prints them as a hex string. This value is just a digest that's calculated
/// by the hubris measured boot implementation and stored in the `DiceTcbInfo`
/// x509 extension of our attestation leaf cert.
///
/// This tool exists to:
/// 1) allow appraisers to evaluate the FWID values produced by an attestation
/// from an RoT and associate them with a particular hubris archive
/// 2) to assist in the construction of a measurement corpus from a collection
/// of hubris archives
#[derive(Parser, Debug)]
struct Args {
    /// Hubris archive
    #[clap(env = "HUBEDIT_ARCHIVE")]
    archive: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let archive = RawHubrisArchive::load(&args.archive)
        .context("Load RawHubrisArchive")?;

    let digest = fwidgen::get_fwid(&archive)?;

    println!("{}", hex::encode(digest));

    Ok(())
}
