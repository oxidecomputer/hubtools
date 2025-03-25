// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use hubtools::{FwidGen, RawHubrisArchive};
use sha2::Sha256;
use sha3::Sha3_256;
use std::{fmt, str};

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
    /// Hash algorithm used to generate FWID
    #[clap(default_value_t, env = "HUBEDIT_DIGEST", long, value_enum)]
    digest: Digest,

    /// Hubris archive
    #[clap(env = "HUBEDIT_ARCHIVE")]
    archive: String,
}

// We provide names explicitly for each variant to map each to the IANA named
// information hash algorithm registry hash name strings.
#[derive(Clone, Debug, Default, ValueEnum)]
enum Digest {
    #[clap(name = "sha-256")]
    Sha256,
    #[clap(name = "sha3-256")]
    #[default]
    Sha3_256,
}

// Display string names for digest algorithms from IANA named information
// hash algorithm registry
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Sha256 => write!(f, "sha-256"),
            Self::Sha3_256 => write!(f, "sha3-256"),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let archive = RawHubrisArchive::load(&args.archive)
        .context("Load RawHubrisArchive")?;

    let fwid = match args.digest {
        Digest::Sha256 => FwidGen::<Sha256>::fwid(&archive)?,
        Digest::Sha3_256 => FwidGen::<Sha3_256>::fwid(&archive)?,
    };

    // Display FWID as the string name for the digest from IANA registry and
    // the output from the selected digest encoded as hex & separated by a
    // `;`.
    println!("{};{}", args.digest, hex::encode(fwid));

    Ok(())
}
