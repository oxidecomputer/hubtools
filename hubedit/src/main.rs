// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{bail, Result};
use clap::Parser;
use hubtools::RawHubrisImage;

#[derive(Parser, Debug, Clone)]
#[clap(name = "hubedit", max_term_width = 80)]
pub struct Args {
    /// Hubris archive
    #[clap(long, short, env = "HUMILITY_ARCHIVE")]
    pub archive: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut archive = RawHubrisImage::load(&args.archive)?;
    println!("loaded archive!");

    let caboose = archive.read_caboose()?;
    println!("{caboose:?}");

    //archive.write_caboose(&[1, 2, 3, 4, 5])?;
    let caboose = archive.read_caboose()?;
    println!("{caboose:?}");

    archive.overwrite()?;
    Ok(())
}
