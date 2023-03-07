// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use hubtools::RawHubrisArchive;

#[derive(Parser, Debug)]
#[clap(name = "hubedit", max_term_width = 80)]
pub struct Args {
    /// Hubris archive
    #[clap(long, short, env = "HUBEDIT_ARCHIVE")]
    archive: String,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    ReadCaboose,
    WriteCaboose {
        #[clap(short, long)]
        version: String,

        #[clap(short, long)]
        force: bool,

        /// Do not write default caboose parameters
        #[clap(short, long)]
        no_defaults: bool,
    },
    EraseCaboose {
        #[clap(short, long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut archive = RawHubrisArchive::load(&args.archive)?;

    match args.cmd {
        Command::ReadCaboose => {
            let caboose = archive.read_caboose()?;
            let reader = tlvc::TlvcReader::begin(caboose.as_slice())
                .map_err(|e| anyhow!("tlvc error: {e:?}"))?;
            let mut t = tlvc_text::dump(reader);

            // Strip raw bytes from the end, for pretty-printing
            if let Some(tlvc_text::Piece::Bytes(bs)) = t.last() {
                if bs.iter().all(|c| *c == 0xFF) {
                    t.pop();
                }
            }

            if t.is_empty() {
                bail!("caboose is empty");
            }

            let mut text = vec![];
            tlvc_text::save(&mut text, &t).unwrap();
            println!("{}", std::str::from_utf8(&text).unwrap());
        }
        Command::WriteCaboose {
            version,
            force,
            no_defaults,
        } => {
            if !archive.is_caboose_empty()? && !force {
                bail!("archive already has a caboose");
            }
            if no_defaults {
                archive.write_version_to_caboose(&version)?;
            } else {
                archive.write_default_caboose(Some(&version))?;
            }
            archive.overwrite()?;
        }
        Command::EraseCaboose { force } => {
            if archive.is_caboose_empty()? && !force {
                bail!("archive does not have a caboose");
            }
            archive.erase_caboose()?;
            archive.overwrite()?;
        }
    }

    Ok(())
}
