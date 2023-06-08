// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
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
    VerifyImage {
        #[clap(short, long)]
        verbose: bool,
    },
    /// Replaces the binary image within an archive with a different binary
    /// image, supplied on the command line as a raw (BIN) file.
    ///
    /// This is intended to be used to replace a default-signed image from the
    /// build system with an actually-signed image from permission-slip.
    ///
    /// If misused, this can produce an archive that can't be debugged, so don't
    /// do that.
    ReplaceImage {
        /// Path to BIN file to insert.
        image: PathBuf,
    },
    /// Extracts the binary image within an archive as a raw (BIN) file.
    ///
    /// This is primarily intended for producing the raw file permission-slip
    /// wants to see, but can also be used to e.g. feed programs to bootloaders
    /// that won't accept ELF or SREC or whatever.
    ///
    /// Because of its intended use with permission-slip, this can also strip
    /// signatures from images.
    ExtractImage {
        /// Strip existing signature from image before generating.
        #[clap(long, short)]
        unsign: bool,

        /// Path where output should be deposited.
        output: PathBuf,
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
        Command::VerifyImage { verbose } => {
            archive.verify(verbose)?;
        }
        Command::ReplaceImage { image } => {
            let contents = std::fs::read(&image).with_context(|| {
                format!("reading image file {}", image.display())
            })?;
            archive.replace(contents);
            archive.overwrite()?;
        }
        Command::ExtractImage { unsign, output } => {
            if unsign {
                archive.unsign()?;
            }
            std::fs::write(output, archive.image.to_binary()?)?;
        }
    }

    Ok(())
}
