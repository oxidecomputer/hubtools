use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hubtools::RawHubrisArchive;
use sha3::{Digest, Sha3_256};
use std::{
    str,
    ops::Range,
};

pub const LPC55_FLASH_PAGE_SIZE: usize = 512;

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

#[derive(Debug)]
enum Chip {
    Lpc55,
    Stm32,
}

impl TryFrom<&RawHubrisArchive> for Chip {
    type Error = anyhow::Error;

    fn try_from(archive: &RawHubrisArchive) -> Result<Self> {
        let manifest = archive.extract_file("app.toml")?;
        let manifest: toml::Value = toml::from_str(
            str::from_utf8(&manifest).context("manifest bytes to UTF8")?,
        ).context("manifest UTF8 to TOML")?;

        let chip = manifest
           .as_table()
           .ok_or(anyhow!("manifest isn't a table"))?
           .get("chip")
           .ok_or(anyhow!("no key \"chip\" in manifest"))?
           .as_str()
           .ok_or(anyhow!("value for key \"chip\" isn't a string"))?;

        if chip.contains("lpc55") {
            Ok(Chip::Lpc55)
        } else if chip.contains("stm32") {
            Ok(Chip::Stm32)
        } else {
            Err(anyhow!("Unsupported chip: {}", chip))
        }
    }
}

// Return a Range describing the named flash range from memory.toml).
fn get_flash_range(name: &str, archive: &RawHubrisArchive) -> Result<Range<u32>> {
    let memory = archive.extract_file("memory.toml")
        .context("extract memory.toml from archive")?;
    let memory: toml::Value = toml::from_str(
        str::from_utf8(&memory).context("memory.toml bytes to UTF8")?,
    ).context("memory.toml UTF8 to TOML")?;

    // this may be easier w/ a derive macro for TOML -> Rust types / instances
    for value in memory
        .as_table()
        .ok_or(anyhow!("no table in memory.toml"))?
        .get("flash")
        .ok_or(anyhow!("no value with key \"flash\" memory.toml table"))?
        .as_array()
        .ok_or(anyhow!("value from key \"flash\" in memory.toml is not an array"))?
    {
        let name_toml = value
            .get("name")
            .ok_or(anyhow!("no key \"name\" found in memory.toml \"flash\""))?
            .as_str()
            .ok_or(anyhow!("value for key \"name\" isn't a string"))?;

        if name == name_toml {
            let start: u32 = value
                .get("address")
                .ok_or(anyhow!("no key \"address\" found in flash table \"a\""))?
                .as_integer()
                .ok_or(anyhow!("value for key \"address\" isn't an integer"))?
                .try_into()
                .context("convert address from memory table to u32")?;
            let size: u32 = value
                .get("size")
                .ok_or(anyhow!("no key \"size\" found in table \"a\""))?
                .as_integer()
                .ok_or(anyhow!("value for key \"size\" isn't an integer"))?
                .try_into()
                .context("convert size from memory table to u32")?;
            let end = start + size;

            return Ok(Range { start, end });
        }
    }

    Err(anyhow!("No flash range for image \"{}\"", name))
}

fn main() -> Result<()> {
    let args = Args::parse();

    let archive = RawHubrisArchive::load(&args.archive)
        .context("Load RawHubrisArchive")?;

    let image = archive.image.to_binary()
        .context("Archive image to binary")?;

    let chip = Chip::try_from(&archive)?;

    // When calculating the FWID value we aim to capture *all* data from the
    // relevant flash region. The hubris image will reside in one contiguous
    // range identical to the image from the archive however all flash pages
    // within the remaining flash region must be represented in the FWID as
    // well. We do this to ensure flash pages not used by the hubris image
    // are in the expected state. Doing this here requires that we accomodate
    // some chip-specific quirks here:
    let pad = match chip {
        Chip::Lpc55 => {
            // On the Lpc55s flash pages that haven't had any data written to
            // them cannot be read. Unused regions of a flash page will
            // return 0xff when read. Claculating the FWID then requires that
            // we pad the final page in the hubris image with `0xff`.
            //
            // NOTE: We do *not* need any info about the flash region where
            // this image will be written on the Lpc55s. The behavior of the
            // flash on this chip means all pages from the end of the hubris
            // image to the end of flash will be unwritten and thus
            // unreadable.
            LPC55_FLASH_PAGE_SIZE - image.len() % LPC55_FLASH_PAGE_SIZE
        },
        Chip::Stm32 => {
            // On the stm32s flash pages that haven't had any data written to
            // them will return 0xff. This includes flash pages that have
            // been partially written. Calculating the FWID then requires
            // that we pad the hubris image w/ `0xff` out to the end of its
            // flash region. This requires we pull additional data from the
            // hubris archive to get the dimensions of the flash range where
            // the image will reside.
            //
            // NOTE: The hubris image that we run on stm32s is the SP and
            // it is only ever written to a single flash range. We still
            // look up the image name and get the flash range from the image
            // manifest in an attempt to be flexible in the event this
            // assumption becomes invalid.
            let name = archive.image_name()?;
            let flash = get_flash_range(&name, &archive)?;

            flash.end as usize - flash.start as usize - image.len()
        }
    };

    let mut digest = Sha3_256::new();
    digest.update(&image);
    digest.update(vec![0xff; pad]);

    let digest = digest.finalize();

    println!("{}", hex::encode(digest));

    Ok(())
}
