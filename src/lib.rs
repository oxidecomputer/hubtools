use anyhow::{bail, Context, Result};

use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    process::Command,
};

/// A chunk of memory
#[derive(Debug, Hash)]
pub struct LoadSegment {
    pub source_file: PathBuf,
    pub data: Vec<u8>,
}

fn objcopy_translate_format(
    in_format: &str,
    src: &Path,
    out_format: &str,
    dest: &Path,
) -> Result<()> {
    let mut cmd = Command::new("arm-none-eabi-objcopy");
    cmd.arg("-I")
        .arg(in_format)
        .arg("-O")
        .arg(out_format)
        .arg("--gap-fill")
        .arg("0xFF")
        .arg(src)
        .arg(dest);

    let status = cmd
        .status()
        .context(format!("failed to objcopy ({:?})", cmd))?;

    if !status.success() {
        bail!("objcopy failed, see output for details");
    }
    Ok(())
}

/// Convert SREC to other formats for convenience.
pub fn translate_srec_to_other_formats(
    dist_dir: &Path,
    name: &str,
) -> Result<()> {
    let src = dist_dir.join(format!("{}.srec", name));
    for (out_type, ext) in [
        ("elf32-littlearm", "elf"),
        ("ihex", "ihex"),
        ("binary", "bin"),
    ] {
        objcopy_translate_format(
            "srec",
            &src,
            out_type,
            &dist_dir.join(format!("{}.{}", name, ext)),
        )?;
    }
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////

/// Minimal Hubris archive, useful for some basic manipulation
#[derive(Debug)]
pub struct HubrisArchive {
    contents: Vec<u8>,
}

impl HubrisArchive {
    pub fn load(filename: &Path) -> Result<Self> {
        let contents = std::fs::read(filename).with_context(|| {
            format!("could not read archive file {filename:?}")
        })?;
        let cursor = Cursor::new(&contents);
        let archive = zip::ZipArchive::new(cursor)?;
        let comment = std::str::from_utf8(archive.comment())
            .context("Failed to decode comment string")?;

        match comment.strip_prefix("hubris build archive v") {
            Some(v) => {
                let _v: u32 = v.parse().with_context(|| {
                    format!("Failed to parse version string {v}")
                })?;
            }
            None => {
                bail!("could not parse hubris archive version from '{comment}'")
            }
        }

        Ok(Self { contents })
    }

    /// Extracts a file from the archive
    fn extract(&self, filename: &str) -> Result<Vec<u8>> {
        let cursor = Cursor::new(self.contents.as_slice());
        let mut archive = zip::ZipArchive::new(cursor)?;
        let mut file = archive
            .by_name(filename)
            .with_context(|| format!("failed to find '{filename:?}'"))?;
        let mut buffer = vec![];
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    /// Reads `final.srec` from the archive
    ///
    /// Returns a tuple of `(memory, kentry)`
    pub fn read_final_srec(&self) -> Result<(BTreeMap<u32, LoadSegment>, u32)> {
        const SREC_FILE: &str = "bin/final.srec";
        let srec = self.extract(SREC_FILE)?;
        let srec_str = std::str::from_utf8(&srec)?;
        load_srec(Path::new(SREC_FILE), srec_str)
    }
}

/// Loads an SREC file into the same representation we use for ELF.
///
/// Returns a tuple of `(memory, kernel entry)`
pub fn load_srec(
    input: &Path,
    srec_text: &str,
) -> Result<(BTreeMap<u32, LoadSegment>, u32)> {
    let mut output = BTreeMap::new();
    for record in srec::reader::read_records(srec_text) {
        let record = record?;
        match record {
            srec::Record::S3(data) => {
                // Check for address overlap
                let range =
                    data.address.0..data.address.0 + data.data.len() as u32;
                if let Some(overlap) = output.range(range.clone()).next() {
                    bail!(
                        "{}: record address range {:x?} overlaps {:x}",
                        input.display(),
                        range,
                        overlap.0
                    )
                }
                output.insert(
                    data.address.0,
                    LoadSegment {
                        source_file: input.into(),
                        data: data.data,
                    },
                );
            }
            srec::Record::S7(srec::Address32(e)) => return Ok((output, e)),
            _ => (),
        }
    }
    panic!("SREC file missing terminating S7 record");
}

/// Converts a binary file (on the filesystem) into an SREC file
pub fn binary_to_srec(
    binary: &Path,
    name: &str,
    bin_addr: u32,
    entry: u32,
    out: &Path,
) -> Result<()> {
    let mut srec_out = vec![srec::Record::S0(name.to_string())];

    let binary = std::fs::read(binary)?;

    let mut addr = bin_addr;
    for chunk in binary.chunks(255 - 5) {
        srec_out.push(srec::Record::S3(srec::Data {
            address: srec::Address32(addr),
            data: chunk.to_vec(),
        }));
        addr += chunk.len() as u32;
    }

    let out_sec_count = srec_out.len() - 1; // header
    if out_sec_count < 0x1_00_00 {
        srec_out.push(srec::Record::S5(srec::Count16(out_sec_count as u16)));
    } else if out_sec_count < 0x1_00_00_00 {
        srec_out.push(srec::Record::S6(srec::Count24(out_sec_count as u32)));
    } else {
        panic!("SREC limit of 2^24 output sections exceeded");
    }

    srec_out.push(srec::Record::S7(srec::Address32(entry)));

    let srec_image = srec::writer::generate_srec_file(&srec_out);
    std::fs::write(out, srec_image)?;
    Ok(())
}

/// Writes a SREC file to the filesystem
pub fn write_srec(
    sections: &BTreeMap<u32, LoadSegment>,
    kentry: u32,
    out: &Path,
) -> Result<()> {
    let mut srec_out = vec![srec::Record::S0("hubris".to_string())];
    for (&base, sec) in sections {
        // SREC record size limit is 255 (0xFF). 32-bit addressed records
        // additionally contain a four-byte address and one-byte checksum, for a
        // payload limit of 255 - 5.
        let mut addr = base;
        for chunk in sec.data.chunks(255 - 5) {
            srec_out.push(srec::Record::S3(srec::Data {
                address: srec::Address32(addr),
                data: chunk.to_vec(),
            }));
            addr += chunk.len() as u32;
        }
    }
    let out_sec_count = srec_out.len() - 1; // header
    if out_sec_count < 0x1_00_00 {
        srec_out.push(srec::Record::S5(srec::Count16(out_sec_count as u16)));
    } else if out_sec_count < 0x1_00_00_00 {
        srec_out.push(srec::Record::S6(srec::Count24(out_sec_count as u32)));
    } else {
        panic!("SREC limit of 2^24 output sections exceeded");
    }

    srec_out.push(srec::Record::S7(srec::Address32(kentry)));

    let srec_image = srec::writer::generate_srec_file(&srec_out);
    std::fs::write(out, srec_image)?;
    Ok(())
}
