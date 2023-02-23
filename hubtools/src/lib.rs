// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, bail, Context, Result};
use zerocopy::{AsBytes, FromBytes};

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

// Defined in the kernel ABI crate
const HEADER_MAGIC: u32 = 0x15356637;
const CABOOSE_MAGIC: u32 = 0xcab0005e;

////////////////////////////////////////////////////////////////////////////////

/// Minimal Hubris archive, useful for some basic manipulation
#[derive(Debug)]
pub struct RawHubrisImage {
    pub zip: Vec<u8>,

    pub data: BTreeMap<u32, LoadSegment>,
    pub kentry: u32,
}

impl RawHubrisImage {
    pub fn load<P: AsRef<Path> + std::fmt::Debug + Copy>(
        filename: P,
    ) -> Result<Self> {
        let contents = std::fs::read(filename).with_context(|| {
            format!("could not read archive file {filename:?}")
        })?;
        let cursor = Cursor::new(contents.as_slice());
        let mut archive = zip::ZipArchive::new(cursor)?;
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

        let (data, kentry) = {
            const SREC_FILE: &str = "img/final.srec";
            let mut file = archive
                .by_name(SREC_FILE)
                .with_context(|| format!("failed to find '{SREC_FILE:?}'"))?;
            let mut buffer = vec![];
            file.read_to_end(&mut buffer)?;
            let srec_str = std::str::from_utf8(&buffer)?;
            load_srec(Path::new(SREC_FILE), srec_str)?
        };

        Ok(Self {
            zip: contents,
            data,
            kentry,
        })
    }

    fn caboose_range(&self) -> Result<std::ops::Range<u32>> {
        let start_addr = self
            .data
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| anyhow!("empty image?"))?;

        let mut found_header = None;

        // The header is located in one of two locations, depending on MCU
        for header_offset in [0xbc, 0x298] {
            let mut header_magic = 0u32;
            self.read(start_addr + header_offset, &mut header_magic)?;
            if header_magic == HEADER_MAGIC {
                found_header = Some(header_offset);
                break;
            }
        }

        let Some(header_offset) = found_header else {
                bail!("could not find HEADER_MAGIC {HEADER_MAGIC:x}");
            };

        let mut image_size = 0u32;
        self.read(start_addr + header_offset + 4, &mut image_size)?;

        let mut caboose_size = 0u32;
        self.read(start_addr + image_size - 4, &mut caboose_size)?;

        let mut caboose_magic = 0u32;
        self.read(start_addr + image_size - caboose_size, &mut caboose_magic)?;
        if caboose_magic != CABOOSE_MAGIC {
            bail!(
                "Invalid caboose magic: expected {CABOOSE_MAGIC}, \
                     got {caboose_magic}"
            );
        }
        Ok(start_addr + image_size - caboose_size + 4
            ..start_addr + image_size - 4)
    }

    pub fn read_caboose(&self) -> Result<Vec<u8>> {
        // Skip the start and end word, which are markers
        let caboose_range = self.caboose_range()?;
        let mut out = vec![0u8; caboose_range.len()];
        self.read(caboose_range.start, out.as_mut_slice())?;
        Ok(out)
    }

    pub fn write_caboose(&mut self, data: &[u8]) -> Result<()> {
        // Skip the start and end word, which are markers
        let caboose_range = self.caboose_range()?;
        if data.len() > caboose_range.len() {
            bail!(
                "data is too long ({} bytes) for caboose ({} bytes)",
                data.len(),
                caboose_range.len()
            );
        }
        self.write(caboose_range.start, data)
    }

    /// Overwrites the existing archive with our modifications
    ///
    /// Changes are only made to the `img/final.*` files
    pub fn overwrite(&self) -> Result<()> {
        let cursor = Cursor::new(self.zip.as_slice());
        let mut archive = zip::ZipArchive::new(cursor)?;

        // Write to an in-memory buffer
        let mut out_buf = vec![];
        let out_cursor = Cursor::new(&mut out_buf);
        let mut out = zip::ZipWriter::new(out_cursor);
        out.set_raw_comment(archive.comment().to_vec());

        let opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Bzip2);

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            let outpath = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => {
                    println!("bad file");
                    continue;
                }
            };
            out.start_file(outpath.as_os_str().to_str().unwrap(), opts)?;
            std::io::copy(&mut file, &mut out).unwrap();
        }
        out.finish()?;
        drop(out);

        println!("got output {}", out_buf.len());
        println!("got output {}", self.zip.len());
        println!("{}", self.zip == out_buf);
        std::fs::write("out.zip", out_buf)?;
        Ok(())
    }

    /// Attempts to read `out.len()` bytes, starting at `start`
    fn read<T: AsBytes + FromBytes + ?Sized>(
        &self,
        start: u32,
        out: &mut T,
    ) -> Result<()> {
        let out_data = out.as_bytes_mut();
        let out_range = start..start + out_data.len() as u32;
        let mut bytes_read = 0;
        // TODO: this isn't particularly efficient, since it looks at **every
        // single** LoadSegment
        for (addr, data) in &self.data {
            let in_data = data.data.as_slice();
            let in_range = *addr..*addr + in_data.len() as u32;
            // Non-overlapping regions
            if out_range.end <= in_range.start
                || in_range.end <= out_range.start
            {
                continue;
            } else if out_range.start >= in_range.start {
                let in_data =
                    &in_data[(out_range.start - in_range.start) as usize..];
                let count = out_data.len().min(in_data.len());
                out_data[..count].copy_from_slice(&in_data[..count]);
                bytes_read += count;
            } else if in_range.start >= out_range.start {
                let out_data = &mut out_data
                    [(in_range.start - out_range.start) as usize..];
                let count = out_data.len().min(in_data.len());
                out_data[..count].copy_from_slice(&in_data[..count]);
                bytes_read += count;
            } else {
                unreachable!("overlapping ranges must overlap");
            }
        }
        if bytes_read != out_data.len() {
            bail!(
                "could not copy out all data; expected {} bytes, got {}",
                out_data.len(),
                bytes_read
            )
        }
        Ok(())
    }

    /// Attempts to read `out.len()` bytes, starting at `start`
    fn write<T: AsBytes + FromBytes + ?Sized>(
        &mut self,
        start: u32,
        input: &T,
    ) -> Result<()> {
        let in_data = input.as_bytes();
        let in_range = start..start + in_data.len() as u32;
        let mut bytes_written = 0;
        // TODO: this isn't particularly efficient, since it looks at **every
        // single** LoadSegment
        for (addr, data) in &mut self.data {
            let out_data = data.data.as_mut_slice();
            let out_range = *addr..*addr + out_data.len() as u32;
            // Non-overlapping regions
            if in_range.end <= out_range.start
                || out_range.end <= in_range.start
            {
                continue;
            } else if in_range.start >= out_range.start {
                let out_data = &mut out_data
                    [(in_range.start - out_range.start) as usize..];
                let count = in_data.len().min(out_data.len());
                out_data[..count].copy_from_slice(&in_data[..count]);
                bytes_written += count;
            } else if out_range.start >= in_range.start {
                let in_data =
                    &in_data[(out_range.start - in_range.start) as usize..];
                let count = in_data.len().min(out_data.len());
                out_data[..count].copy_from_slice(&in_data[..count]);
                bytes_written += count;
            } else {
                unreachable!("overlapping ranges must overlap");
            }
        }
        if bytes_written != in_data.len() {
            bail!(
                "could not copy out all data; expected {} bytes, got {}",
                in_data.len(),
                bytes_written
            )
        }
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous utility zone!

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

/// Loads an SREC file into the same representation we use for ELF.
///
/// Returns a tuple of `(memory, kernel entry)`
///
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
