// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use path_slash::PathBufExt;
use thiserror::Error;
use zerocopy::{AsBytes, FromBytes};

use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Write},
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

#[derive(Error, Debug)]
pub enum Error {
    #[error("could not read file `{0}`: {1}")]
    FileReadFailed(PathBuf, std::io::Error),

    #[error("could not write file `{0}`: {1}")]
    FileWriteFailed(PathBuf, std::io::Error),

    #[error("could not create zip archive: {0}")]
    ZipNewError(zip::result::ZipError),

    #[error("zip error: {0}")]
    ZipError(#[from] zip::result::ZipError),

    #[error("invalid file in zip archive: {0}")]
    BadFileInZip(String),

    #[error("bad comment encoding")]
    BadCommentEncoding(std::str::Utf8Error),

    #[error("could not parse version string `{0}`")]
    BadVersionString(std::num::ParseIntError, String),

    #[error("could not parse Hubris archive version from `{0}`")]
    BadComment(String),

    #[error("could not find `{1}`: {0}")]
    MissingFile(zip::result::ZipError, String),

    #[error("file read error: {0}")]
    FileReadError(std::io::Error),

    #[error("could not create temporary dir: {0}")]
    TempDirError(std::io::Error),

    #[error("srec decoding error: {0}")]
    BadSrec(std::str::Utf8Error),

    #[error("image is empty")]
    EmptyImage,

    #[error("could not find magic number {0:#x}")]
    MissingMagic(u32),

    #[error("caboose is not present in this image")]
    MissingCaboose,

    #[error("bad caboose magic number: expected {0:#x}, got {1:#x}")]
    BadCabooseMagic(u32, u32),

    #[error("data is too large ({0:#x}) for caboose ({1:#x})")]
    OversizedData(usize, usize),

    #[error("start address {0:#x} is not available")]
    BadStartAddress(u32),

    #[error("memory map has discontiguous segments at the target range")]
    DiscontiguousSegments,

    #[error("failed to write the entire data")]
    WriteFailed,

    #[error("failed to read the entire data")]
    ReadFailed,

    #[error("calling objcopy with {0:?} failed: {1}")]
    ObjcopyCallFailed(Command, std::io::Error),

    #[error("objcopy failed, see output for details")]
    ObjcopyFailed,

    #[error("srec error: {0}")]
    SrecError(#[from] srec::ReaderError),

    #[error("{0}: record address range {1:#x?} overlaps {2:#x}")]
    MemoryRangeOverlap(String, std::ops::Range<u32>, u32),
}

////////////////////////////////////////////////////////////////////////////////

/// Minimal Hubris archive, useful for some basic manipulation
///
/// Specifically, a `RawHubrisArchive` contains the memory contents of the
/// image, stored as a map from address to [`LoadSegment`], along with the
/// kernel entry point.
///
/// This is sufficient to reconstruct the SREC file, without any ELF
/// manipulation or parsing of the manifest.
#[derive(Debug)]
pub struct RawHubrisImage {
    pub path: PathBuf,
    pub zip: Vec<u8>,

    pub data: BTreeMap<u32, LoadSegment>,
    pub kentry: u32,
}

impl RawHubrisImage {
    pub fn load<P: AsRef<Path> + std::fmt::Debug + Copy>(
        filename: P,
    ) -> Result<Self, Error> {
        let contents = std::fs::read(filename).map_err(|e| {
            Error::FileReadFailed(filename.as_ref().to_owned(), e)
        })?;
        let cursor = Cursor::new(contents.as_slice());
        let mut archive =
            zip::ZipArchive::new(cursor).map_err(Error::ZipNewError)?;
        let comment = std::str::from_utf8(archive.comment())
            .map_err(Error::BadCommentEncoding)?;

        match comment.strip_prefix("hubris build archive v") {
            Some(v) => {
                let _v: u32 = v
                    .parse()
                    .map_err(|e| Error::BadVersionString(e, v.to_owned()))?;
            }
            None => {
                return Err(Error::BadComment(comment.to_owned()));
            }
        }

        let (data, kentry) = {
            const SREC_FILE: &str = "img/final.srec";
            let mut file = archive.by_name(SREC_FILE).map_err(|e| {
                Error::MissingFile(e, format!("failed to find '{SREC_FILE:?}'"))
            })?;
            let mut buffer = vec![];
            file.read_to_end(&mut buffer)
                .map_err(Error::FileReadError)?;
            let srec_str =
                std::str::from_utf8(&buffer).map_err(Error::BadSrec)?;
            load_srec(Path::new(SREC_FILE), srec_str)?
        };

        Ok(Self {
            path: filename.as_ref().to_owned(),
            zip: contents,
            data,
            kentry,
        })
    }

    fn caboose_range(&self) -> Result<std::ops::Range<u32>, Error> {
        let start_addr =
            self.data.keys().next().cloned().ok_or(Error::EmptyImage)?;

        let mut found_header = None;

        // The header is located in one of a few locations, depending on MCU
        // and versions of the PAC crates.
        for header_offset in [0xbc, 0xc0, 0x298] {
            let mut header_magic = 0u32;
            self.read(start_addr + header_offset, &mut header_magic)?;
            if header_magic == HEADER_MAGIC {
                found_header = Some(header_offset);
                break;
            }
        }

        let Some(header_offset) = found_header else {
            return Err(Error::MissingMagic(HEADER_MAGIC));
        };

        let mut image_size = 0u32;
        self.read(start_addr + header_offset + 4, &mut image_size)?;

        let mut caboose_size = 0u32;
        self.read(start_addr + image_size - 4, &mut caboose_size)?;

        let mut caboose_magic = 0u32;
        let caboose_magic_addr = (start_addr + image_size)
            .checked_sub(caboose_size)
            .ok_or(Error::MissingCaboose)?;
        self.read(caboose_magic_addr, &mut caboose_magic)?;
        if caboose_magic != CABOOSE_MAGIC {
            return Err(Error::BadCabooseMagic(CABOOSE_MAGIC, caboose_magic))?;
        }
        Ok(start_addr + image_size - caboose_size + 4
            ..start_addr + image_size - 4)
    }

    /// Reads the caboose from local memory
    pub fn read_caboose(&self) -> Result<Vec<u8>, Error> {
        // Skip the start and end word, which are markers
        let caboose_range = self.caboose_range()?;
        let mut out = vec![0u8; caboose_range.len()];
        self.read(caboose_range.start, out.as_mut_slice())?;
        Ok(out)
    }

    /// Writes to the caboose in local memory
    ///
    /// [`overwrite`] must be called to write these changes back to disk.
    pub fn write_caboose(&mut self, data: &[u8]) -> Result<(), Error> {
        // Skip the start and end word, which are markers
        let caboose_range = self.caboose_range()?;
        if data.len() > caboose_range.len() {
            return Err(Error::OversizedData(data.len(), caboose_range.len()));
        }
        self.write(caboose_range.start, data)
    }

    /// Erases the caboose in local memory
    ///
    /// [`overwrite`] must be called to write these changes back to disk.
    pub fn erase_caboose(&mut self) -> Result<(), Error> {
        let caboose_range = self.caboose_range()?;
        let data = vec![0xFFu8; caboose_range.len()];
        self.write(caboose_range.start, data.as_slice())
    }

    pub fn is_caboose_empty(&self) -> Result<bool, Error> {
        let caboose = self.read_caboose()?;
        Ok(caboose.into_iter().all(|c| c == 0xFF))
    }

    /// Overwrites the existing archive with our modifications
    ///
    /// Changes are only made to the `img/final.*` files
    pub fn overwrite(&self) -> Result<(), Error> {
        // We'll use a temporary file to create modified object files, because
        // we build them with `arm-none-eabi-objcopy`
        let temp_dir = tempfile::tempdir().map_err(Error::TempDirError)?;
        write_srec(
            &self.data,
            self.kentry,
            &temp_dir.path().join("final.srec"),
        )?;
        translate_srec_to_other_formats(temp_dir.path(), "final")?;

        let cursor = Cursor::new(self.zip.as_slice());
        let mut archive =
            zip::ZipArchive::new(cursor).map_err(Error::ZipNewError)?;

        // Write to an in-memory buffer
        let mut out_buf = vec![];
        let out_cursor = Cursor::new(&mut out_buf);
        let mut out = zip::ZipWriter::new(out_cursor);
        out.set_raw_comment(archive.comment().to_vec());

        let opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Bzip2);

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            let outpath = file
                .enclosed_name()
                .ok_or_else(|| Error::BadFileInZip(file.name().to_owned()))?
                .to_owned();
            let path = outpath.iter().collect::<Vec<_>>();
            let new_data = if path.len() == 2
                && path[0].to_str() == Some("img")
                && path[1].to_str().unwrap().starts_with("final.")
            {
                Some(
                    std::fs::read(temp_dir.path().join(path[1]))
                        .map_err(Error::FileReadError)?,
                )
            } else {
                None
            };

            out.start_file(outpath.to_slash().unwrap(), opts)?;
            if let Some(data) = new_data {
                out.write_all(&data).unwrap();
            } else {
                std::io::copy(&mut file, &mut out).unwrap();
            }
        }
        out.finish()?;
        drop(out);

        std::fs::write(&self.path, out_buf)
            .map_err(|e| Error::FileWriteFailed(self.path.clone(), e))?;
        Ok(())
    }

    /// Attempts to read `out.len()` bytes, starting at `start`
    fn read<T: AsBytes + FromBytes + ?Sized>(
        &self,
        start: u32,
        out: &mut T,
    ) -> Result<(), Error> {
        // Find the element in the BTreeMap that's just below our start address
        let lower_bound = *self
            .data
            .range(..=start)
            .rev()
            .next()
            .ok_or(Error::BadStartAddress(start))?
            .0;
        assert!(start >= lower_bound);

        let mut prev = None;
        let mut num_bytes = 0;

        // Iterate over ((byte address, byte), output byte)
        //
        // Looking at byte address isn't strictly necessary, but it lets us
        // detect whether the input segments are discontiguous.
        for ((i, c), out) in self
            .data
            .range(lower_bound..)
            .flat_map(|(i, d)| {
                d.data.iter().enumerate().map(|(j, c)| (*i as usize + j, c))
            })
            .skip((start - lower_bound) as usize)
            .zip(out.as_bytes_mut())
        {
            if let Some(prev) = prev {
                if i != prev + 1 {
                    return Err(Error::DiscontiguousSegments);
                }
            }
            prev = Some(i);
            *out = *c;
            num_bytes += 1;
        }

        if num_bytes != (out.as_bytes().len()) {
            return Err(Error::WriteFailed);
        }

        Ok(())
    }

    /// Attempts to read `out.len()` bytes, starting at `start`
    fn write<T: AsBytes + FromBytes + ?Sized>(
        &mut self,
        start: u32,
        input: &T,
    ) -> Result<(), Error> {
        // Find the element in the BTreeMap that's just below our start address
        let lower_bound = *self
            .data
            .range(..=start)
            .rev()
            .next()
            .ok_or(Error::BadStartAddress(start))?
            .0;

        let mut prev = None;
        let mut num_bytes = 0;
        for ((i, out), c) in self
            .data
            .range_mut(lower_bound..)
            .flat_map(|(i, d)| {
                d.data
                    .iter_mut()
                    .enumerate()
                    .map(|(j, c)| (*i as usize + j, c))
            })
            .skip((start - lower_bound) as usize)
            .zip(input.as_bytes())
        {
            if let Some(prev) = prev {
                if i != prev + 1 {
                    return Err(Error::DiscontiguousSegments);
                }
            }
            prev = Some(i);
            *out = *c;
            num_bytes += 1;
        }

        if num_bytes != (input.as_bytes().len()) {
            return Err(Error::WriteFailed);
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
) -> Result<(), Error> {
    let mut cmd = Command::new("arm-none-eabi-objcopy");
    cmd.arg("-I")
        .arg(in_format)
        .arg("-O")
        .arg(out_format)
        .arg("--gap-fill")
        .arg("0xFF")
        .arg(src)
        .arg(dest);

    let status = cmd.status().map_err(|e| Error::ObjcopyCallFailed(cmd, e))?;

    if status.success() {
        Ok(())
    } else {
        Err(Error::ObjcopyFailed)
    }
}

/// Convert SREC to other formats for convenience.
pub fn translate_srec_to_other_formats(
    dist_dir: &Path,
    name: &str,
) -> Result<(), Error> {
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
) -> Result<(BTreeMap<u32, LoadSegment>, u32), Error> {
    let mut output = BTreeMap::new();
    for record in srec::reader::read_records(srec_text) {
        let record = record?;
        match record {
            srec::Record::S3(data) => {
                // Check for address overlap
                let range =
                    data.address.0..data.address.0 + data.data.len() as u32;
                if let Some(overlap) = output.range(range.clone()).next() {
                    return Err(Error::MemoryRangeOverlap(
                        input.display().to_string(),
                        range,
                        *overlap.0,
                    ));
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
) -> Result<(), Error> {
    let mut srec_out = vec![srec::Record::S0(name.to_string())];

    let binary = std::fs::read(binary)
        .map_err(|e| Error::FileReadFailed(binary.to_owned(), e))?;

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
    std::fs::write(out, srec_image)
        .map_err(|e| Error::FileWriteFailed(out.to_owned(), e))?;
    Ok(())
}

/// Writes a SREC file to the filesystem
pub fn write_srec(
    sections: &BTreeMap<u32, LoadSegment>,
    kentry: u32,
    out: &Path,
) -> Result<(), Error> {
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
    std::fs::write(out, srec_image)
        .map_err(|e| Error::FileWriteFailed(out.to_owned(), e))?;
    Ok(())
}
