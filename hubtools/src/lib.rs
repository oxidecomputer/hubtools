// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use path_slash::PathBufExt;
use thiserror::Error;
use zerocopy::{AsBytes, FromBytes};

use std::{
    collections::{btree_map::Entry, BTreeMap},
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

/// Represents (possibly discontiguous) segments in memory
pub struct SegmentMap {
    pub data: BTreeMap<u32, LoadSegment>,
    pub kentry: u32,
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

    #[error("manifest decoding error: {0}")]
    BadManifest(std::str::Utf8Error),

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

    #[error("bad TOML file: {0}")]
    BadToml(toml::de::Error),

    #[error("duplicate filename in zip archive: {0}")]
    DuplicateFilename(String),

    #[error("failed to build ihex file: {0}")]
    IHexError(ihex::WriterError),

    #[error("start address of ihex chunk at {0:#x} is not aligned")]
    BadIHexStartAddress(u32),
}

////////////////////////////////////////////////////////////////////////////////

/// Minimal Hubris archive, useful for some basic manipulation of the binary
/// image within.
#[derive(Debug)]
pub struct RawHubrisImage {
    /// Source path of the Hubris archive on disk
    pub path: PathBuf,

    /// New files to be inserted into the zip archive when `overwrite` is called
    new_files: BTreeMap<String, Vec<u8>>,

    /// Raw data of the Hubris archive zip file
    ///
    /// Note that this may diverge from the data stored below as we edit it;
    /// call `overwrite` to write it back to disk.
    pub zip: Vec<u8>,

    /// Start address of the raw data (absolute)
    pub start_addr: u32,

    /// Raw data from the image
    pub data: Vec<u8>,

    /// Kernel entry point (absolute address)
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

        let (start_addr, data, kentry) = {
            const SREC_FILE: &str = "img/final.srec";
            let mut file = archive.by_name(SREC_FILE).map_err(|e| {
                Error::MissingFile(e, format!("failed to find '{SREC_FILE:?}'"))
            })?;
            let mut buffer = vec![];
            file.read_to_end(&mut buffer)
                .map_err(Error::FileReadError)?;
            let srec_str =
                std::str::from_utf8(&buffer).map_err(Error::BadSrec)?;
            let segment_map = load_srec(Path::new(SREC_FILE), srec_str)?;

            let (start_addr, data) = segment_map_to_binary(&segment_map, 0xFF)?;
            (start_addr, data, segment_map.kentry)
        };

        Ok(Self {
            path: filename.as_ref().to_owned(),
            zip: contents,
            new_files: BTreeMap::new(),
            start_addr,
            data,
            kentry,
        })
    }

    /// Adds a file to the archive
    ///
    /// This only modifies the archive in memory; call `overwrite` to persist
    /// the changes to disk.
    pub fn add_file(&mut self, name: &str, data: &[u8]) -> Result<(), Error> {
        match self.new_files.entry(name.to_string()) {
            Entry::Vacant(v) => {
                v.insert(data.to_vec());
                Ok(())
            }
            Entry::Occupied(_) => {
                Err(Error::DuplicateFilename(name.to_string()))
            }
        }
    }

    fn caboose_range(&self) -> Result<std::ops::Range<u32>, Error> {
        let mut found_header = None;

        // The header is located in one of a few locations, depending on MCU
        // and versions of the PAC crates.
        for header_offset in [0xbc, 0xc0, 0x298] {
            let mut header_magic = 0u32;
            self.read(self.start_addr + header_offset, &mut header_magic)?;
            if header_magic == HEADER_MAGIC {
                found_header = Some(header_offset);
                break;
            }
        }

        let Some(header_offset) = found_header else {
            return Err(Error::MissingMagic(HEADER_MAGIC));
        };

        let mut image_size = 0u32;
        self.read(self.start_addr + header_offset + 4, &mut image_size)?;

        let mut caboose_size = 0u32;
        self.read(self.start_addr + image_size - 4, &mut caboose_size)?;

        let mut caboose_magic = 0u32;
        let caboose_magic_addr = (self.start_addr + image_size)
            .checked_sub(caboose_size)
            .ok_or(Error::MissingCaboose)?;
        self.read(caboose_magic_addr, &mut caboose_magic)?;
        if caboose_magic != CABOOSE_MAGIC {
            return Err(Error::BadCabooseMagic(CABOOSE_MAGIC, caboose_magic))?;
        }
        Ok(self.start_addr + image_size - caboose_size + 4
            ..self.start_addr + image_size - 4)
    }

    /// Reads the caboose from local memory
    pub fn read_caboose(&self) -> Result<Vec<u8>, Error> {
        // Skip the start and end word, which are markers
        let caboose_range = self.caboose_range()?;
        let mut out = vec![0u8; caboose_range.len()];
        self.read(caboose_range.start, out.as_mut_slice())?;
        Ok(out)
    }

    fn extract_file(&self, name: &str) -> Result<Vec<u8>, Error> {
        let cursor = Cursor::new(self.zip.as_slice());
        let mut archive =
            zip::ZipArchive::new(cursor).map_err(Error::ZipNewError)?;
        let mut file = archive.by_name(name).map_err(|e| {
            Error::MissingFile(e, format!("failed to find '{name:?}'"))
        })?;
        let mut buffer = vec![];
        file.read_to_end(&mut buffer)
            .map_err(Error::FileReadError)?;
        Ok(buffer)
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

    /// Writes the given version (and nothing else) to the caboose
    pub fn write_version_to_caboose(
        &mut self,
        version: &str,
    ) -> Result<(), Error> {
        // Manually build the TLV-C data for the caboose
        let data = tlvc_text::Piece::Chunk(
            tlvc_text::Tag::new(*b"VERS"),
            vec![tlvc_text::Piece::String(version.to_owned())],
        );
        let out = tlvc_text::pack(&[data]);
        self.write_caboose(&out)?;
        Ok(())
    }

    /// Writes a default caboose
    ///
    /// The default caboose includes the following tags:
    /// - `GITC`: the current Git commit with an optional trailing "-dirty"
    /// - `NAME`: image name
    /// - `BORD`: board name
    /// - `VERS`: the provided version string (if present)
    ///
    /// Everything except `VERS` are extracted from the Hubris archive itself.
    pub fn write_default_caboose(
        &mut self,
        version: Option<&String>,
    ) -> Result<(), Error> {
        let manifest = self.extract_file("app.toml")?;
        let git = self.extract_file("git-rev")?;

        let manifest: toml::Value = toml::from_str(
            std::str::from_utf8(&manifest).map_err(Error::BadManifest)?,
        )
        .map_err(Error::BadToml)?;

        let board = manifest
            .as_table()
            .unwrap()
            .get("board")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let name = manifest
            .as_table()
            .unwrap()
            .get("name")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();

        let mut chunks = vec![
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(*b"GITC"),
                vec![tlvc_text::Piece::Bytes(git)],
            ),
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(*b"BORD"),
                vec![tlvc_text::Piece::String(board)],
            ),
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(*b"NAME"),
                vec![tlvc_text::Piece::String(name)],
            ),
        ];
        if let Some(v) = version {
            let data = tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(*b"VERS"),
                vec![tlvc_text::Piece::String(v.to_owned())],
            );
            chunks.push(data)
        }
        let out = tlvc_text::pack(&chunks);
        self.write_caboose(&out)
    }

    /// Erases the caboose in local memory
    ///
    /// [`overwrite`] must be called to write these changes back to disk.
    pub fn erase_caboose(&mut self) -> Result<(), Error> {
        let caboose_range = self.caboose_range()?;
        let data = vec![0xFFu8; caboose_range.len()];
        self.write(caboose_range.start, data.as_slice())
    }

    /// Checks whether the caboose is empty in local memory
    pub fn is_caboose_empty(&self) -> Result<bool, Error> {
        let caboose = self.read_caboose()?;
        Ok(caboose.into_iter().all(|c| c == 0xFF))
    }

    /// Overwrites the existing archive with our modifications
    ///
    /// Changes are only made to the `img/final.*` files, as well as anything
    /// listed in `self.new_files`
    pub fn overwrite(mut self) -> Result<(), Error> {
        let segment_map = binary_to_segment_map(
            &self.data,
            "final.bin",
            self.start_addr,
            self.kentry,
        )?;

        // Convert the SREC into all of our canonical file formats
        self.add_file(
            "img/final.srec",
            segment_map_to_srec(&segment_map)?.as_bytes(),
        )?;
        self.add_file(
            "img/final.ihex",
            segment_map_to_ihex(&segment_map)?.as_bytes(),
        )?;
        self.add_file("img/final.elf", &segment_map_to_elf(&segment_map))?;
        self.add_file(
            "img/final.bin",
            &segment_map_to_binary(&segment_map, 0xFF)?.1,
        )?;

        let cursor = Cursor::new(self.zip.as_slice());
        let mut archive =
            zip::ZipArchive::new(cursor).map_err(Error::ZipNewError)?;

        // Write to an in-memory buffer, representing a zip file
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

            let path = outpath.to_slash().unwrap();
            if !self.new_files.contains_key(&path) {
                out.start_file(path, opts)?;
                std::io::copy(&mut file, &mut out).unwrap();
            }
        }

        // Write all of our new and modified files
        for (f, d) in self.new_files.into_iter() {
            out.start_file(f, opts)?;
            out.write_all(&d).unwrap();
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
        let start = start
            .checked_sub(self.start_addr)
            .ok_or(Error::BadStartAddress(start))? as usize;

        let chunk = self
            .data
            .get(start..start + out.as_bytes().len())
            .ok_or(Error::ReadFailed)?;
        out.as_bytes_mut().copy_from_slice(chunk);
        Ok(())
    }

    /// Attempts to read `out.len()` bytes, starting at `start`
    fn write<T: AsBytes + FromBytes + ?Sized>(
        &mut self,
        start: u32,
        input: &T,
    ) -> Result<(), Error> {
        let start = start
            .checked_sub(self.start_addr)
            .ok_or(Error::BadStartAddress(start))? as usize;

        let chunk = self
            .data
            .get_mut(start..start + input.as_bytes().len())
            .ok_or(Error::WriteFailed)?;
        chunk.copy_from_slice(input.as_bytes());
        Ok(())
    }

    /// Returns a mutable reference to the inner data
    ///
    /// Modifications made here are not applied to the on-disk archive until
    /// `overwrite` is called.
    pub fn get_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous utility zone!

/// Convert SREC to other formats for convenience.
pub fn write_all_formats(
    segment_map: &SegmentMap,
    dist_dir: &Path,
    name: &str,
) -> Result<(), Error> {
    let elf = segment_map_to_elf(segment_map);
    let elf_file = dist_dir.join(format!("{name}.elf"));
    std::fs::write(&elf_file, &elf)
        .map_err(|e| Error::FileWriteFailed(elf_file, e))?;

    let (_, bin) = segment_map_to_binary(segment_map, 0xFF)?;
    let bin_file = dist_dir.join(format!("{name}.bin"));
    std::fs::write(&bin_file, &bin)
        .map_err(|e| Error::FileWriteFailed(bin_file, e))?;

    let ihex = segment_map_to_ihex(segment_map)?;
    let ihex_file = dist_dir.join(format!("{name}.ihex"));
    std::fs::write(&ihex_file, ihex)
        .map_err(|e| Error::FileWriteFailed(ihex_file, e))?;

    Ok(())
}

pub fn segment_map_to_ihex(segment_map: &SegmentMap) -> Result<String, Error> {
    let mut records = vec![];

    for (addr, LoadSegment { data, .. }) in &segment_map.data {
        for (offset, chunk) in data.chunks(65536).enumerate() {
            let start_addr: u32 =
                (*addr as usize + 65536 * offset).try_into().unwrap();
            if start_addr & 0xFFFF != 0 {
                return Err(Error::BadIHexStartAddress(start_addr));
            }
            records.push(ihex::Record::ExtendedLinearAddress(
                (start_addr >> 16) as u16,
            ));
            for (i, line) in chunk.chunks(16).enumerate() {
                records.push(ihex::Record::Data {
                    offset: (i * 16).try_into().unwrap(),
                    value: line.to_owned(),
                });
            }
        }
    }

    records.push(ihex::Record::EndOfFile);
    ihex::create_object_file_representation(&records).map_err(Error::IHexError)
}

/// Loads an SREC file into a segment map, merging adjacent sections
pub fn load_srec(input: &Path, srec_text: &str) -> Result<SegmentMap, Error> {
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
            srec::Record::S7(srec::Address32(kentry)) => {
                let mut merged: BTreeMap<u32, LoadSegment> = BTreeMap::new();
                let mut prev = None;
                for (addr, data) in output {
                    let size = data.data.len();
                    if prev == Some(addr) {
                        merged
                            .values_mut()
                            .rev()
                            .next()
                            .unwrap()
                            .data
                            .extend(data.data);
                    } else {
                        merged.insert(addr, data);
                    }
                    prev = Some(addr + size as u32);
                }
                return Ok(SegmentMap {
                    data: merged,
                    kentry,
                });
            }
            _ => (),
        }
    }
    panic!("SREC file missing terminating S7 record");
}

/// Converts binary data into an SREC-style memory map
pub fn binary_to_segment_map(
    binary: &[u8],
    name: &str,
    start_addr: u32,
    kentry: u32,
) -> Result<SegmentMap, Error> {
    let mut data = BTreeMap::new();

    let mut addr = start_addr;
    data.insert(
        addr,
        LoadSegment {
            source_file: PathBuf::from(name),
            data: binary.to_owned(),
        },
    );

    Ok(SegmentMap { data, kentry })
}

pub fn segment_map_to_elf(segment_map: &SegmentMap) -> Vec<u8> {
    let mut out = vec![];
    let mut w = object::write::elf::Writer::new(
        object::Endianness::Little,
        false,
        &mut out,
    );

    // The order in which we do things is taken from
    // `object/src/write/elf/object.rs:elf_write`, but this is dramatically
    // simpler: we're writing a single section with no relocations, symbols, or
    // other fanciness (other than .shstrtab)
    let header = object::write::elf::FileHeader {
        abi_version: 0,
        e_entry: segment_map.kentry as u64,
        e_flags: 0,
        e_machine: object::elf::EM_ARM,
        e_type: object::elf::ET_REL,
        os_abi: object::elf::ELFOSABI_ARM,
    };
    w.reserve_file_header();

    // Build a set of names with the same lifetime as the writer
    let names = (0..segment_map.data.len())
        .map(|i| format!(".sec{}", i + 1))
        .collect::<Vec<_>>();
    let mut sections = vec![];
    for (i, bin) in segment_map.data.values().enumerate() {
        let _index = w.reserve_section_index();
        let offset = w.reserve(bin.data.len(), 1);
        let name = w.add_section_name(names[i].as_bytes());
        sections.push((offset, name))
    }

    w.reserve_shstrtab_section_index();
    w.reserve_shstrtab();

    w.reserve_section_headers();

    w.write_file_header(&header).unwrap();
    w.write_align(4);
    for bin in segment_map.data.values() {
        w.write(&bin.data);
    }

    w.write_shstrtab();
    w.write_null_section_header();

    for ((offset, name), (addr, bin)) in
        sections.iter().zip(segment_map.data.iter())
    {
        w.write_section_header(&object::write::elf::SectionHeader {
            name: Some(*name),
            sh_addr: *addr as u64,
            sh_addralign: 1,
            sh_entsize: 0,
            sh_flags: (object::elf::SHF_WRITE | object::elf::SHF_ALLOC) as u64,
            sh_info: 0,
            sh_link: 0,
            sh_offset: *offset as u64,
            sh_size: bin.data.len() as u64,
            sh_type: object::elf::SHT_PROGBITS,
        });
    }

    w.write_shstrtab_section_header();

    debug_assert_eq!(w.reserved_len(), w.len());

    out
}

/// Converts from an SREC-style memory map to a single binary blob
pub fn segment_map_to_binary(
    segment_map: &SegmentMap,
    gap_fill: u8,
) -> Result<(u32, Vec<u8>), Error> {
    let mut prev: Option<u32> = None;
    let mut out = vec![];
    for (addr, data) in &segment_map.data {
        if let Some(mut prev) = prev {
            while prev != *addr {
                out.push(gap_fill);
                prev += 1;
            }
        }
        prev = Some(*addr + data.data.len() as u32);
        out.extend(&data.data);
    }
    let start = segment_map.data.keys().next().cloned().unwrap_or(0);
    Ok((start, out))
}

/// Writes a SREC file to a string
pub fn segment_map_to_srec(segment_map: &SegmentMap) -> Result<String, Error> {
    let mut srec_out = vec![srec::Record::S0("hubris".to_string())];
    for (&base, sec) in &segment_map.data {
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

    srec_out.push(srec::Record::S7(srec::Address32(segment_map.kentry)));

    let srec_image = srec::writer::generate_srec_file(&srec_out);
    Ok(srec_image)
}
