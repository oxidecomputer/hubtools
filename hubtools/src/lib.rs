// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use object::{Object, ObjectSection, ObjectSegment};
use path_slash::PathBufExt;
use thiserror::Error;
use x509_cert::Certificate;
use zerocopy::{AsBytes, FromBytes};

use std::{
    collections::{btree_map::Entry, BTreeMap},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

mod archive_builder;
mod bootleby;
mod caboose;

pub use archive_builder::HubrisArchiveBuilder;
pub use bootleby::bootleby_to_archive;
pub use caboose::{Caboose, CabooseBuilder, CabooseError};

#[derive(Debug)]
pub struct RawHubrisImage {
    pub start_addr: u32,
    pub data: Vec<u8>,
    pub kentry: u32,
}

impl RawHubrisImage {
    pub fn from_segments(
        data: &BTreeMap<u32, Vec<u8>>,
        kentry: u32,
        gap_fill: u8,
    ) -> Result<Self, Error> {
        let mut prev: Option<u32> = None;
        let mut out = vec![];
        for (addr, data) in data.iter() {
            if let Some(prev) = prev {
                let gap_size = addr
                    .checked_sub(prev)
                    .ok_or(Error::MemorySegmentOverlap)?;
                out.resize(out.len() + gap_size as usize, gap_fill);
            }
            prev = Some(*addr + data.len() as u32);
            out.extend(data);
        }
        let start_addr = data.keys().next().copied().unwrap_or(0);
        Ok(RawHubrisImage {
            start_addr,
            data: out,
            kentry,
        })
    }

    pub fn from_binary(
        data: Vec<u8>,
        start_addr: u32,
        kentry: u32,
    ) -> Result<Self, Error> {
        let mut segments = BTreeMap::new();
        segments.insert(start_addr, data);
        Self::from_segments(&segments, kentry, 0xFF)
    }

    /// Convert a not hubris binary into a hubris archive
    pub fn from_generic_elf(elf_data: &[u8]) -> Result<Self, Error> {
        let elf = object::read::File::parse(elf_data)?;
        if elf.format() != object::BinaryFormat::Elf {
            return Err(Error::NotAnElf(elf.format()));
        }

        let mut segments: BTreeMap<u32, Vec<u8>> = BTreeMap::new();

        for s in elf.segments() {
            if let Ok(d) = s.data() {
                if !d.is_empty() {
                    segments.insert(s.address() as u32, d.to_vec());
                }
            }
        }

        Self::from_segments(&segments, elf.entry().try_into().unwrap(), 0xFF)
    }

    /// For elfs from previously produced hubris archives
    pub fn from_elf(elf_data: &[u8]) -> Result<Self, Error> {
        let elf = object::read::File::parse(elf_data)?;
        if elf.format() != object::BinaryFormat::Elf {
            return Err(Error::NotAnElf(elf.format()));
        }

        let mut segments: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        let code_flags = object::SectionFlags::Elf {
            sh_flags: (object::elf::SHF_WRITE | object::elf::SHF_ALLOC) as u64,
        };
        for s in elf.sections() {
            if s.flags() == code_flags {
                segments.insert(
                    s.address().try_into().unwrap(),
                    s.data()?.to_vec(),
                );
            }
        }
        Self::from_segments(&segments, elf.entry().try_into().unwrap(), 0xFF)
    }

    /// Converts the raw image to an ELF file
    ///
    /// This produces a single PROGBITS section
    pub fn to_elf(&self) -> Result<Vec<u8>, Error> {
        let mut out = vec![];
        let mut w = object::write::elf::Writer::new(
            object::Endianness::Little,
            false,
            &mut out,
        );

        // The order in which we do things is taken from
        // `object/src/write/elf/object.rs:elf_write`, but this is dramatically
        // simpler: we're writing a single section with no relocations, symbols,
        // or other fanciness (other than .shstrtab)
        let header = object::write::elf::FileHeader {
            abi_version: 0,
            e_entry: self.kentry as u64,
            e_flags: 0,
            e_machine: object::elf::EM_ARM,
            e_type: object::elf::ET_REL,
            os_abi: object::elf::ELFOSABI_ARM,
        };
        w.reserve_file_header();
        w.reserve_program_headers(1);

        let offset = w.reserve(self.data.len(), 4);

        let _index = w.reserve_section_index();
        let name = w.add_section_name(b".sec1");

        w.reserve_shstrtab_section_index();
        w.reserve_shstrtab();

        w.reserve_section_headers();

        // Writing happens here!
        w.write_file_header(&header).unwrap();
        w.write_align_program_headers();
        w.write_program_header(&object::write::elf::ProgramHeader {
            p_align: 0x20,
            p_filesz: self.data.len() as u64,
            p_memsz: self.data.len() as u64,
            p_flags: object::elf::PF_R,
            p_type: object::elf::PT_LOAD,
            p_offset: offset as u64,
            p_paddr: self.start_addr as u64,
            p_vaddr: self.start_addr as u64,
        });

        w.write_align(4);
        assert_eq!(w.len(), offset);
        w.write(self.data.as_slice());

        w.write_shstrtab();
        w.write_null_section_header();

        w.write_section_header(&object::write::elf::SectionHeader {
            name: Some(name),
            sh_addr: self.start_addr as u64,
            sh_addralign: 1,
            sh_entsize: 0,
            sh_flags: (object::elf::SHF_WRITE | object::elf::SHF_ALLOC) as u64,
            sh_info: 0,
            sh_link: 0,
            sh_offset: offset as u64,
            sh_size: self.data.len() as u64,
            sh_type: object::elf::SHT_PROGBITS,
        });

        w.write_shstrtab_section_header();

        debug_assert_eq!(w.reserved_len(), w.len());

        Ok(out)
    }

    /// Converts to a raw binary file
    pub fn to_binary(&self) -> Result<Vec<u8>, Error> {
        Ok(self.data.clone())
    }

    /// Convert SREC to other formats for convenience.
    pub fn write_all(&self, dist_dir: &Path, name: &str) -> Result<(), Error> {
        let elf = self.to_elf()?;
        let elf_file = dist_dir.join(format!("{name}.elf"));
        std::fs::write(&elf_file, elf)
            .map_err(|e| Error::FileWriteFailed(elf_file, e))?;

        let bin_file = dist_dir.join(format!("{name}.bin"));
        std::fs::write(&bin_file, &self.data)
            .map_err(|e| Error::FileWriteFailed(bin_file, e))?;
        Ok(())
    }

    /// Converts from an absolute address range to relative addresses
    ///
    /// The input addresses should be based on chip memory; the returned range
    /// can be used as an index into `self.data`
    fn find_chunk(
        &self,
        range: std::ops::Range<u32>,
    ) -> Result<std::ops::Range<usize>, Error> {
        let start = range
            .start
            .checked_sub(self.start_addr)
            .ok_or_else(|| Error::BadAddress(range.clone()))?
            as usize;
        let end = range
            .end
            .checked_sub(self.start_addr)
            .ok_or_else(|| Error::BadAddress(range.clone()))?
            as usize;

        if end > self.data.len() {
            return Err(Error::BadAddress(range));
        }
        Ok(start..end)
    }

    /// Gets a slice from the image, using absolute addresses
    pub fn get(&self, range: std::ops::Range<u32>) -> Result<&[u8], Error> {
        let range = self.find_chunk(range)?;
        Ok(&self.data[range])
    }

    /// Gets a mutable slice from the image, using absolute addresses
    pub fn get_mut(
        &mut self,
        range: std::ops::Range<u32>,
    ) -> Result<&mut [u8], Error> {
        let range = self.find_chunk(range)?;
        Ok(&mut self.data[range])
    }

    pub fn sign(
        &mut self,
        signing_certs: Vec<Certificate>,
        root_certs: Vec<Certificate>,
        private_key: &rsa::RsaPrivateKey,
        execution_address: u32,
    ) -> Result<(), Error> {
        // Overwrite the image with a signed blob
        let stamped = lpc55_sign::signed_image::stamp_image(
            self.data.clone(),
            signing_certs,
            root_certs,
            execution_address,
        )?;
        let signed =
            lpc55_sign::signed_image::sign_image(&stamped, private_key)?;

        self.data = signed;

        Ok(())
    }

    pub fn unsign(&mut self) -> Result<(), Error> {
        let stamped = lpc55_sign::signed_image::remove_image_signature(
            self.data.clone(),
        )?;
        self.data = stamped;

        Ok(())
    }

    pub fn replace(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    fn caboose_range(&self) -> Result<std::ops::Range<u32>, Error> {
        let mut found_header = None;
        let start_addr = self.start_addr;

        for header_offset in header::POSSIBLE_OFFSETS {
            let mut header_magic = 0u32;
            self.read(start_addr + header_offset, &mut header_magic)?;
            if header::MAGIC.contains(&header_magic) {
                found_header = Some(header_offset);
                break;
            }
        }

        let Some(header_offset) = found_header else {
            return Err(Error::MissingMagic(header::MAGIC));
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

    /// Writes to the caboose in local memory
    fn write_caboose(&mut self, data: &[u8]) -> Result<(), Error> {
        // Skip the start and end word, which are markers
        let caboose_range = self.caboose_range()?;

        let end = caboose_range.end - self.start_addr;
        if end as usize != self.data.len() - 4 {
            Err(Error::BadCabooseLocation)
        } else if data.len() > caboose_range.len() {
            Err(Error::OversizedData(data.len(), caboose_range.len()))
        } else {
            self.write(caboose_range.start, data)
        }
    }

    /// Attempts to read `out.len()` bytes, starting at `start`
    fn read<T: AsBytes + FromBytes + ?Sized>(
        &self,
        start: u32,
        out: &mut T,
    ) -> Result<(), Error> {
        let size = out.as_bytes().len() as u32;
        out.as_bytes_mut()
            .copy_from_slice(self.get(start..start + size)?);
        Ok(())
    }

    /// Attempts to read `out.len()` bytes, starting at `start`
    fn write<T: AsBytes + FromBytes + ?Sized>(
        &mut self,
        start: u32,
        input: &T,
    ) -> Result<(), Error> {
        let size = input.as_bytes().len() as u32;
        self.get_mut(start..start + size)?
            .copy_from_slice(input.as_bytes());
        Ok(())
    }
}

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

    #[error("bad image name encoding")]
    BadImageNameEncoding(std::string::FromUtf8Error),

    #[error("could not parse version string `{0}`")]
    BadVersionString(std::num::ParseIntError, String),

    #[error("could not parse Hubris archive version from `{0}`")]
    BadComment(String),

    #[error("could not find `{1}`: {0}")]
    MissingFile(zip::result::ZipError, String),

    #[error("file read error: {0}")]
    FileReadError(std::io::Error),

    #[error("manifest decoding error: {0}")]
    BadManifest(std::str::Utf8Error),

    #[error("can't find header to locate caboose (sought magic: {0:#x?})")]
    MissingMagic([u32; 2]),

    #[error("caboose is not present in this image")]
    MissingCaboose,

    #[error("bad caboose magic number: expected {0:#x}, got {1:#x}")]
    BadCabooseMagic(u32, u32),

    #[error("data is too large ({0:#x}) for caboose ({1:#x})")]
    OversizedData(usize, usize),

    #[error("address range {0:#x?} is not available")]
    BadAddress(std::ops::Range<u32>),

    #[error("{0}: record address range {1:#x?} overlaps {2:#x}")]
    MemoryRangeOverlap(String, std::ops::Range<u32>, u32),

    #[error("bad TOML file: {0}")]
    BadToml(toml::de::Error),

    #[error("wrong type for entry in TOML file")]
    BadTomlType,

    #[error("duplicate filename in zip archive: {0}")]
    DuplicateFilename(String),

    #[error("object error: {0}")]
    ObjectError(#[from] object::Error),

    #[error("this is not an ELF file: {0:?}")]
    NotAnElf(object::BinaryFormat),

    #[error("memory segments are overlapping")]
    MemorySegmentOverlap,

    #[error(
        "caboose is not located at the end of the image; \
         you may need to unsign the image first"
    )]
    BadCabooseLocation,

    #[error("LPC55 support error: {0}")]
    Lpc55(#[from] lpc55_sign::Error),

    #[error("wrong chip: expected lpc55, got {0}")]
    WrongChip(String),

    #[error("cannot overwrite an in-memory archive")]
    CannotOverwriteInMemoryArchive,

    #[error("Could not create a CMPA region")]
    BadCMPA,

    #[error("Could not create a CFPA region")]
    BadCFPA,

    #[error("Bad signature length")]
    BadSignatureLength,

    #[error("Missing certificates for LPC55 signing")]
    MissingCerts,

    #[error(".header section is too small")]
    HeaderTooSmall,

    #[error("Missing .header section")]
    MissingHeader,

    #[error("Bad file range for .header")]
    BadFileRange,

    #[error("Bad prefix")]
    BadPrefix,
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveSource {
    Memory,
    Disk(PathBuf),
}

/// Minimal Hubris archive, useful for some basic manipulation of the binary
/// image within.
#[derive(Debug)]
pub struct RawHubrisArchive {
    /// Source of the Hubris archive
    pub source: ArchiveSource,

    /// New files to be inserted into the zip archive when `overwrite` is called
    new_files: BTreeMap<String, Vec<u8>>,

    /// Raw data of the Hubris archive zip file
    ///
    /// Note that this may diverge from the data stored below as we edit it;
    /// call `overwrite` to write it back to disk.
    pub zip: Vec<u8>,

    /// Raw data from the image
    pub image: RawHubrisImage,
}

impl RawHubrisArchive {
    pub fn from_vec(contents: Vec<u8>) -> Result<Self, Error> {
        Self::new(contents, ArchiveSource::Memory)
    }

    pub fn load<P: AsRef<Path> + std::fmt::Debug + Copy>(
        filename: P,
    ) -> Result<Self, Error> {
        let contents = std::fs::read(filename).map_err(|e| {
            Error::FileReadFailed(filename.as_ref().to_owned(), e)
        })?;
        let source = ArchiveSource::Disk(filename.as_ref().to_owned());
        Self::new(contents, source)
    }

    fn new(contents: Vec<u8>, source: ArchiveSource) -> Result<Self, Error> {
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

        let image = {
            const ELF_FILE: &str = "img/final.elf";
            let mut file = archive
                .by_name(ELF_FILE)
                .map_err(|e| Error::MissingFile(e, ELF_FILE.to_string()))?;
            let mut elf = vec![];
            file.read_to_end(&mut elf).map_err(Error::FileReadError)?;
            RawHubrisImage::from_elf(&elf)?
        };

        Ok(Self {
            source,
            zip: contents,
            new_files: BTreeMap::new(),
            image,
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

    /// Reads the caboose from local memory
    pub fn read_caboose(&self) -> Result<Caboose, Error> {
        // Skip the start and end word, which are markers
        let caboose_range = self.image.caboose_range()?;
        let mut out = vec![0u8; caboose_range.len()];
        self.image.read(caboose_range.start, out.as_mut_slice())?;
        Ok(Caboose::new(out))
    }

    /// Extract the name of the image from the ZIP archive
    pub fn image_name(&self) -> Result<String, Error> {
        let raw = self.extract_file("image-name")?;
        String::from_utf8(raw).map_err(Error::BadImageNameEncoding)
    }

    /// Extract the TLVC-encoded auxiliary image file from the ZIP archive
    pub fn auxiliary_image(&self) -> Result<Vec<u8>, Error> {
        self.extract_file("img/auxi.tlvc")
    }

    /// Extracts a file from the ZIP archive by name
    pub fn extract_file(&self, name: &str) -> Result<Vec<u8>, Error> {
        let cursor = Cursor::new(self.zip.as_slice());
        let mut archive =
            zip::ZipArchive::new(cursor).map_err(Error::ZipNewError)?;
        let mut file = archive
            .by_name(name)
            .map_err(|e| Error::MissingFile(e, name.to_string()))?;
        let mut buffer = vec![];
        file.read_to_end(&mut buffer)
            .map_err(Error::FileReadError)?;
        Ok(buffer)
    }

    /// Writes to the caboose in local memory
    ///
    /// [`overwrite`] must be called to write these changes back to disk.
    pub fn write_caboose(&mut self, data: &[u8]) -> Result<(), Error> {
        self.image.write_caboose(data)
    }

    /// Writes the given version (and nothing else) to the caboose
    pub fn write_version_to_caboose(
        &mut self,
        version: &str,
    ) -> Result<(), Error> {
        // Manually build the TLV-C data for the caboose
        let data = tlvc_text::Piece::Chunk(
            tlvc_text::Tag::new(caboose::tags::VERS),
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
            .ok_or(Error::BadTomlType)?
            .get("board")
            .ok_or(Error::BadTomlType)?
            .as_str()
            .ok_or(Error::BadTomlType)?
            .to_owned();
        let mut name = manifest
            .as_table()
            .ok_or(Error::BadTomlType)?
            .get("name")
            .ok_or(Error::BadTomlType)?
            .as_str()
            .ok_or(Error::BadTomlType)?
            .to_owned();

        // If this Hubris archive used our TOML inheritance system, then the
        // name could be overridded in the `patches.toml` file.
        if let Ok(patches) = self.extract_file("patches.toml") {
            let patches: toml::Value = toml::from_str(
                std::str::from_utf8(&patches).map_err(Error::BadManifest)?,
            )
            .map_err(Error::BadToml)?;

            if let Some(n) = patches
                .as_table()
                .and_then(|p| p.get("name"))
                .and_then(|p| p.as_str())
            {
                name = n.to_string();
            }
        }

        let mut chunks = vec![
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(caboose::tags::GITC),
                vec![tlvc_text::Piece::Bytes(git)],
            ),
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(caboose::tags::BORD),
                vec![tlvc_text::Piece::String(board)],
            ),
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(caboose::tags::NAME),
                vec![tlvc_text::Piece::String(name)],
            ),
        ];
        if let Some(v) = version {
            let data = tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(caboose::tags::VERS),
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
        let caboose_range = self.image.caboose_range()?;
        let end = caboose_range.end - self.image.start_addr;
        if end as usize != self.image.data.len() - 4 {
            return Err(Error::BadCabooseLocation);
        }
        let data = vec![0xFFu8; caboose_range.len()];
        self.image.write(caboose_range.start, data.as_slice())
    }

    /// Checks whether the caboose is empty in local memory
    pub fn is_caboose_empty(&self) -> Result<bool, Error> {
        let caboose = self.read_caboose()?;
        Ok(caboose.as_slice().iter().all(|&c| c == 0xFF))
    }

    /// Returns a `Vec<u8>` with our modifications
    /// Changes are only made to the `img/final.*` files, as well as anything
    /// listed in `self.new_files`.
    pub fn to_vec(mut self) -> Result<Vec<u8>, Error> {
        // Convert the SREC into all of our canonical file formats
        let elf = self.image.to_elf()?;
        self.add_file("img/final.elf", &elf)?;
        let data = self.image.to_binary()?;
        self.add_file("img/final.bin", &data)?;

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

        Ok(out_buf)
    }

    /// Overwrites the existing archive with our modifications
    /// Only supported if this archive was opened from an on-disk
    /// file via `RawHubrisArchive::load()`; not supported for
    /// in-memory archives.
    #[allow(unused_mut)]
    pub fn overwrite(mut self) -> Result<(), Error> {
        // Ensure our archive came from an on-disk source. We can't actually
        // extract the path here due to our mutation of `self` below, so we
        // check here and then extract it below when it's time to write.
        let path = match self.source {
            ArchiveSource::Disk(ref path) => path.clone(),
            // We checked above that our source was `::Disk(_)`.
            ArchiveSource::Memory => {
                return Err(Error::CannotOverwriteInMemoryArchive)
            }
        };

        let out_buf = self.to_vec()?;

        std::fs::write(&path, out_buf)
            .map_err(|e| Error::FileWriteFailed(path.to_path_buf(), e))?;
        Ok(())
    }

    /// Signs the given image with a chain of one-or-more certificates
    ///
    /// This modifies local data in memory; call `self.overwrite` to persist
    /// changes back to the archive on disk.
    pub fn sign(
        &mut self,
        signing_certs: Vec<Certificate>,
        root_certs: Vec<Certificate>,
        private_key: &rsa::RsaPrivateKey,
        execution_address: u32,
    ) -> Result<(), Error> {
        self.is_lpc55()?;

        self.image.sign(
            signing_certs,
            root_certs,
            private_key,
            execution_address,
        )
    }

    fn is_lpc55(&self) -> Result<(), Error> {
        let manifest = self.extract_file("app.toml")?;
        let manifest: toml::Value = toml::from_str(
            std::str::from_utf8(&manifest).map_err(Error::BadManifest)?,
        )
        .map_err(Error::BadToml)?;
        let chip = manifest
            .as_table()
            .ok_or(Error::BadTomlType)?
            .get("chip")
            .ok_or(Error::BadTomlType)?
            .as_str()
            .ok_or(Error::BadTomlType)?
            .to_owned();

        if !chip.contains("lpc55") {
            Err(Error::WrongChip(chip))
        } else {
            Ok(())
        }
    }

    /// Unsign the image and re-stamp for signing, including an updated
    /// version for the caboose
    pub fn restamp(
        &mut self,
        root_certs: Vec<Certificate>,
        signing_certs: Vec<Certificate>,
        version: Option<&String>,
    ) -> Result<Vec<u8>, Error> {
        match self.is_lpc55() {
            Ok(_) => {
                let _ = self.unsign();
                // Need to write the caboose _after_ we unsign
                self.write_default_caboose(version)?;
                let stamped = lpc55_sign::signed_image::stamp_image(
                    self.image.data.clone(),
                    signing_certs,
                    root_certs,
                    0,
                )?;
                Ok(stamped)
            }
            Err(_) => {
                self.write_default_caboose(version)?;
                // Not an LPC55 image, just return the image back for now
                self.image.to_binary()
            }
        }
    }

    /// Add a signature to a binary
    pub fn append_signature(&mut self, sig: &[u8]) -> Result<(), Error> {
        match self.is_lpc55() {
            Ok(_) => {
                let mut b = self.image.to_binary()?;
                b.extend_from_slice(sig);
                self.replace(b);
                Ok(())
            }
            Err(_) => {
                // Save the signature as signature.txt for now until we
                // figure out what to do with it
                self.add_file("signature.txt", sig)?;
                Ok(())
            }
        }
    }

    /// Strips any existing signature from the image.
    pub fn unsign(&mut self) -> Result<(), Error> {
        self.is_lpc55()?;
        self.image.unsign()
    }

    /// Replaces the image with a binary equivalent from somewhere else.
    ///
    /// This is intended for use when inserting an image that has been
    /// externally signed.
    ///
    /// This modifies local data in memory; call `self.overwrite` to persist
    /// changes back to the archive on disk.
    pub fn replace(&mut self, data: Vec<u8>) {
        self.image.replace(data);
    }

    pub fn verify(
        &self,
        cmpa_bytes: &[u8; 512],
        cfpa_bytes: &[u8; 512],
    ) -> Result<(), Error> {
        let cmpa = lpc55_areas::CMPAPage::from_bytes(cmpa_bytes)
            .map_err(|_| Error::BadCMPA)?;

        let cfpa = lpc55_areas::CFPAPage::from_bytes(cfpa_bytes)
            .map_err(|_| Error::BadCFPA)?;

        lpc55_sign::verify::verify_image(&self.image.data, cmpa, cfpa)
            .map_err(Error::Lpc55)?;
        Ok(())
    }
}

mod header {
    use zerocopy::{AsBytes, FromBytes};

    // Defined in the kernel ABI crate - we support both the original and
    // new-style magic numbers, which use the same header layout.
    pub(crate) const MAGIC: [u32; 2] = [0x15356637, 0x64_CE_D6_CA];

    #[derive(Default, AsBytes, FromBytes)]
    #[repr(C)]
    pub(crate) struct ImageHeader {
        pub magic: u32,
        pub total_image_len: u32,
    }

    // The header is located in one of a few locations, depending on MCU
    // and versions of the PAC crates.
    //
    // - 0xbc and 0xc0 are possible values for the STM32G0
    // - 0x298 is for the STM32H7
    // - 0x130 is for the LPC55
    pub(crate) const POSSIBLE_OFFSETS: [u32; 4] = [0xbc, 0xc0, 0x130, 0x298];
}
