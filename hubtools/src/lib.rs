// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use digest::{Digest, FixedOutput};
use object::{Object, ObjectSection, ObjectSegment};
use path_slash::PathBufExt;
use thiserror::Error;
use x509_cert::Certificate;
use zerocopy::{AsBytes, FromBytes};

use std::{
    collections::{btree_map::Entry, BTreeMap},
    io::{Cursor, Read, Write},
    ops::Range,
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
            // Before writing new data, fill the entire caboose data area with 0xFF
            // to simulate erased flash and avoid remnants of old data.
            let full_caboose_data_len = caboose_range.len();
            let padding = vec![0xFFu8; full_caboose_data_len];
            self.write(caboose_range.start, padding.as_bytes())?; // Fill with 0xFF
            self.write(caboose_range.start, data) // Write new data
        }
    }

    /// Reads the caboose from local memory
    pub fn read_caboose(&self) -> Result<Caboose, Error> {
        // Skip the start and end word, which are markers
        let caboose_range = self.caboose_range()?;
        let mut out = vec![0u8; caboose_range.len()];
        self.read(caboose_range.start, out.as_mut_slice())?;
        Ok(Caboose::new(out))
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

    #[error("TLVC: {0}")]
    Tlvc(String),

    #[error("packing error: {0}")]
    PackingError(String),

    #[error("Unsupported chip type: {0}")]
    UnsupportedChip(String),

    #[error("No memory range with name: {0}")]
    NoMemoryRange(String),

    #[error("memory.toml decoding error: {0}")]
    BadMemory(std::str::Utf8Error),

    #[error("Failed to convert TOML int to u32: {0}")]
    BadInt(std::num::TryFromIntError),

    #[error("invalid caboose entry")]
    InvalidCabooseEntry(String),
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
        self.image.read_caboose()
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

    /// Extract manufacturing configuration file (currently just CMPA/CFPA)
    pub fn manufacturing_cfg(&self) -> Result<Vec<u8>, Error> {
        self.extract_file("build_cfg/mfg_cfg.toml")
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

    /// Generates a default caboose
    ///
    /// The default caboose includes the following tags:
    /// - `GITC`: the current Git commit with an optional trailing "-dirty"
    ///     - taken from archive file `git-rev`
    /// - `NAME`: image name
    ///     - value of `name` in files used to compose the `app.toml`
    /// - `BORD`: board name
    ///     - value of `board` in files used to compose the `app.toml`
    /// - `VERS`: the provided version string (if present)
    ///     - provided by the caller.
    ///
    /// Everything except `VERS` are extracted from the Hubris archive itself.
    fn generate_default_caboose(
        &mut self,
        version: Option<&String>,
    ) -> Result<Vec<tlvc_text::Piece>, Error> {
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
        Ok(chunks)
    }

    pub fn write_default_caboose(
        &mut self,
        version: Option<&String>,
    ) -> Result<(), Error> {
        let out = tlvc_text::pack(&self.generate_default_caboose(version)?);
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
        let chip = Chip::try_from(self)?;

        if chip == Chip::Lpc55 {
            Ok(())
        } else {
            Err(Error::WrongChip(chip.to_string()))
        }
    }

    fn delete_tag(caboose: &mut Vec<tlvc_text::Piece>, tag: [u8; 4]) {
        let tag = tlvc_text::Tag::new(tag);
        caboose.retain(|piece| match piece {
            tlvc_text::Piece::Chunk(entry_tag, _) => *entry_tag != tag,
            tlvc_text::Piece::Bytes(_) | tlvc_text::Piece::String(_) => true,
        });
    }

    /// Prepare an image for signing.
    ///
    /// This is typically called to prepare a Hubris or RoT bootloader
    /// (stage0/Bootleby) artifact for the signing server, specifically to set
    /// an official release version and to set the SIGN tag indicating which
    /// key set will be used for signing.
    ///
    /// Existing caboose tags are preserved. Only specific tags are modified:
    ///
    /// - **VERS**: Updated if `version` is provided; otherwise preserved as-is
    /// - **SIGN**: For LPC55 images, always set to the root key table hash
    ///
    /// If the caboose is empty or unreadable, a default caboose is generated
    /// from archive metadata (`git-rev`, `app.toml`, `patches.toml`).
    ///
    /// # Returns
    ///
    /// - For LPC55: The image data stamped with certificate headers, ready
    ///   to be signed
    /// - For other chips: The raw image binary with updated caboose
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The caboose exists but is corrupt ([`Error::InvalidCabooseEntry`])
    /// - Required archive files are missing when generating a default caboose
    /// - LPC55 certificate processing fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hubtools::RawHubrisArchive;
    ///
    /// fn example(
    ///     root_certs: Vec<x509_cert::Certificate>,
    ///     signing_certs: Vec<x509_cert::Certificate>,
    /// ) -> Result<(), hubtools::Error> {
    ///     let mut archive = RawHubrisArchive::load("my-image.zip")?;
    ///     let version = "1.2.3".to_string();
    ///     let stamped = archive.restamp(root_certs, signing_certs, Some(&version))?;
    ///     // For LPC55: `stamped` is ready to be signed
    ///     // For other chips: `stamped` is the final image with updated caboose
    ///     Ok(())
    /// }
    /// ```
    pub fn restamp(
        &mut self,
        root_certs: Vec<Certificate>,
        signing_certs: Vec<Certificate>,
        version: Option<&String>,
    ) -> Result<Vec<u8>, Error> {
        use crate::caboose::tags::{SIGN, VERS};

        let mut caboose = match self.read_caboose() {
            Err(_) => self.generate_default_caboose(version)?,
            Ok(existing) => {
                let is_empty = existing.is_empty().unwrap_or(false);
                if is_empty {
                    self.generate_default_caboose(version)?
                } else {
                    let mut chunks = Vec::new();
                    for item_result in existing.iter().map_err(|e| {
                        Error::InvalidCabooseEntry(e.to_string())
                    })? {
                        match item_result {
                            Ok((tag, data)) => {
                                chunks.push(tlvc_text::Piece::Chunk(
                                    tlvc_text::Tag::new(tag),
                                    vec![tlvc_text::Piece::Bytes(
                                        data.to_vec(),
                                    )],
                                ));
                            }
                            Err(e) => {
                                return Err(Error::InvalidCabooseEntry(
                                    e.to_string(),
                                ));
                            }
                        }
                    }
                    if let Some(vers) = version {
                        Self::delete_tag(&mut chunks, VERS);
                        chunks.push(tlvc_text::Piece::Chunk(
                            tlvc_text::Tag::new(VERS),
                            vec![tlvc_text::Piece::String(vers.clone())],
                        ));
                    }
                    chunks
                }
            }
        };

        match self.is_lpc55() {
            Ok(_) => {
                // Remove any existing signature. Ignore errors because the
                // image may not be signed yet, which is the common case.
                let _ = self.unsign();
                self.erase_caboose()?;
                // Need to write the caboose _after_ we unsign

                let rkth = lpc55_sign::signed_image::root_key_table_hash(
                    &lpc55_sign::signed_image::pad_roots(root_certs.clone())?,
                )?;

                if let Ok(cfile) = self.manufacturing_cfg() {
                    let cfg: lpc55_sign::signed_image::MfgCfg = toml::from_str(
                        std::str::from_utf8(&cfile)
                            .map_err(Error::BadManifest)?,
                    )
                    .map_err(Error::BadToml)?;

                    let mut cfpa = cfg.cfpa.generate()?;
                    // We don't lock right now
                    let mut cmpa = cfg.cmpa.generate(false, rkth)?;
                    self.add_file(
                        "cmpa.bin",
                        &cmpa.to_vec().map_err(|e| {
                            Error::PackingError(format!("{:?}", e))
                        })?,
                    )?;
                    self.add_file(
                        "cfpa.bin",
                        &cfpa.to_vec().map_err(|e| {
                            Error::PackingError(format!("{:?}", e))
                        })?,
                    )?;
                }

                Self::delete_tag(&mut caboose, SIGN);

                caboose.push(tlvc_text::Piece::Chunk(
                    tlvc_text::Tag::new(SIGN),
                    vec![tlvc_text::Piece::String(hex::encode(rkth))],
                ));

                let out_packed = tlvc_text::pack(&caboose);
                self.write_caboose(&out_packed)?;

                let stamped = lpc55_sign::signed_image::stamp_image(
                    self.image.data.clone(),
                    signing_certs,
                    root_certs,
                    0, // execution_address for stamp_image
                )?;
                Ok(stamped)
            }
            Err(_) => {
                // Not LPC55
                let out_packed = tlvc_text::pack(&caboose);
                self.write_caboose(&out_packed)?;
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

        lpc55_sign::verify::verify_image(&self.image.data, cmpa, cfpa)?;
        Ok(())
    }
    //
    // Return a Range describing the named flash range from memory.toml).
    pub fn get_flash_range(&self, name: &str) -> Result<Range<u32>, Error> {
        let memory = self.extract_file("memory.toml")?;
        let memory: toml::Value = toml::from_str(
            std::str::from_utf8(&memory).map_err(Error::BadMemory)?,
        )
        .map_err(Error::BadToml)?;

        // this may be easier w/ a derive macro for TOML -> Rust types / instances
        for value in memory
            .as_table()
            .ok_or(Error::BadTomlType)?
            .get("flash")
            .ok_or(Error::BadTomlType)?
            .as_array()
            .ok_or(Error::BadTomlType)?
        {
            let name_toml = value
                .get("name")
                .ok_or(Error::BadTomlType)?
                .as_str()
                .ok_or(Error::BadTomlType)?;

            if name == name_toml {
                let start: u32 = value
                    .get("address")
                    .ok_or(Error::BadTomlType)?
                    .as_integer()
                    .ok_or(Error::BadTomlType)?
                    .try_into()
                    .map_err(Error::BadInt)?;
                let size: u32 = value
                    .get("size")
                    .ok_or(Error::BadTomlType)?
                    .as_integer()
                    .ok_or(Error::BadTomlType)?
                    .try_into()
                    .map_err(Error::BadInt)?;
                let end = start + size;

                return Ok(Range { start, end });
            }
        }

        Err(Error::NoMemoryRange(name.to_string()))
    }
}

pub const LPC55_FLASH_PAGE_SIZE: usize = 512;

pub trait FwidGen<D: Default + Digest + FixedOutput> {
    fn fwid(&self) -> Result<Vec<u8>, Error>;
}

impl<D: Default + Digest + FixedOutput> FwidGen<D> for RawHubrisArchive {
    fn fwid(&self) -> Result<Vec<u8>, Error> {
        let image = self.image.to_binary()?;
        // When calculating the FWID value we aim to capture *all* data from the
        // relevant flash region. The hubris image will reside in one contiguous
        // range identical to the image from the archive however all flash pages
        // within the remaining flash region must be represented in the FWID as
        // well. We do this to ensure flash pages not used by the hubris image
        // are in the expected state. Doing this here requires that we accomodate
        // some chip-specific quirks here:
        let pad = match Chip::try_from(self)? {
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
            }
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
                let name = self.image_name()?;
                let flash = self.get_flash_range(&name)?;

                flash.end as usize - flash.start as usize - image.len()
            }
        };

        let mut digest = D::default();
        Digest::update(&mut digest, &image);
        Digest::update(&mut digest, vec![0xff; pad]);

        Ok(digest.finalize().to_vec())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Chip {
    Lpc55,
    Stm32,
}

impl TryFrom<&RawHubrisArchive> for Chip {
    type Error = Error;

    fn try_from(archive: &RawHubrisArchive) -> Result<Self, Error> {
        let manifest_bytes = archive.extract_file("app.toml")?;
        let manifest_str =
            std::str::from_utf8(&manifest_bytes).map_err(Error::BadManifest)?;
        let manifest: toml::Value =
            toml::from_str(manifest_str).map_err(Error::BadToml)?;

        let chip_str = manifest
            .get("chip")
            .and_then(toml::Value::as_str)
            .ok_or(Error::BadTomlType)?;

        if chip_str.contains("lpc55") {
            Ok(Chip::Lpc55)
        } else if chip_str.contains("stm32") {
            Ok(Chip::Stm32)
        } else {
            Err(Error::WrongChip(chip_str.to_string()))
        }
    }
}

impl std::fmt::Display for Chip {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Chip::Lpc55 => write!(f, "lpc55"),
            Chip::Stm32 => write!(f, "stm32"),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Write;
    use x509_cert::der::Decode;
    use zerocopy::AsBytes;
    use zip::{write::FileOptions, ZipWriter};

    const MOCK_START_ADDR: u32 = 0x1000;
    const MOCK_KENTRY: u32 = 0x10F0;
    const MOCK_HEADER_OFFSET: u32 = header::POSSIBLE_OFFSETS[0];
    const MOCK_CABOOSE_TOTAL_SIZE: u32 = 256;

    fn create_mock_image_data(
        initial_caboose_tlvc: Option<&[u8]>,
        caboose_total_size_override: Option<u32>,
    ) -> Vec<u8> {
        let mut data = vec![0xFFu8; 2048];
        let caboose_total_size =
            caboose_total_size_override.unwrap_or(MOCK_CABOOSE_TOTAL_SIZE);
        let caboose_data_area_size = caboose_total_size.saturating_sub(8);

        let kentry_offset = MOCK_KENTRY
            .checked_sub(MOCK_START_ADDR)
            .expect("Kentry must be >= start_addr");
        assert!(
            (kentry_offset as usize) < data.len(),
            "Kentry out of bounds for mock image data"
        );

        let header_abs_addr = MOCK_START_ADDR + MOCK_HEADER_OFFSET;
        let header_rel_addr = (header_abs_addr - MOCK_START_ADDR) as usize;

        assert!(
            header_rel_addr + std::mem::size_of::<header::ImageHeader>()
                <= data.len(),
            "Header out of bounds"
        );

        let img_header = header::ImageHeader {
            magic: header::MAGIC[0],
            total_image_len: data.len() as u32,
        };
        data[header_rel_addr
            ..header_rel_addr + std::mem::size_of::<header::ImageHeader>()]
            .copy_from_slice(img_header.as_bytes());

        assert!(
            caboose_total_size as usize <= data.len(),
            "Caboose total size override too large for image data"
        );

        let caboose_magic_word_offset =
            data.len() - caboose_total_size as usize;
        let caboose_data_start_offset = caboose_magic_word_offset + 4;
        let caboose_size_word_offset = data.len() - 4;

        data[caboose_magic_word_offset..caboose_magic_word_offset + 4]
            .copy_from_slice(&CABOOSE_MAGIC.to_le_bytes());
        data[caboose_size_word_offset..caboose_size_word_offset + 4]
            .copy_from_slice(&caboose_total_size.to_le_bytes());

        if let Some(content) = initial_caboose_tlvc {
            if caboose_data_area_size > 0 {
                assert!(content.len() <= caboose_data_area_size as usize,
                    "Caboose content (len={}) too large for mock area (size={})",
                    content.len(), caboose_data_area_size);
                if !content.is_empty() {
                    data[caboose_data_start_offset
                        ..caboose_data_start_offset + content.len()]
                        .copy_from_slice(content);
                }
            } else if !content.is_empty() {
                panic!("Caboose content provided but data area size is zero");
            }
        }
        data
    }

    fn create_mock_raw_hubris_image_with_specific_caboose_size(
        initial_caboose_tlvc: Option<&[u8]>,
        caboose_total_size: u32,
    ) -> RawHubrisImage {
        RawHubrisImage {
            start_addr: MOCK_START_ADDR,
            data: create_mock_image_data(
                initial_caboose_tlvc,
                Some(caboose_total_size),
            ),
            kentry: MOCK_KENTRY,
        }
    }

    fn create_mock_raw_hubris_image(
        initial_caboose_tlvc: Option<&[u8]>,
    ) -> RawHubrisImage {
        RawHubrisImage {
            start_addr: MOCK_START_ADDR,
            data: create_mock_image_data(initial_caboose_tlvc, None),
            kentry: MOCK_KENTRY,
        }
    }

    fn dummy_certs() -> Vec<Certificate> {
        let der_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/fake_certificate.der"
        ));
        vec![Certificate::from_der(der_bytes)
            .expect("Failed to parse dummy DER certificate from file")]
    }

    fn minimal_valid_packed_tlvc_for_init() -> Vec<u8> {
        tlvc_text::pack(&[tlvc_text::Piece::Chunk(
            tlvc_text::Tag::new(*b"INIT"),
            vec![tlvc_text::Piece::Bytes(vec![0x00, 0x01, 0x02, 0x03])],
        )])
    }

    fn empty_packed_caboose() -> Vec<u8> {
        tlvc_text::pack(&[])
    }

    fn dummy_mfg_toml_content_from_example() -> &'static str {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/stage0-bart-build_cfg-mfg_cfg.toml"
        ))
    }

    fn create_mock_archive_configurable(
        chip_name_str: &str,
        initial_image_caboose_tlvc: Option<&[u8]>,
        mfg_cfg_content: Option<&str>,
        app_toml_content_custom: Option<String>,
        patches_toml_content: Option<String>,
        git_rev_content: Option<&str>,
        image_name_content: Option<&str>,
        memory_toml_content: Option<&str>,
        caboose_total_size_override: Option<u32>,
    ) -> Result<RawHubrisArchive, Error> {
        let mut zip_buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut zip_buf));
            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            let raw_image = if let Some(cts) = caboose_total_size_override {
                create_mock_raw_hubris_image_with_specific_caboose_size(
                    initial_image_caboose_tlvc,
                    cts,
                )
            } else {
                create_mock_raw_hubris_image(initial_image_caboose_tlvc)
            };
            let elf_data =
                raw_image.to_elf().expect("Failed to create mock ELF");
            zip.start_file("img/final.elf", options).unwrap();
            zip.write_all(&elf_data).unwrap();

            let default_app_toml_string_holder;
            let app_toml_to_write_ref: &str = match &app_toml_content_custom {
                Some(custom_toml) => custom_toml.as_str(),
                None => {
                    default_app_toml_string_holder = format!(
                        "chip = \"{}\"\nboard = \"test_board\"\nname = \"default_app_name\"",
                        chip_name_str
                    );
                    &default_app_toml_string_holder
                }
            };
            zip.start_file("app.toml", options).unwrap();
            zip.write_all(app_toml_to_write_ref.as_bytes()).unwrap();

            if let Some(patches) = &patches_toml_content {
                zip.start_file("patches.toml", options).unwrap();
                zip.write_all(patches.as_bytes()).unwrap();
            }

            zip.start_file("git-rev", options).unwrap();
            zip.write_all(
                git_rev_content.unwrap_or("mock_git_rev_123").as_bytes(),
            )
            .unwrap();

            zip.start_file("image-name", options).unwrap();
            zip.write_all(
                image_name_content.unwrap_or("test_image_name").as_bytes(),
            )
            .unwrap();

            if let Some(mem_toml) = memory_toml_content {
                zip.start_file("memory.toml", options).unwrap();
                zip.write_all(mem_toml.as_bytes()).unwrap();
            } else if chip_name_str.contains("stm32") {
                let app_name_for_mem_toml =
                    toml::from_str::<toml::Value>(app_toml_to_write_ref)
                        .ok()
                        .and_then(|v| {
                            v.get("name")
                                .and_then(|n| n.as_str().map(String::from))
                        })
                        .unwrap_or_else(|| "default_app_name".to_string());

                let mem_toml_default = format!(
                    "[[flash]]\nname=\"{}\"\naddress=0x08000000\nsize=0x20000\n",
                    app_name_for_mem_toml 
                );
                zip.start_file("memory.toml", options).unwrap();
                zip.write_all(mem_toml_default.as_bytes()).unwrap();
            }

            if let Some(mfg_content_str) = mfg_cfg_content {
                zip.start_file("build_cfg/mfg_cfg.toml", options).unwrap();
                zip.write_all(mfg_content_str.as_bytes()).unwrap();
            }

            zip.set_comment("hubris build archive v1");
            zip.finish().unwrap();
        }
        RawHubrisArchive::from_vec(zip_buf)
    }

    fn create_mock_archive(
        chip_name_str: &str,
        initial_image_caboose_tlvc: Option<&[u8]>,
        mfg_cfg_content: Option<&str>,
        app_toml_name_override: Option<&str>,
        patches_toml_name: Option<&str>,
    ) -> Result<RawHubrisArchive, Error> {
        let app_toml_string_content = Some(format!(
            "chip = \"{}\"\nboard = \"test_board\"\nname = \"{}\"",
            chip_name_str,
            app_toml_name_override.unwrap_or("default_app_name")
        ));
        let patches_toml_string_content = patches_toml_name
            .map(|name_val| format!("name = \"{}\"", name_val));

        create_mock_archive_configurable(
            chip_name_str,
            initial_image_caboose_tlvc,
            mfg_cfg_content,
            app_toml_string_content,
            patches_toml_string_content,
            None,
            None,
            None,
            None,
        )
    }

    fn get_caboose_items_from_image(
        image: &RawHubrisImage,
    ) -> Result<BTreeMap<[u8; 4], String>, String> {
        let caboose_object = image
            .read_caboose()
            .map_err(|e| format!("Image::read_caboose failed: {:?}", e))?;
        let mut items = BTreeMap::new();

        let caboose_iterator = caboose_object
            .iter()
            .map_err(|e| format!("Caboose::iter() setup failed: {:?}", e))?;

        for entry_result in caboose_iterator {
            match entry_result {
                Ok((tag_array, value_bytes)) => {
                    let value_str = String::from_utf8(value_bytes.to_vec())
                        .unwrap_or_else(|_| hex::encode(value_bytes));
                    items.insert(tag_array, value_str);
                }
                Err(e) => {
                    return Err(format!(
                        "Error iterating caboose entry: {:?}",
                        e
                    ));
                }
            }
        }
        Ok(items)
    }

    #[test]
    fn test_caboose_iterator_step_by_step() {
        let caboose = CabooseBuilder::default()
            .name("TestApp")
            .version("1.0.0")
            .git_commit("abcdef")
            .board("TestBoard")
            .build();

        let mut caboose_iterator = caboose
            .iter()
            .expect("Caboose::iter() for builder-created caboose");

        match caboose_iterator.next() {
            Some(Ok((tag, value))) => {
                assert_eq!(tag, caboose::tags::GITC);
                assert_eq!(value, b"abcdef");
            }
            other => panic!("Expected GITC, got {:?}", other),
        }
        match caboose_iterator.next() {
            Some(Ok((tag, value))) => {
                assert_eq!(tag, caboose::tags::BORD);
                assert_eq!(value, b"TestBoard");
            }
            other => panic!("Expected BORD, got {:?}", other),
        }
        match caboose_iterator.next() {
            Some(Ok((tag, value))) => {
                assert_eq!(tag, caboose::tags::NAME);
                assert_eq!(value, b"TestApp");
            }
            other => panic!("Expected NAME, got {:?}", other),
        }
        match caboose_iterator.next() {
            Some(Ok((tag, value))) => {
                assert_eq!(tag, caboose::tags::VERS);
                assert_eq!(value, b"1.0.0");
            }
            other => panic!("Expected VERS, got {:?}", other),
        }
        assert!(caboose_iterator.next().is_none(), "Expected end");
        assert!(caboose_iterator.next().is_none(), "Subsequent end");
    }

    #[test]
    fn test_default_caboose_integrity_non_lpc55() {
        let init_caboose = minimal_valid_packed_tlvc_for_init();
        let mut archive = create_mock_archive(
            "stm32h7",
            Some(&init_caboose),
            None,
            Some("testapp"),
            None,
        )
        .unwrap();

        let version_string = "1.2.3-test".to_string();
        let version: Option<&String> = Some(&version_string);

        let pieces = archive
            .generate_default_caboose(version)
            .expect("generate_default_caboose should succeed");

        let packed_bytes = tlvc_text::pack(&pieces);
        assert!(!packed_bytes.is_empty(), "Packed caboose is empty");

        if packed_bytes.len() >= std::mem::size_of::<tlvc::ChunkHeader>() {
            let header_data =
                &packed_bytes[0..std::mem::size_of::<tlvc::ChunkHeader>()];
            let parsed_header = tlvc::ChunkHeader::read_from(header_data)
                .expect("Read ChunkHeader from packed_bytes prefix");

            assert_eq!(
                parsed_header.header_checksum.get(),
                parsed_header.compute_checksum(),
                "Header checksum error. Stored: {:#010x}, Computed: {:#010x}",
                parsed_header.header_checksum.get(),
                parsed_header.compute_checksum()
            );
        } else {
            panic!("Packed caboose too short for ChunkHeader.");
        }

        let test_caboose_obj = Caboose::new(packed_bytes.clone());
        let iterator = test_caboose_obj
            .iter()
            .expect("Caboose::iter() if header checksums correct");

        let mut items_found = 0;
        for item_res in iterator {
            item_res.unwrap_or_else(|e| {
                panic!("Item in default caboose not Ok. Error: {:?}", e)
            });
            items_found += 1;
        }
        let expected_items = 3 + if version.is_some() { 1 } else { 0 };
        assert_eq!(items_found, expected_items, "Item count mismatch");
    }

    // --- Tests for restamp ---

    #[test]
    fn restamp_non_lpc55_with_empty_caboose_generates_default() {
        let empty_caboose_bytes = empty_packed_caboose();
        let mut archive = create_mock_archive(
            "stm32h7",
            Some(&empty_caboose_bytes),
            None,
            Some("app_default"),
            None,
        )
        .unwrap();
        let version_str = "7.8.9".to_string();

        archive
            .restamp(dummy_certs(), dummy_certs(), Some(&version_str))
            .unwrap();

        let caboose_items =
            get_caboose_items_from_image(&archive.image).unwrap();
        assert_eq!(
            caboose_items.get(&caboose::tags::NAME).unwrap(),
            "app_default"
        );
        assert_eq!(
            caboose_items.get(&caboose::tags::BORD).unwrap(),
            "test_board"
        );
        assert_eq!(
            *caboose_items.get(&caboose::tags::GITC).unwrap(),
            "mock_git_rev_123"
        );
        assert_eq!(caboose_items.get(&caboose::tags::VERS).unwrap(), "7.8.9");
        assert!(!caboose_items.contains_key(&caboose::tags::SIGN));
    }

    #[test]
    fn restamp_non_lpc55_preserves_existing_tags_and_updates_version() {
        let initial_tlvc_pieces = vec![
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(*b"FOO "),
                vec![tlvc_text::Piece::String("bar".to_string())],
            ),
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(caboose::tags::NAME),
                vec![tlvc_text::Piece::String("OldName".to_string())],
            ),
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(caboose::tags::VERS),
                vec![tlvc_text::Piece::String("0.1.0".to_string())],
            ),
        ];
        let initial_caboose_data = tlvc_text::pack(&initial_tlvc_pieces);
        let mut archive = create_mock_archive(
            "stm32h7",
            Some(&initial_caboose_data),
            None,
            Some("app_toml_name"),
            None,
        )
        .unwrap();

        let new_version_str = "1.0.0-new".to_string();
        archive
            .restamp(dummy_certs(), dummy_certs(), Some(&new_version_str))
            .unwrap();

        let caboose_items =
            get_caboose_items_from_image(&archive.image).unwrap();
        // Custom tag preserved
        assert_eq!(caboose_items.get(b"FOO ").unwrap(), "bar");
        // Original NAME preserved (not overwritten from app.toml)
        assert_eq!(caboose_items.get(&caboose::tags::NAME).unwrap(), "OldName");
        // VERS updated
        assert_eq!(
            caboose_items.get(&caboose::tags::VERS).unwrap(),
            "1.0.0-new"
        );
        // BORD was not in original, so not present
        assert!(!caboose_items.contains_key(&caboose::tags::BORD));
    }

    #[test]
    fn restamp_lpc55_preserves_tags_updates_version_and_adds_sign() {
        let initial_tlvc_pieces = vec![
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(*b"BAR "),
                vec![tlvc_text::Piece::String("baz".to_string())],
            ),
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(caboose::tags::VERS),
                vec![tlvc_text::Piece::String("0.5.0".to_string())],
            ),
        ];
        let initial_caboose_data = tlvc_text::pack(&initial_tlvc_pieces);
        let mfg_toml_content_str = dummy_mfg_toml_content_from_example();

        let mut archive = create_mock_archive(
            "lpc55s69",
            Some(&initial_caboose_data),
            Some(mfg_toml_content_str),
            Some("lpc_preserve_app"),
            None,
        )
        .unwrap();

        let new_version_str = "0.6.0-lpc".to_string();
        let certs = dummy_certs();
        archive
            .restamp(certs.clone(), certs, Some(&new_version_str))
            .unwrap();

        let caboose_items =
            get_caboose_items_from_image(&archive.image).unwrap();
        // Custom tag preserved
        assert_eq!(caboose_items.get(b"BAR ").unwrap(), "baz");
        // VERS updated
        assert_eq!(
            caboose_items.get(&caboose::tags::VERS).unwrap(),
            "0.6.0-lpc"
        );
        // SIGN added for LPC55
        assert!(caboose_items.contains_key(&caboose::tags::SIGN));

        // These were not in original caboose, so not present
        assert!(!caboose_items.contains_key(&caboose::tags::NAME));
        assert!(!caboose_items.contains_key(&caboose::tags::BORD));
        assert!(!caboose_items.contains_key(&caboose::tags::GITC));

        assert!(archive.new_files.contains_key("cmpa.bin"));
        assert!(archive.new_files.contains_key("cfpa.bin"));
    }

    #[test]
    fn restamp_lpc55_empty_caboose_generates_default_with_sign() {
        let empty_caboose_bytes = empty_packed_caboose();
        let mut archive = create_mock_archive(
            "lpc55s69",
            Some(&empty_caboose_bytes),
            None,
            Some("lpc_app"),
            None,
        )
        .unwrap();
        let version_str = "3.0.0-lpc".to_string();
        let certs = dummy_certs();

        archive
            .restamp(certs.clone(), certs, Some(&version_str))
            .unwrap();

        let caboose_items =
            get_caboose_items_from_image(&archive.image).unwrap();
        assert_eq!(caboose_items.get(&caboose::tags::NAME).unwrap(), "lpc_app");
        assert_eq!(
            caboose_items.get(&caboose::tags::BORD).unwrap(),
            "test_board"
        );
        assert_eq!(
            *caboose_items.get(&caboose::tags::GITC).unwrap(),
            "mock_git_rev_123"
        );
        assert_eq!(
            caboose_items.get(&caboose::tags::VERS).unwrap(),
            "3.0.0-lpc"
        );
        assert!(caboose_items.contains_key(&caboose::tags::SIGN));
    }

    #[test]
    fn restamp_lpc55_no_mfg_cfg_still_works() {
        let empty_caboose_bytes = empty_packed_caboose();
        let mut archive = create_mock_archive(
            "lpc55s69",
            Some(&empty_caboose_bytes),
            None,
            Some("lpc_app"),
            None,
        )
        .unwrap();
        let version_str = "2.0.0-lpc".to_string();
        let certs = dummy_certs();

        let stamped_binary = archive
            .restamp(certs.clone(), certs.clone(), Some(&version_str))
            .unwrap();

        assert_ne!(stamped_binary, archive.image.data);

        let caboose_items =
            get_caboose_items_from_image(&archive.image).unwrap();
        assert_eq!(caboose_items.get(&caboose::tags::NAME).unwrap(), "lpc_app");
        assert_eq!(
            caboose_items.get(&caboose::tags::VERS).unwrap(),
            "2.0.0-lpc"
        );
        assert!(caboose_items.contains_key(&caboose::tags::SIGN));
        // No mfg_cfg means no cmpa/cfpa generated
        assert!(!archive.new_files.contains_key("cmpa.bin"));
        assert!(!archive.new_files.contains_key("cfpa.bin"));
    }

    #[test]
    fn restamp_with_version_none_preserves_existing_vers() {
        let initial_tlvc_pieces = vec![
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(caboose::tags::NAME),
                vec![tlvc_text::Piece::String("MyApp".to_string())],
            ),
            tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(caboose::tags::VERS),
                vec![tlvc_text::Piece::String("1.0.0-existing".to_string())],
            ),
        ];
        let initial_caboose_data = tlvc_text::pack(&initial_tlvc_pieces);
        let mut archive = create_mock_archive(
            "stm32h7",
            Some(&initial_caboose_data),
            None,
            Some("app_toml_name"),
            None,
        )
        .unwrap();

        // Call restamp with version=None
        archive.restamp(dummy_certs(), dummy_certs(), None).unwrap();

        let caboose_items =
            get_caboose_items_from_image(&archive.image).unwrap();
        // Existing VERS should be preserved
        assert_eq!(
            caboose_items.get(&caboose::tags::VERS).unwrap(),
            "1.0.0-existing"
        );
        // NAME should also be preserved
        assert_eq!(caboose_items.get(&caboose::tags::NAME).unwrap(), "MyApp");
    }

    #[test]
    fn restamp_lpc55_error_on_empty_root_certs() {
        let empty_caboose_bytes = empty_packed_caboose();
        let mut archive = create_mock_archive(
            "lpc55s69",
            Some(&empty_caboose_bytes),
            None,
            Some("app"),
            None,
        )
        .unwrap();
        let signing_certs = dummy_certs();

        let result = archive.restamp(vec![], signing_certs, None);

        match result {
            Err(Error::Lpc55(lpc_err)) => {
                let err_string = format!("{:?}", lpc_err);
                assert!(
                    err_string.contains("MissingCertificates")
                        || err_string.contains("InvalidInput")
                        || err_string.contains("MinItemsNotReached")
                        || err_string.contains("NoSigningCertificate")
                        || err_string.contains("NoRootCertificate"),
                    "Unexpected LPC55 error: {}",
                    err_string
                );
            }
            Ok(_) => panic!("Expected Lpc55 error"),
            Err(e) => panic!("Expected Lpc55 error, got: {:?}", e),
        }
    }

    // --- Error path tests ---

    #[test]
    fn restamp_fails_if_app_toml_missing_and_caboose_empty() {
        let mut zip_buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut zip_buf));
            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            // Create image with empty caboose so restamp needs to generate default
            let raw_image =
                create_mock_raw_hubris_image(Some(&empty_packed_caboose()));
            let elf_data = raw_image.to_elf().unwrap();
            zip.start_file("img/final.elf", options).unwrap();
            zip.write_all(&elf_data).unwrap();
            // No app.toml is added
            zip.start_file("git-rev", options).unwrap();
            zip.write_all(b"mock_git_rev_123").unwrap();
            zip.set_comment("hubris build archive v1");
            zip.finish().unwrap();
        }
        let mut archive = RawHubrisArchive::from_vec(zip_buf).unwrap();

        let result = archive.restamp(dummy_certs(), dummy_certs(), None);
        match result {
            Err(Error::MissingFile(_, fname)) => {
                assert_eq!(fname, "app.toml");
            }
            _ => panic!("Expected MissingFile for app.toml, got {:?}", result),
        }
    }

    #[test]
    fn restamp_lpc55_fails_if_mfg_cfg_is_bad_toml() {
        let empty_caboose_bytes = empty_packed_caboose();
        let bad_mfg_toml = "this is not valid toml {{{{";
        let app_toml_string =
            "chip = \"lpc55s69\"\nname=\"app\"\nboard=\"board\"".to_string();
        let mut archive = create_mock_archive_configurable(
            "lpc55s69",
            Some(&empty_caboose_bytes),
            Some(bad_mfg_toml),
            Some(app_toml_string),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let result = archive.restamp(dummy_certs(), dummy_certs(), None);
        assert!(matches!(result, Err(Error::BadToml(_))));
    }

    #[test]
    fn restamp_with_corrupt_body_in_caboose_returns_error() {
        // Create one valid chunk
        let valid_piece = tlvc_text::Piece::Chunk(
            tlvc_text::Tag::new(*b"GOOD"),
            vec![tlvc_text::Piece::Bytes(b"is_ok".to_vec())],
        );
        let mut initial_caboose_data = tlvc_text::pack(&[valid_piece]);

        // Create a second chunk and corrupt its body CRC
        let corrupt_tag_val = *b"BADD";
        let corrupt_body_content = b"bad_data";
        let corrupt_piece_proto = tlvc_text::Piece::Chunk(
            tlvc_text::Tag::new(corrupt_tag_val),
            vec![tlvc_text::Piece::Bytes(corrupt_body_content.to_vec())],
        );
        let mut packed_corrupt_part = tlvc_text::pack(&[corrupt_piece_proto]);

        // Ensure there are enough bytes for header, body, and body CRC
        let header_size = std::mem::size_of::<tlvc::ChunkHeader>();
        let body_len_unrounded = corrupt_body_content.len();
        let body_len_rounded_up = (body_len_unrounded + 3) & !3;
        let body_crc_size = 4;
        let expected_corrupt_part_len =
            header_size + body_len_rounded_up + body_crc_size;

        assert_eq!(
            packed_corrupt_part.len(),
            expected_corrupt_part_len,
            "Corrupt part packed length unexpected"
        );

        // Corrupt the body checksum (last 4 bytes of this part)
        let crc_offset_in_corrupt_part =
            packed_corrupt_part.len() - body_crc_size;
        packed_corrupt_part[crc_offset_in_corrupt_part] =
            packed_corrupt_part[crc_offset_in_corrupt_part].wrapping_add(1);

        initial_caboose_data.extend_from_slice(&packed_corrupt_part);

        let mut archive = create_mock_archive(
            "stm32h7",
            Some(&initial_caboose_data),
            None,
            Some("app_for_corrupt_test"),
            None,
        )
        .unwrap();

        let result = archive.restamp(dummy_certs(), dummy_certs(), None);

        match result {
            Err(Error::InvalidCabooseEntry(msg)) => {
                assert!(
                    msg.contains("BodyCorrupt"), // Check for substring BodyCorrupt
                    "Expected BodyCorrupt error message, got: {}",
                    msg
                );
            }
            _ => panic!(
                "Expected InvalidCabooseEntry for body corruption, got {:?}",
                result
            ),
        }
    }
}
