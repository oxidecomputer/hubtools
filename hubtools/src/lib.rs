// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use object::{Object, ObjectSection};
use packed_struct::PackedStruct;
use path_slash::PathBufExt;
use thiserror::Error;
use zerocopy::{AsBytes, FromBytes};

use std::{
    collections::{btree_map::Entry, BTreeMap},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

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
        signing_certs: Vec<Vec<u8>>,
        root_certs: Vec<Vec<u8>>,
        private_key: &str,
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

    #[error("manifest decoding error: {0}")]
    BadManifest(std::str::Utf8Error),

    #[error("could not find magic number {0:#x}")]
    MissingMagic(u32),

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

    #[error("caboose is not located at the end of the image; is it signed?")]
    BadCabooseLocation,

    #[error("Bad CMPA size: expected 512 bytes, got {0}")]
    BadCMPASize(usize),

    #[error("Bad CFPA size: expected 512 bytes, got {0}")]
    BadCFPASize(usize),

    #[error("packed struct error: {0}")]
    PackedStruct(#[from] packed_struct::PackingError),

    #[error("LPC55 support error: {0}")]
    Lpc55(#[from] lpc55_sign::Error),

    #[error("wrong chip: expected lpc55, got {0}")]
    WrongChip(String),
}

////////////////////////////////////////////////////////////////////////////////

/// Minimal Hubris archive, useful for some basic manipulation of the binary
/// image within.
#[derive(Debug)]
pub struct RawHubrisArchive {
    /// Source path of the Hubris archive on disk
    pub path: PathBuf,

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

const CMPA_FILE: &str = "img/CMPA.bin";
const CFPA_FILE: &str = "img/CFPA.bin";

impl RawHubrisArchive {
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
            path: filename.as_ref().to_owned(),
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

    fn start_addr(&self) -> u32 {
        self.image.start_addr
    }

    fn caboose_range(&self) -> Result<std::ops::Range<u32>, Error> {
        let mut found_header = None;
        let start_addr = self.start_addr();

        // The header is located in one of a few locations, depending on MCU
        // and versions of the PAC crates.
        //
        // - 0xbc and 0xc0 are possible values for the STM32G0
        // - 0x298 is for the STM32H7
        // - 0x130 is for the LPC55
        for header_offset in [0xbc, 0xc0, 0x130, 0x298] {
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
        // Skip the start and end word, which are markers
        let caboose_range = self.caboose_range()?;

        let end = caboose_range.end - self.image.start_addr;
        if end as usize != self.image.data.len() - 4 {
            Err(Error::BadCabooseLocation)
        } else if data.len() > caboose_range.len() {
            Err(Error::OversizedData(data.len(), caboose_range.len()))
        } else {
            self.write(caboose_range.start, data)
        }
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
            .ok_or(Error::BadTomlType)?
            .get("board")
            .ok_or(Error::BadTomlType)?
            .as_str()
            .ok_or(Error::BadTomlType)?
            .to_owned();
        let name = manifest
            .as_table()
            .ok_or(Error::BadTomlType)?
            .get("name")
            .ok_or(Error::BadTomlType)?
            .as_str()
            .ok_or(Error::BadTomlType)?
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
        let end = caboose_range.end - self.image.start_addr;
        if end as usize != self.image.data.len() - 4 {
            return Err(Error::BadCabooseLocation);
        }
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
        let size = out.as_bytes().len() as u32;
        out.as_bytes_mut()
            .copy_from_slice(self.image.get(start..start + size)?);
        Ok(())
    }

    /// Attempts to read `out.len()` bytes, starting at `start`
    fn write<T: AsBytes + FromBytes + ?Sized>(
        &mut self,
        start: u32,
        input: &T,
    ) -> Result<(), Error> {
        let size = input.as_bytes().len() as u32;
        self.image
            .get_mut(start..start + size)?
            .copy_from_slice(input.as_bytes());
        Ok(())
    }

    /// Verifies the signature of an LPC55 image
    ///
    /// Results are printed to `stderr` using `log`
    pub fn verify(&self, verbose: bool) -> Result<(), Error> {
        // CMPA and CFPA are included in the archive (for now)
        let cmpa_bytes = self.extract_file("img/CMPA.bin")?;
        let cmpa_array: Box<[u8; 512]> = cmpa_bytes
            .try_into()
            .map_err(|v: Vec<u8>| Error::BadCMPASize(v.len()))?;
        let cmpa = lpc55_areas::CMPAPage::from_bytes(&cmpa_array)?;

        let cfpa_bytes = self.extract_file("img/CFPA.bin")?;
        let cfpa_array: Box<[u8; 512]> = cfpa_bytes
            .try_into()
            .map_err(|v: Vec<u8>| Error::BadCFPASize(v.len()))?;
        let cfpa = lpc55_areas::CFPAPage::from_bytes(&cfpa_array)?;

        lpc55_sign::verify::init_verify_logger(verbose);
        lpc55_sign::verify::verify_image(&self.image.data, cmpa, cfpa)?;

        Ok(())
    }

    /// Signs the given image with a chain of one-or-more certificates
    ///
    /// This modifies local data in memory; call `self.overwrite` to persist
    /// changes back to the archive on disk.
    pub fn sign(
        &mut self,
        signing_certs: Vec<Vec<u8>>,
        root_certs: Vec<Vec<u8>>,
        private_key: &str,
        execution_address: u32,
    ) -> Result<(), Error> {
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
            return Err(Error::WrongChip(chip));
        }

        self.image.sign(
            signing_certs,
            root_certs,
            private_key,
            execution_address,
        )
    }

    /// Adds `img/CMPA.bin` to the archive, generated based on a DICE
    /// configuration and set of root certificates.
    ///
    /// This modifies local data in memory; call `self.overwrite` to persist
    /// changes back to the archive on disk.
    pub fn set_cmpa(
        &mut self,
        dice: lpc55_sign::signed_image::DiceArgs,
        enable_secure_boot: bool,
        debug: lpc55_areas::DebugSettings,
        default_isp: lpc55_areas::DefaultIsp,
        speed: lpc55_areas::BootSpeed,
        boot_error_pin: lpc55_areas::BootErrorPin,
        root_certs: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let rkth = lpc55_sign::signed_image::root_key_table_hash(root_certs)?;
        let cmpa = lpc55_sign::signed_image::generate_cmpa(
            dice,
            enable_secure_boot,
            debug,
            default_isp,
            speed,
            boot_error_pin,
            rkth,
        )?;
        if self.new_files.contains_key(CMPA_FILE)
            || self.extract_file(CMPA_FILE).is_ok()
        {
            return Err(Error::DuplicateFilename(CMPA_FILE.to_owned()));
        }
        self.new_files
            .insert(CMPA_FILE.to_string(), cmpa.pack()?.to_vec());
        Ok(())
    }

    /// Adds `img/CFPA.bin` to the archive, based on a set of root certificates.
    ///
    /// This modifies local data in memory; call `self.overwrite` to persist
    /// changes back to the archive on disk.
    pub fn set_cfpa(
        &mut self,
        settings: lpc55_areas::DebugSettings,
        revoke: [lpc55_areas::ROTKeyStatus; 4],
    ) -> Result<(), Error> {
        let cfpa = lpc55_sign::signed_image::generate_cfpa(settings, revoke)?;
        if self.new_files.contains_key(CFPA_FILE)
            || self.extract_file(CFPA_FILE).is_ok()
        {
            return Err(Error::DuplicateFilename(CFPA_FILE.to_owned()));
        }
        self.new_files
            .insert(CFPA_FILE.to_string(), cfpa.pack()?.to_vec());
        Ok(())
    }
}
