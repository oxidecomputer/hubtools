// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use object::{Object, ObjectSection, ObjectSegment};
use std::path::PathBuf;

use crate::header;
use crate::Error;
use crate::HubrisArchiveBuilder;
use crate::RawHubrisArchive;
use crate::RawHubrisImage;
use zerocopy::AsBytes;

fn image_length(elf: &object::read::File) -> Result<u64, Error> {
    let mut total: u64 = 0;
    let mut prev: Option<u64> = None;

    for s in elf.segments() {
        let (_, fsize) = s.file_range();
        if fsize == 0 {
            continue;
        }

        let len = s.size();
        total += len;

        if let Some(prev) = prev {
            let gap_size = s
                .address()
                .checked_sub(prev)
                .ok_or(Error::MemorySegmentOverlap)?;
            total += gap_size;
        }
        prev = Some(s.address() + len);
    }

    Ok(total)
}

fn header_offset(elf: &object::read::File) -> Result<u64, Error> {
    for s in elf.sections() {
        let name = match s.name() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if name == ".header" {
            if (s.size() as usize) < core::mem::size_of::<header::ImageHeader>()
            {
                return Err(Error::HeaderTooSmall);
            }

            let (offset, _) = s.file_range().ok_or(Error::BadFileRange)?;
            return Ok(offset);
        }
    }

    Err(Error::MissingHeader)
}

fn add_image_header(path: PathBuf) -> Result<Vec<u8>, Error> {
    // We can't construct an ELF object from a mutable reference so we
    // work on the file path and return the bytes
    let mut f = std::fs::read(path).map_err(Error::FileReadError)?;

    let elf =
        object::read::File::parse(&*f).map_err(Error::ObjectError)?;
    if elf.format() != object::BinaryFormat::Elf {
        return Err(Error::NotAnElf(elf.format()));
    }

    let len = image_length(&elf)?;

    let offset = header_offset(&elf)?;
    drop(elf);

    let header = header::ImageHeader {
        magic: 0x64_CE_D6_CA,
        total_image_len: len as u32,
    };

    header
        .write_to_prefix(&mut f[(offset as usize)..])
        .ok_or(Error::BadPrefix)?;

    Ok(f)
}

pub fn bootleby_to_archive(
    path: PathBuf,
    board: String,
    name: String,
    gitc: String,
) -> Result<Vec<u8>, Error> {
    let f = add_image_header(path)?;

    let img = RawHubrisImage::from_generic_elf(&f)?;

    let bytes = HubrisArchiveBuilder::with_image(img).build_to_vec()?;

    let mut archive = RawHubrisArchive::from_vec(bytes)?;

    let toml = format!(
        r#"
        name = "{}"
        board = "{}"
        chip = "lpc55"
        "#,
        name, board
    );

    archive.add_file("elf/kernel", &f)?;
    archive.add_file("app.toml", toml.as_bytes())?;
    archive.add_file("git-rev", gitc.as_bytes())?;

    archive.to_vec()
}
