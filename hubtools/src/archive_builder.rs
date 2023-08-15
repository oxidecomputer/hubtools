// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::header;
use crate::Error;
use crate::RawHubrisImage;
use crate::CABOOSE_MAGIC;
use std::io;
use std::io::Write;
use zip::ZipWriter;

/// `HubrisArchiveBuilder` can create an extremely minimal hubris archive.
///
/// Currently the archives produced by `HubrisArchiveBuilder` only contain the
/// final hubris image (in both binary and ELF format), and are therefore likely
/// unsuitable for many uses (including humility). The intented use for this
/// (again, for now) is generating test data; see
/// [`HubrisArchiveBuilder::with_fake_image()`].
pub struct HubrisArchiveBuilder {
    image: RawHubrisImage,
    archive_version: u32,
}

impl HubrisArchiveBuilder {
    pub fn with_image(image: RawHubrisImage) -> Self {
        Self {
            image,
            archive_version: 0,
        }
    }

    /// Construct a fake `RawHubrisImage` that is not valid, but _appears_ to be
    /// valid: it contains the correct magic numbers at the correct offsets to
    /// look like a hubris image and contain a caboose.
    pub fn with_fake_image() -> Self {
        const FAKE_IMAGE_SIZE: usize = 1024;
        const FAKE_CABOOSE_SIZE: usize = 256;

        // Built a dummy image that still looks reasonable enough for testing
        // (e.g, we stick some magic values in the right places and allow for
        // insertion of a caboose).
        let mut data = io::Cursor::new(vec![0; FAKE_IMAGE_SIZE]);

        // Write the header magic at the largest possible value where
        // `RawHubrisArchive` might look for it.
        data.set_position(u64::from(
            header::POSSIBLE_OFFSETS.iter().copied().max().unwrap(),
        ));
        data.write_all(&header::MAGIC.last().copied().unwrap().to_le_bytes())
            .unwrap();

        // Write the image size immediately after the header magic.
        data.write_all(&(FAKE_IMAGE_SIZE as u32).to_le_bytes())
            .unwrap();

        // Write the caboose magic at the beginning of the caboose.
        data.set_position((FAKE_IMAGE_SIZE - FAKE_CABOOSE_SIZE) as u64);
        data.write_all(&CABOOSE_MAGIC.to_le_bytes()).unwrap();

        // Write the caboose size as the last word in the image.
        data.set_position((FAKE_IMAGE_SIZE - 4) as u64);
        data.write_all(&(FAKE_CABOOSE_SIZE as u32).to_le_bytes())
            .unwrap();

        let image =
            RawHubrisImage::from_binary(data.into_inner(), 0, 0).unwrap();

        // Ensure our caboose staging above was correct.
        assert_eq!(
            (FAKE_IMAGE_SIZE - FAKE_CABOOSE_SIZE + 4) as u32
                ..FAKE_IMAGE_SIZE as u32 - 4,
            image.caboose_range().unwrap()
        );

        Self::with_image(image)
    }

    /// Set the version number including in the zip file comment.
    pub fn archive_version(&mut self, archive_version: u32) -> &mut Self {
        self.archive_version = archive_version;
        self
    }

    /// Overwrite the caboose of the image included in this archive.
    pub fn write_caboose(&mut self, data: &[u8]) -> Result<&mut Self, Error> {
        self.image.write_caboose(data)?;
        Ok(self)
    }

    pub fn build<W>(self, out: W) -> Result<W, Error>
    where
        W: io::Write + io::Seek,
    {
        let opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Bzip2);

        let mut archive = ZipWriter::new(out);
        archive.set_comment(format!(
            "hubris build archive v{}",
            self.archive_version
        ));

        archive.start_file("img/final.elf", opts)?;
        let elf = self.image.to_elf()?;
        archive.write_all(&elf).unwrap();
        let bin = self.image.to_binary()?;
        archive.write_all(&bin).unwrap();

        let out = archive.finish()?;
        Ok(out)
    }

    pub fn build_to_vec(self) -> Result<Vec<u8>, Error> {
        let out = io::Cursor::new(Vec::new());
        self.build(out).map(io::Cursor::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CabooseBuilder;
    use crate::RawHubrisArchive;

    #[test]
    fn built_archives_are_loadable() {
        let builder = HubrisArchiveBuilder::with_fake_image();
        let archive = builder.build_to_vec().unwrap();

        let loaded = RawHubrisArchive::from_vec(archive).unwrap();
        let caboose = loaded.read_caboose().unwrap();

        // We didn't specify any caboose contents, so it should be empty.
        assert!(caboose.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn written_caboose_values_are_loadable() {
        let mut builder = HubrisArchiveBuilder::with_fake_image();
        builder
            .write_caboose(
                CabooseBuilder::default()
                    .git_commit("foo")
                    .board("bar")
                    .name("fizz")
                    .version("buzz")
                    .build()
                    .as_slice(),
            )
            .unwrap();
        let archive = builder.build_to_vec().unwrap();

        let loaded = RawHubrisArchive::from_vec(archive).unwrap();
        let caboose = loaded.read_caboose().unwrap();

        assert_eq!(caboose.git_commit(), Ok("foo".as_bytes()));
        assert_eq!(caboose.board(), Ok("bar".as_bytes()));
        assert_eq!(caboose.name(), Ok("fizz".as_bytes()));
        assert_eq!(caboose.version(), Ok("buzz".as_bytes()));
    }
}
