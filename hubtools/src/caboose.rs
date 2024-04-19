// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::mem;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CabooseError {
    #[error("error reading caboose: {0:?}")]
    TlvcReadError(tlvc::TlvcReadError<std::convert::Infallible>),

    #[error("caboose missing expected tag {tag:?}")]
    MissingTag { tag: [u8; 4] },
}

#[derive(Debug, Clone)]
pub struct Caboose {
    raw: Vec<u8>,
}

impl Caboose {
    pub(crate) fn new(raw: Vec<u8>) -> Self {
        Self { raw }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.raw
    }

    pub fn git_commit(&self) -> Result<&[u8], CabooseError> {
        self.get_tag(tags::GITC)
    }

    pub fn board(&self) -> Result<&[u8], CabooseError> {
        self.get_tag(tags::BORD)
    }

    pub fn name(&self) -> Result<&[u8], CabooseError> {
        self.get_tag(tags::NAME)
    }

    pub fn version(&self) -> Result<&[u8], CabooseError> {
        self.get_tag(tags::VERS)
    }

    pub fn sign(&self) -> Result<&[u8], CabooseError> {
        self.get_tag(tags::SIGN)
    }

    fn get_tag(&self, tag: [u8; 4]) -> Result<&[u8], CabooseError> {
        use tlvc::TlvcReader;
        let mut reader = TlvcReader::begin(self.as_slice())
            .map_err(CabooseError::TlvcReadError)?;

        while let Ok(Some(chunk)) = reader.next() {
            if chunk.header().tag != tag {
                continue;
            }

            let mut buf = [0; 32];
            chunk
                .check_body_checksum(&mut buf)
                .map_err(CabooseError::TlvcReadError)?;

            // At this point, the reader is positioned **after** the data
            // from the target chunk.  We'll back up to the start of the
            // data slice.
            let (data, pos, _end) = reader.into_inner();

            let pos = pos as usize;
            let data_len = chunk.header().len.get() as usize;
            let data_start = pos - chunk.header().total_len_in_bytes()
                + mem::size_of::<tlvc::ChunkHeader>();
            return Ok(&data[data_start..][..data_len]);
        }

        Err(CabooseError::MissingTag { tag })
    }
}

pub(crate) mod tags {
    pub(crate) const GITC: [u8; 4] = *b"GITC";
    pub(crate) const BORD: [u8; 4] = *b"BORD";
    pub(crate) const NAME: [u8; 4] = *b"NAME";
    pub(crate) const VERS: [u8; 4] = *b"VERS";
    pub(crate) const SIGN: [u8; 4] = *b"SIGN";
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CabooseBuilder {
    git_commit: Option<String>,
    board: Option<String>,
    name: Option<String>,
    version: Option<String>,
    sign: Option<String>,
}

impl CabooseBuilder {
    pub fn git_commit<S: Into<String>>(mut self, git_commit: S) -> Self {
        self.git_commit = Some(git_commit.into());
        self
    }

    pub fn board<S: Into<String>>(mut self, board: S) -> Self {
        self.board = Some(board.into());
        self
    }

    pub fn name<S: Into<String>>(mut self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn version<S: Into<String>>(mut self, version: S) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn sign<S: Into<String>>(mut self, sign: S) -> Self {
        self.sign = Some(sign.into());
        self
    }

    pub fn build(self) -> Caboose {
        let mut pieces = Vec::new();
        for (tag, maybe_value) in [
            (tags::GITC, self.git_commit),
            (tags::BORD, self.board),
            (tags::NAME, self.name),
            (tags::VERS, self.version),
            (tags::SIGN, self.sign),
        ] {
            let Some(value) = maybe_value else {
                continue;
            };
            pieces.push(tlvc_text::Piece::Chunk(
                tlvc_text::Tag::new(tag),
                vec![tlvc_text::Piece::String(value)],
            ));
        }
        Caboose::new(tlvc_text::pack(&pieces))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_builder_makes_empty_caboose() {
        let caboose = CabooseBuilder::default().build();
        assert_eq!(
            caboose.git_commit(),
            Err(CabooseError::MissingTag { tag: tags::GITC })
        );
        assert_eq!(
            caboose.board(),
            Err(CabooseError::MissingTag { tag: tags::BORD })
        );
        assert_eq!(
            caboose.name(),
            Err(CabooseError::MissingTag { tag: tags::NAME })
        );
        assert_eq!(
            caboose.version(),
            Err(CabooseError::MissingTag { tag: tags::VERS })
        );
    }

    #[test]
    fn builder_can_make_caboose_with_one_tag() {
        let caboose = CabooseBuilder::default().git_commit("foo").build();
        assert_eq!(caboose.git_commit(), Ok("foo".as_bytes()));
        assert_eq!(
            caboose.board(),
            Err(CabooseError::MissingTag { tag: tags::BORD })
        );
        assert_eq!(
            caboose.name(),
            Err(CabooseError::MissingTag { tag: tags::NAME })
        );
        assert_eq!(
            caboose.version(),
            Err(CabooseError::MissingTag { tag: tags::VERS })
        );
    }

    #[test]
    fn builder_can_make_caboose_with_all_tags() {
        let caboose = CabooseBuilder::default()
            .git_commit("foo")
            .board("bar")
            .name("fizz")
            .version("buzz")
            .build();
        assert_eq!(caboose.git_commit(), Ok("foo".as_bytes()));
        assert_eq!(caboose.board(), Ok("bar".as_bytes()));
        assert_eq!(caboose.name(), Ok("fizz".as_bytes()));
        assert_eq!(caboose.version(), Ok("buzz".as_bytes()));
    }
}
