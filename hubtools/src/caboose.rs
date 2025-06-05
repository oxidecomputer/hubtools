// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;
use tlvc::TlvcReader;

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
        self.iter()?
            .find_map(|chunk| match chunk {
                Ok((chunk_tag, chunk_data)) if chunk_tag == tag => {
                    Some(Ok(chunk_data))
                }
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .unwrap_or(Err(CabooseError::MissingTag { tag }))
    }

    pub fn iter(&self) -> Result<CabooseIter<'_>, CabooseError> {
        let reader = tlvc::TlvcReader::<&[u8]>::begin(self.as_slice())
            .map_err(CabooseError::TlvcReadError)?;
        Ok(CabooseIter {
            reader,
            checksum_buf: [0; 32],
        })
    }

    pub fn is_empty(&self) -> Result<bool, CabooseError> {
        match self.iter()?.next() {
            Some(Ok(_)) => Ok(false),
            Some(Err(e)) => Err(e),
            None => Ok(true),
        }
    }
}

pub struct CabooseIter<'a> {
    reader: TlvcReader<&'a [u8]>,
    checksum_buf: [u8; 32],
}

impl<'a> Iterator for CabooseIter<'a> {
    type Item = Result<([u8; 4], &'a [u8]), CabooseError>;

    fn next(&mut self) -> Option<Self::Item> {
        use tlvc::TlvcReadError;

        // Clone reader state *before* attempting to read the next chunk.
        // This allows inspecting the bytes at the current position if self.reader.next() fails.
        let reader_state_at_start_of_next = self.reader.clone();

        match self.reader.next() {
            Ok(Some(chunk)) => {
                let header_copy = *chunk.header();

                // Validate the body checksum for this valid chunk
                if let Err(body_checksum_error) =
                    chunk.check_body_checksum(&mut self.checksum_buf)
                {
                    // Body is corrupt for an otherwise validly-headered chunk
                    return Some(Err(CabooseError::TlvcReadError(
                        body_checksum_error,
                    )));
                }

                // Body checksum is also fine. Extract and return the data.
                // The TlvcReader (`self.reader`) has already advanced past the current chunk.
                let (original_full_slice, advanced_reader_pos, _reader_limit) =
                    self.reader.clone().into_inner();

                let body_data_start_in_full_slice = (advanced_reader_pos
                    as usize)
                    // Go to start of the chunk (header) just consumed
                    .saturating_sub(header_copy.total_len_in_bytes())
                    // Add header size to get body start
                    .saturating_add(std::mem::size_of::<tlvc::ChunkHeader>());

                let body_data_len = header_copy.len.get() as usize;

                if body_data_start_in_full_slice.saturating_add(body_data_len)
                    > original_full_slice.len()
                {
                    return Some(Err(CabooseError::TlvcReadError(
                        TlvcReadError::Truncated,
                    )));
                }
                let data_slice = &original_full_slice
                    [body_data_start_in_full_slice
                        ..body_data_start_in_full_slice + body_data_len];

                Some(Ok((header_copy.tag, data_slice)))
            }
            Ok(None) => None, // TlvcReader correctly signaled end of data within its limit.
            Err(tlvc_error) => {
                // An error occurred in TlvcReader::next(), likely from TlvcReader::read_header()
                match tlvc_error {
                    TlvcReadError::HeaderCorrupt {
                        stored_checksum,
                        computed_checksum: _,
                    } => {
                        if stored_checksum == 0xFFFFFFFF {
                            // Got HeaderCorrupt and stored_checksum suggests uninitialized flash.
                            // Let's peek at the bytes where TlvcReader tried to read the header.
                            // Use the state *before* the failing .next()
                            let (
                                source_slice,
                                reader_pos_at_error,
                                reader_limit,
                            ) = reader_state_at_start_of_next.into_inner();

                            let remaining_len_at_error_pos = reader_limit
                                .saturating_sub(reader_pos_at_error);

                            // How many bytes to check for 0xFF padding? At least a tag's worth.
                            let bytes_to_peek = std::cmp::min(
                                remaining_len_at_error_pos,
                                4, // Check at least 4 bytes for an all-0xFF tag
                            )
                                as usize;

                            if bytes_to_peek > 0 {
                                let potential_padding_slice = &source_slice
                                    [reader_pos_at_error as usize
                                        ..(reader_pos_at_error as usize
                                            + bytes_to_peek)];
                                if potential_padding_slice
                                    .iter()
                                    .all(|&b| b == 0xFF)
                                {
                                    // If the start of what would be a tag is all 0xFFs,
                                    // and we got HeaderCorrupt with stored_checksum 0xFFFFFFFF,
                                    // conclude it's padding and end iteration.
                                    return None;
                                }
                            } else if remaining_len_at_error_pos == 0 {
                                // No bytes left at the point of error, also treat as EOF.
                                return None;
                            }
                        }
                        // If not the specific 0xFFFFFFFF padding case, or if peeking didn't confirm 0xFFs,
                        // then it's a genuine HeaderCorrupt error.
                        Some(Err(CabooseError::TlvcReadError(tlvc_error)))
                    }
                    // Propagate other TlvcReadErrors (like Truncated if not caught above, or User errors)
                    _ => Some(Err(CabooseError::TlvcReadError(tlvc_error))),
                }
            }
        }
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
    fn caboose_is_empty_works() {
        let caboose = CabooseBuilder::default().build();
        assert_eq!(caboose.is_empty(), Ok(true));
        let caboose = CabooseBuilder::default().git_commit("foo").build();
        assert_eq!(caboose.is_empty(), Ok(false));
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
