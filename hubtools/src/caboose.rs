// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::mem;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CabooseError {
    #[error("error reading caboose: {0:?}")]
    TlvcReadError(tlvc::TlvcReadError),

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

    pub fn board(&self) -> Result<&[u8], CabooseError> {
        use tlvc::TlvcReader;
        let mut reader = TlvcReader::begin(self.as_slice())
            .map_err(CabooseError::TlvcReadError)?;

        while let Ok(Some(chunk)) = reader.next() {
            if chunk.header().tag != tags::BORD {
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

        Err(CabooseError::MissingTag { tag: tags::BORD })
    }
}

pub(crate) mod tags {
    pub(crate) const GITC: [u8; 4] = *b"GITC";
    pub(crate) const BORD: [u8; 4] = *b"BORD";
    pub(crate) const NAME: [u8; 4] = *b"NAME";
    pub(crate) const VERS: [u8; 4] = *b"VERS";
}
