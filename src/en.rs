use std::num::NonZeroU8;

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::proto::{
    HDR_SIZE, PacketHeader, ParityHeader, SymbolGlobalId, data_to_symbol, decode_data_symbol_hdr,
    encode_hdr,
};

#[derive(Debug)]
pub struct FecEncoder {
    group_id: u64,
    group_data: Vec<Vec<u8>>,
    symbol_size: usize,
}
#[bon::bon]
impl FecEncoder {
    #[builder]
    pub fn new(symbol_size: usize) -> Self {
        Self {
            group_id: 0,
            group_data: vec![],
            symbol_size,
        }
    }
}
impl FecEncoder {
    pub fn group_data_count(&self) -> usize {
        self.group_data.len()
    }

    /// The longest information prefix among the open group's data symbols: a
    /// stored shard is its data-symbol header followed by its payload, and
    /// every byte past that prefix is the zero pad.  The parity of an all-zero
    /// column is zero, so a parity shard is informative only up to this length
    /// — the cap a parity datagram can be trimmed to without losing anything.
    fn group_information_len(&self) -> usize {
        self.group_data
            .iter()
            .filter_map(|symbol| decode_data_symbol_hdr(symbol))
            .map(|(hdr_len, data_len)| hdr_len + usize::from(data_len))
            .max()
            .unwrap_or(self.symbol_size)
            .min(self.symbol_size)
    }
    pub fn skip_group(&mut self) {
        self.group_data.clear();
        self.group_id += 1;
    }
    pub fn encode_data(&mut self, data: &[u8], buf: &mut [u8]) -> usize {
        let pos = {
            let symbol_global_id = SymbolGlobalId {
                group_id: self.group_id,
                symbol_id: self.group_data_count().try_into().unwrap(),
            };
            let hdr = PacketHeader {
                symbol_global_id,
                parity: None,
            };
            let hdr_len = encode_hdr(hdr, buf);
            let data_buf = &mut buf[hdr_len..];
            let data_len = data_buf.len().min(data.len());
            data_buf[..data_len].copy_from_slice(&data[..data_len]);
            hdr_len + data_len
        };
        let symbol = data_to_symbol(data, self.symbol_size);
        self.group_data.push(symbol);
        pos
    }
    pub fn flush_parities(&mut self, parity_count: u8) -> FecParityEncoder {
        let data_count = self.group_data_count();
        let en = ReedSolomon::new(data_count, parity_count.into()).unwrap();
        let mut parities: Vec<Vec<u8>> = (0..parity_count)
            .map(|_| vec![0; self.symbol_size])
            .collect();
        en.encode_sep(&self.group_data, &mut parities).unwrap();
        let information_len = self.group_information_len();
        let group_id = self.group_id;
        self.group_data.clear();
        self.group_id += 1;
        FecParityEncoder {
            group_id,
            data_count: NonZeroU8::new(data_count.try_into().unwrap()).unwrap(),
            parity_count,
            information_len,
            left_parities: parities,
        }
    }
}

#[derive(Debug)]
pub struct FecParityEncoder {
    group_id: u64,
    data_count: NonZeroU8,
    parity_count: u8,
    /// Longest information prefix in the flushed group.  The parity datagram is
    /// trimmed to it: the bytes past it are the zero pad in every data shard, so
    /// the parity bytes there are zero too and trimming them loses nothing.
    information_len: usize,
    left_parities: Vec<Vec<u8>>,
}
impl FecParityEncoder {
    pub fn encode_parity(&mut self, buf: &mut [u8]) -> Option<usize> {
        let parity = self.left_parities.pop()?;
        let i = self.left_parities.len();
        let offset: u8 = i.try_into().unwrap();
        let symbol_global_id = SymbolGlobalId {
            group_id: self.group_id,
            symbol_id: self.data_count.get() + offset,
        };
        let hdr = PacketHeader {
            symbol_global_id,
            parity: Some(ParityHeader {
                data_count: self.data_count,
                parity_count: self.parity_count,
            }),
        };
        // The datagram is the header plus the group's information prefix; the
        // trailing zero pad carries no information and is not sent.
        let parity_len = parity.len().min(self.information_len);
        assert!(
            buf.len() >= HDR_SIZE + parity_len,
            "the parity buffer must hold the header plus the information prefix"
        );
        let hdr_len = encode_hdr(hdr, buf);
        let parity_buf = &mut buf[hdr_len..];
        parity_buf[..parity_len].copy_from_slice(&parity[..parity_len]);
        Some(hdr_len + parity_len)
    }
}
