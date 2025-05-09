use std::{collections::BTreeMap, num::NonZeroU64};

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::proto::{data_to_symbol, decode_hdr, symbol_to_data};

#[derive(Debug)]
pub struct FecDecoder {
    window_size: NonZeroU64,
    window: BTreeMap<u64, Group>,
    symbol_size: usize,
    max_group_size: usize,
}
#[bon::bon]
impl FecDecoder {
    #[builder]
    pub fn new(window_size: NonZeroU64, symbol_size: usize, max_group_size: usize) -> Self {
        Self {
            window_size,
            window: BTreeMap::new(),
            symbol_size,
            max_group_size,
        }
    }
}
impl FecDecoder {
    pub fn decode(&mut self, buf: &[u8], mut recover: impl FnMut(&[u8])) -> Option<usize> {
        let (hdr, hdr_len) = decode_hdr(buf)?;
        if self.max_group_size <= hdr.symbol_global_id.symbol_id.into() {
            return None;
        }
        let data_or_parity = &buf[hdr_len..];
        let symbol = match hdr.parity {
            Some(_) => data_or_parity.to_vec(),
            None => data_to_symbol(data_or_parity, self.symbol_size),
        };
        let min_group_id = hdr
            .symbol_global_id
            .group_id
            .checked_sub(self.window_size.get());
        if let Some(min_group_id) = min_group_id {
            while let Some((first_group_id, _)) = self.window.first_key_value() {
                if *first_group_id < min_group_id {
                    self.window.pop_first();
                } else {
                    break;
                }
            }
        }
        if self.window.len() == self.window_size.get().try_into().unwrap() {
            return None;
        }
        let group = self
            .window
            .entry(hdr.symbol_global_id.group_id)
            .or_default();
        group.push(hdr.symbol_global_id.symbol_id.into(), symbol);
        if let Some(parity) = hdr.parity {
            for symbol in group
                .recover()
                .data_count(parity.data_count.get().into())
                .parity_count(parity.parity_count.into())
                .call()
            {
                let mut buf = vec![0; symbol.len()];
                let Some(n) = symbol_to_data(&symbol, &mut buf) else {
                    continue;
                };
                recover(&buf[..n]);
            }
            return None;
        }
        Some(hdr_len)
    }
}

#[derive(Debug, Default)]
struct Group {
    symbols: Vec<Option<Vec<u8>>>,
}
#[bon::bon]
impl Group {
    pub fn push(&mut self, symbol_id: usize, symbol: Vec<u8>) {
        while self.symbols.len() <= symbol_id {
            self.symbols.push(None);
        }
        self.symbols[symbol_id] = Some(symbol);
    }
    #[builder]
    pub fn recover(&mut self, data_count: usize, parity_count: usize) -> Vec<Vec<u8>> {
        while self.symbols.len() < data_count {
            self.symbols.push(None);
        }
        let missing_data: Vec<usize> = self
            .symbols
            .iter()
            .enumerate()
            .take(data_count)
            .filter_map(|(i, symbol)| if symbol.is_none() { Some(i) } else { None })
            .collect();
        let de = ReedSolomon::new(data_count, parity_count).unwrap();
        if de.reconstruct_data(&mut self.symbols).is_err() {
            return vec![];
        }
        missing_data
            .into_iter()
            .map(|i| self.symbols[i].take().unwrap())
            .collect()
    }
}
