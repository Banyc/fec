use std::{collections::BTreeMap, num::NonZeroU64};

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::proto::{data_to_symbol, decode_hdr, symbol_to_data};

#[derive(Debug)]
pub struct FecDecoder {
    window_size: NonZeroU64,
    window: BTreeMap<u64, Group>,
    symbol_size: usize,
    max_group_size: usize,
    /// Reconstructed symbols dropped because their own length header claims more
    /// than their shard holds.  Nothing else in the decoder observes this: the
    /// symbol never becomes a payload, so the caller cannot tell a rejected
    /// reconstruction from a group that recovered nothing.
    rejected_recovered_symbols: usize,
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
            rejected_recovered_symbols: 0,
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
            Some(_) => self.parity_symbol(data_or_parity)?,
            None => data_to_symbol(data_or_parity, self.symbol_size),
        };
        let min_group_id = hdr
            .symbol_global_id
            .group_id
            .checked_sub(self.window_size.get() - 1);
        if let Some(min_group_id) = min_group_id {
            while let Some((first_group_id, _)) = self.window.first_key_value() {
                if *first_group_id < min_group_id {
                    self.window.pop_first();
                } else {
                    break;
                }
            }
        }
        if self.window.len() == self.window_size.get().try_into().unwrap()
            && !self.window.contains_key(&hdr.symbol_global_id.group_id)
        {
            return None;
        }
        let group = self
            .window
            .entry(hdr.symbol_global_id.group_id)
            .or_default();
        group.push(hdr.symbol_global_id.symbol_id.into(), symbol);
        if let Some(parity) = hdr.parity {
            let mut rejected = 0_usize;
            for symbol in group
                .recover()
                .data_count(parity.data_count.get().into())
                .parity_count(parity.parity_count.into())
                .call()
            {
                let mut buf = vec![0; symbol.len()];
                let Some(n) = symbol_to_data(&symbol, &mut buf) else {
                    rejected += 1;
                    continue;
                };
                recover(&buf[..n]);
            }
            self.rejected_recovered_symbols += rejected;
            return None;
        }
        Some(hdr_len)
    }

    /// Reconstructed symbols rejected because they claim more than they hold.
    /// The decoder is the only witness: a rejected symbol never becomes a
    /// payload, so a caller cannot distinguish it from a group that recovered
    /// nothing.
    pub fn rejected_recovered_symbols(&self) -> usize {
        self.rejected_recovered_symbols
    }

    /// Restore a received parity shard to this decoder's full shard length.
    ///
    /// A sender may cap a parity datagram at its group's longest information
    /// prefix: every shard byte past that prefix is the sender's zero pad, so
    /// the parity bytes there are zero as well and the cap loses no
    /// information.  The shard is zero-extended to `symbol_size`, which both
    /// keeps that cap lossless and satisfies `reconstruct_data`'s requirement
    /// that every present shard have the same length.  A shard longer than
    /// `symbol_size` cannot come from a conforming peer, so it is rejected
    /// rather than silently trimmed.
    fn parity_symbol(&self, received: &[u8]) -> Option<Vec<u8>> {
        if received.len() > self.symbol_size {
            return None;
        }
        let mut symbol = received.to_vec();
        symbol.resize(self.symbol_size, 0);
        Some(symbol)
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use crate::en::FecEncoder;
    use crate::proto::DATA_SYMBOL_HDR_SIZE;

    use super::FecDecoder;

    const SYMBOL_SIZE: usize = 256;
    const PAYLOAD: [u8; 100] = [0xA5; 100];

    /// The wire layout of a FEC datagram: the group and symbol identity, then —
    /// for a parity — the group's data and parity counts, then the shard.
    fn parity_datagram(data_count: u8, parity_count: u8, body: &[u8]) -> Vec<u8> {
        let mut pkt = 0_u64.to_be_bytes().to_vec();
        pkt.push(1);
        pkt.push(data_count);
        pkt.push(parity_count);
        pkt.extend_from_slice(body);
        pkt
    }

    /// A parity whose shard reconstructs a member claiming a 0xFFFF-byte
    /// payload cannot fit its shard, so the member is dropped — and that drop is
    /// counted, since nothing else in the decoder sees it.
    #[test]
    fn a_rejected_recovered_symbol_is_counted() {
        let mut decoder = decoder();
        let mut delivered = 0_usize;
        assert!(
            decoder
                .decode(&parity_datagram(1, 1, &[0xFF; 8]), |_| delivered += 1)
                .is_none()
        );
        assert_eq!(delivered, 0, "a rejected symbol must not be delivered");
        assert_eq!(decoder.rejected_recovered_symbols(), 1);
    }

    fn decoder() -> FecDecoder {
        FecDecoder::builder()
            .window_size(NonZeroU64::new(1).unwrap())
            .symbol_size(SYMBOL_SIZE)
            .max_group_size(25)
            .build()
    }

    /// Encode two symbols into one group and return the first symbol's wire
    /// datagram, the group's parity datagram (trimmed to the group's information
    /// prefix), and the parity header length, so a caller can cap the parity at
    /// any prefix of the shard.
    fn group_with_parity() -> (Vec<u8>, Vec<u8>, usize) {
        let mut encoder = FecEncoder::builder().symbol_size(SYMBOL_SIZE).build();
        let mut wire = [0_u8; 2 * SYMBOL_SIZE];
        let first_len = encoder.encode_data(&[0x11; 100], &mut wire);
        let first = wire[..first_len].to_vec();
        encoder.encode_data(&PAYLOAD, &mut wire);
        let mut parity = encoder.flush_parities(1);
        let parity_len = parity.encode_parity(&mut wire).unwrap();
        (first, wire[..parity_len].to_vec(), crate::proto::HDR_SIZE)
    }

    /// Recover the group's second symbol from a parity datagram capped at
    /// `info_len` information bytes, with the first symbol present.
    fn recover_with_capped_parity(
        first: &[u8],
        parity: &[u8],
        hdr_len: usize,
        info_len: usize,
    ) -> Vec<Vec<u8>> {
        let mut decoder = decoder();
        assert!(
            decoder.decode(first, |_| {}).is_some(),
            "a present data symbol is delivered directly"
        );
        let mut recovered = Vec::new();
        decoder.decode(&parity[..hdr_len + info_len], |data| {
            recovered.push(data.to_vec());
        });
        recovered
    }

    /// A parity datagram carries information only up to the group's longest
    /// information prefix, and the encoder trims it there instead of sending the
    /// zero pad.  The decoder must zero-extend the received prefix back to the
    /// full shard length, because `reconstruct_data` rejects present shards of
    /// differing lengths as `IncorrectShardSize` and a group with a present
    /// sibling would otherwise recover nothing at all.
    #[test]
    fn capped_parity_prefix_recovers_the_missing_symbol_exactly() {
        let (first, parity, hdr_len) = group_with_parity();
        // A member's information prefix is its data-symbol header plus its
        // payload — a payload-only cap would drop the header's parity bytes.
        let info_len = DATA_SYMBOL_HDR_SIZE + PAYLOAD.len();
        assert_eq!(
            parity.len(),
            hdr_len + info_len,
            "the encoder must send the information prefix alone"
        );
        let recovered = recover_with_capped_parity(&first, &parity, hdr_len, info_len);
        assert_eq!(
            recovered.len(),
            1,
            "the capped parity must recover the missing symbol"
        );
        assert_eq!(recovered[0], PAYLOAD, "the recovered payload must be exact");
    }

    /// The cap's lower bound is load-bearing: the parity carries information
    /// over the members' data-symbol headers, so a cap short of the header
    /// still reconstructs a symbol (the group looks recovered) but yields wrong
    /// bytes.  The zero-extension cannot detect the shortfall, so this is the
    /// invariant a sender-side cap must respect.
    #[test]
    fn a_cap_short_of_the_data_symbol_header_corrupts_the_recovery() {
        let (first, parity, hdr_len) = group_with_parity();
        let info_len = DATA_SYMBOL_HDR_SIZE + PAYLOAD.len();
        let recovered = recover_with_capped_parity(&first, &parity, hdr_len, info_len - 1);
        assert_eq!(recovered.len(), 1, "the group still reconstructs a symbol");
        assert_ne!(
            recovered[0], PAYLOAD,
            "a cap short of the information prefix must not recover exact bytes"
        );
    }

    /// A peer that sends the zero pad explicitly is recovered identically: the
    /// trimmed tail is zero in the sender's pad and in the parity alike.
    #[test]
    fn a_full_shard_parity_recovers_the_missing_symbol_exactly() {
        let (first, parity, hdr_len) = group_with_parity();
        let mut untrimmed = parity;
        untrimmed.resize(hdr_len + SYMBOL_SIZE, 0);
        let recovered = recover_with_capped_parity(&first, &untrimmed, hdr_len, SYMBOL_SIZE);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0], PAYLOAD);
    }
}
