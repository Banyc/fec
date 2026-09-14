extern crate reed_solomon_erasure;

pub mod de;
pub mod en;
pub mod proto;

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use crate::{
        de::FecDecoder,
        en::FecEncoder,
        proto::{data_mss, symbol_size},
    };

    #[test]
    fn en_de_data() {
        const MSS: usize = 16;
        let symbol_size = symbol_size(MSS).unwrap();
        let data_mss = data_mss(MSS).unwrap();
        let mut en = FecEncoder::builder().symbol_size(symbol_size).build();
        let mut de = FecDecoder::builder()
            .symbol_size(symbol_size)
            .max_group_size(20)
            .window_size(NonZeroU64::new(32).unwrap())
            .build();
        assert_eq!(en.group_data_count(), 0);
        let data = &[0, 1, 2];
        assert!(data.len() <= data_mss);
        let buf = &mut [0; 14];
        let n = en.encode_data(data, buf);
        let pkt = &buf[..n];
        let n = de.decode(pkt, |_| panic!()).unwrap();
        let data_ = &pkt[n..];
        assert_eq!(data, data_);
    }

    #[test]
    fn en_de_parity() {
        const MSS: usize = 16;
        let symbol_size = symbol_size(MSS).unwrap();
        let data_mss = data_mss(MSS).unwrap();
        let mut en = FecEncoder::builder().symbol_size(symbol_size).build();
        let mut de = FecDecoder::builder()
            .symbol_size(symbol_size)
            .max_group_size(20)
            .window_size(NonZeroU64::new(32).unwrap())
            .build();
        assert_eq!(en.group_data_count(), 0);
        let data = &[0, 1, 2];
        assert!(data.len() <= data_mss);
        let buf = &mut [0; MSS];
        let n = en.encode_data(data, buf);
        let _lost_pkt = &buf[..n];
        assert_eq!(en.group_data_count(), 1);
        let mut parity_en = en.flush_parities(1);
        let n = parity_en.encode_parity(buf).unwrap();
        let pkt = &buf[..n];
        let mut recovered = vec![];
        assert!(de.decode(pkt, |pkt| recovered.push(pkt.to_vec())).is_none());
        assert_eq!(recovered.len(), 1);
        let data_ = &recovered[0];
        assert_eq!(&data[..], &data_[..]);
    }

    /// A parity datagram carries information only up to the open group's longest
    /// member prefix (its data-symbol header plus payload): every shard byte past
    /// that prefix is the zero pad, so the parity bytes there are zero too and
    /// trimming them loses nothing.  The interactive lane's small messages are
    /// exactly this case, so the trim is what keeps prompt parity affordable on
    /// the wire.
    #[test]
    fn parity_is_trimmed_to_the_groups_longest_information_prefix() {
        const SYMBOL_SIZE: usize = 256;
        let mut en = FecEncoder::builder().symbol_size(SYMBOL_SIZE).build();
        let buf = &mut [0; SYMBOL_SIZE];
        en.encode_data(&[0x11; 100], buf);
        en.encode_data(&[0x22; 40], buf);
        let mut parity_en = en.flush_parities(1);
        let n = parity_en.encode_parity(buf).unwrap();
        assert_eq!(
            n - crate::proto::HDR_SIZE,
            crate::proto::DATA_SYMBOL_HDR_SIZE + 100,
            "the parity shard must stop at the longest member's information prefix"
        );
        assert!(
            n < SYMBOL_SIZE + crate::proto::HDR_SIZE,
            "the padded tail must not go out on the wire"
        );
    }

    /// The trimmed parity still reconstructs every member exactly: the receiver
    /// zero-extends it back to the shard length, and the trimmed tail is zero in
    /// the sender's pad and in the parity alike.
    #[test]
    fn a_trimmed_parity_reconstructs_each_member_exactly() {
        const SYMBOL_SIZE: usize = 256;
        let first = &[0x11; 100];
        let second = &[0x22; 40];
        let buf = &mut [0; SYMBOL_SIZE];

        let mut en = FecEncoder::builder().symbol_size(SYMBOL_SIZE).build();
        let n = en.encode_data(first, buf);
        let first_pkt = buf[..n].to_vec();
        let n = en.encode_data(second, buf);
        let second_pkt = buf[..n].to_vec();
        let mut parity_en = en.flush_parities(1);
        let n = parity_en.encode_parity(buf).unwrap();
        let parity_pkt = buf[..n].to_vec();

        let recover = |present: &[u8]| {
            let mut de = FecDecoder::builder()
                .symbol_size(SYMBOL_SIZE)
                .max_group_size(20)
                .window_size(NonZeroU64::new(32).unwrap())
                .build();
            assert!(de.decode(present, |_| panic!()).is_some());
            let mut recovered = vec![];
            de.decode(&parity_pkt, |pkt| recovered.push(pkt.to_vec()));
            recovered
        };
        assert_eq!(recover(&second_pkt), vec![first.to_vec()]);
        assert_eq!(recover(&first_pkt), vec![second.to_vec()]);
    }
}
