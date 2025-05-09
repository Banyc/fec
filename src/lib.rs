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
}
