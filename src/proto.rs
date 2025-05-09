use std::{
    io::{self, Read, Write},
    num::NonZeroU8,
};

pub const fn symbol_size(mss: usize) -> Option<usize> {
    mss.checked_sub(HDR_SIZE)
}
pub const fn data_mss(mss: usize) -> Option<usize> {
    match symbol_size(mss) {
        Some(symbol_size) => symbol_size.checked_sub(DATA_SYMBOL_HDR_SIZE),
        None => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) struct PacketHeader {
    pub symbol_global_id: SymbolGlobalId,
    pub parity: Option<ParityHeader>,
}
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) struct SymbolGlobalId {
    pub group_id: u64,
    pub symbol_id: u8,
}
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) struct ParityHeader {
    pub data_count: NonZeroU8,
    pub parity_count: u8,
}

pub(crate) fn data_to_symbol(data: &[u8], symbol_size: usize) -> Vec<u8> {
    let mut symbol = vec![0; symbol_size];
    let hdr_len = encode_data_symbol_hdr(data.len().try_into().unwrap(), &mut symbol);
    let symbol_data_buf = &mut symbol[hdr_len..];
    let len = symbol_data_buf.len().min(data.len());
    symbol_data_buf[..len].copy_from_slice(&data[..len]);
    symbol
}
pub(crate) fn symbol_to_data(symbol: &[u8], buf: &mut [u8]) -> Option<usize> {
    let (hdr_len, data_len) = decode_data_symbol_hdr(symbol)?;
    let data_buf = &symbol[hdr_len..];
    let data = &data_buf[..data_len.into()];
    let len = buf.len().min(data.len());
    buf[..len].copy_from_slice(&data[..len]);
    Some(len)
}
#[cfg(test)]
#[test]
fn test_data_symbol_conversion() {
    let data = &[1, 2, 3, 4, 5];
    let symbol_size = 1024;
    let symbol = data_to_symbol(data, symbol_size);
    assert_eq!(symbol.len(), symbol_size);
    let data_buf = &mut [0; 5];
    let n = symbol_to_data(&symbol, data_buf).unwrap();
    assert_eq!(data, &data_buf[..n]);
}

pub const DATA_SYMBOL_HDR_SIZE: usize = 2;
pub(crate) fn encode_data_symbol_hdr(data_size: u16, buf: &mut [u8]) -> usize {
    let mut wtr = io::Cursor::new(buf);
    let _ = wtr.write_all(&data_size.to_be_bytes());
    wtr.position().try_into().unwrap()
}
pub(crate) fn decode_data_symbol_hdr(buf: &[u8]) -> Option<(usize, u16)> {
    let mut rdr = io::Cursor::new(buf);
    let mut len = 0_u16.to_be_bytes();
    rdr.read_exact(&mut len).ok()?;
    Some((rdr.position().try_into().unwrap(), u16::from_be_bytes(len)))
}
#[cfg(test)]
#[test]
fn test_data_symbol_hdr() {
    let buf = &mut [0; 10];
    let n = encode_data_symbol_hdr(3, buf);
    let (n_, data_size) = decode_data_symbol_hdr(buf).unwrap();
    assert_eq!(n, n_);
    assert_eq!(data_size, 3);
}

pub const HDR_SIZE: usize = 11;
pub(crate) fn encode_hdr(hdr: PacketHeader, buf: &mut [u8]) -> usize {
    let mut wtr = io::Cursor::new(buf);
    let group_id = hdr.symbol_global_id.group_id.to_be_bytes();
    let _ = wtr.write_all(&group_id[..]);
    let symbol_id = hdr.symbol_global_id.symbol_id.to_be_bytes();
    let _ = wtr.write_all(&symbol_id[..]);
    match hdr.parity {
        Some(parity) => {
            let data_count = parity.data_count.get().to_be_bytes();
            let _ = wtr.write_all(&data_count[..]);
            let parity_size = parity.parity_count.to_be_bytes();
            let _ = wtr.write_all(&parity_size[..]);
        }
        None => {
            let _ = wtr.write_all(&[0]);
        }
    }
    wtr.position().try_into().unwrap()
}
pub(crate) fn decode_hdr(buf: &[u8]) -> Option<(PacketHeader, usize)> {
    let mut rdr = io::Cursor::new(buf);
    let mut group_id = 0_u64.to_be_bytes();
    rdr.read_exact(&mut group_id).ok()?;
    let mut symbol_id = 0_u8.to_be_bytes();
    rdr.read_exact(&mut symbol_id).ok()?;
    let mut data_count = 0_u8.to_be_bytes();
    rdr.read_exact(&mut data_count).ok()?;
    let data_count = u8::from_be_bytes(data_count);
    let parity = match NonZeroU8::new(data_count) {
        None => None,
        Some(data_count) => {
            let mut parity_size = 0_u8.to_be_bytes();
            rdr.read_exact(&mut parity_size).ok()?;
            let parity_size = u8::from_be_bytes(parity_size);
            Some(ParityHeader {
                data_count,
                parity_count: parity_size,
            })
        }
    };
    let hdr = PacketHeader {
        symbol_global_id: SymbolGlobalId {
            group_id: u64::from_be_bytes(group_id),
            symbol_id: u8::from_be_bytes(symbol_id),
        },
        parity,
    };
    let pos = rdr.position().try_into().ok()?;
    Some((hdr, pos))
}
#[cfg(test)]
#[test]
fn test_hdr() {
    let hdrs = &[
        PacketHeader {
            symbol_global_id: SymbolGlobalId {
                group_id: 2,
                symbol_id: 3,
            },
            parity: None,
        },
        PacketHeader {
            symbol_global_id: SymbolGlobalId {
                group_id: 2,
                symbol_id: 3,
            },
            parity: Some(ParityHeader {
                data_count: NonZeroU8::new(4).unwrap(),
                parity_count: 5,
            }),
        },
    ];
    for hdr in hdrs {
        let buf = &mut [0; 1024];
        let n = encode_hdr(*hdr, buf);
        let (hdr_, n_) = decode_hdr(buf).unwrap();
        assert_eq!(*hdr, hdr_);
        assert_eq!(n, n_);
    }
}
