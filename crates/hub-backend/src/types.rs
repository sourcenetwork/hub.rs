//! Commonware QMDB type aliases and codecs.

use alloy_primitives::U256;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
use commonware_utils::sequence::FixedBytes;
use hub_qmdb::AccountEncoding;

/// 20-byte account key (the EVM address).
pub type AccountKey = FixedBytes<20>;
/// 60-byte storage key (address, generation, slot).
pub type StorageKey = FixedBytes<60>;
/// 32-byte code key (the code hash).
pub type CodeKey = FixedBytes<32>;

#[derive(Clone, Debug)]
/// Fixed-size encoded account record.
pub struct AccountValue(pub [u8; AccountEncoding::SIZE]);

impl Write for AccountValue {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.0);
    }
}

impl EncodeSize for AccountValue {
    fn encode_size(&self) -> usize {
        AccountEncoding::SIZE
    }
}

impl Read for AccountValue {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < AccountEncoding::SIZE {
            return Err(CodecError::EndOfBuffer);
        }
        let mut out = [0u8; AccountEncoding::SIZE];
        buf.copy_to_slice(&mut out);
        Ok(Self(out))
    }
}

#[derive(Clone, Copy, Debug)]
/// Storage slot value.
pub struct StorageValue(pub U256);

impl Write for StorageValue {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.0.to_be_bytes::<32>());
    }
}

impl EncodeSize for StorageValue {
    fn encode_size(&self) -> usize {
        32
    }
}

impl Read for StorageValue {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < 32 {
            return Err(CodecError::EndOfBuffer);
        }
        let mut out = [0u8; 32];
        buf.copy_to_slice(&mut out);
        Ok(Self(U256::from_be_bytes(out)))
    }
}

#[cfg(test)]
mod tests {
    use commonware_codec::{DecodeExt, Encode};

    use super::*;

    #[test]
    fn test_account_value_roundtrip() {
        let mut data = [0u8; AccountEncoding::SIZE];
        data[0] = 0x42;
        data[79] = 0xFF;
        let value = AccountValue(data);

        let encoded = value.encode();
        let decoded = AccountValue::decode(encoded).unwrap();
        assert_eq!(decoded.0, data);
    }

    #[test]
    fn test_account_value_encode_size() {
        let value = AccountValue([0u8; AccountEncoding::SIZE]);
        assert_eq!(value.encode_size(), AccountEncoding::SIZE);
    }

    #[test]
    fn test_storage_value_roundtrip() {
        let value = StorageValue(U256::from(12345678u64));
        let encoded = value.encode();
        let decoded = StorageValue::decode(encoded).unwrap();
        assert_eq!(decoded.0, value.0);
    }

    #[test]
    fn test_storage_value_max() {
        let value = StorageValue(U256::MAX);
        let encoded = value.encode();
        let decoded = StorageValue::decode(encoded).unwrap();
        assert_eq!(decoded.0, U256::MAX);
    }

    #[test]
    fn test_storage_value_encode_size() {
        let value = StorageValue(U256::ZERO);
        assert_eq!(value.encode_size(), 32);
    }
}
