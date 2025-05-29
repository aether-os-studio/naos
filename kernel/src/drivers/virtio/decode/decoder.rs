use super::{Key, KeyDecoder, KeyType, Mouse, MouseDecoder};

pub struct Decoder();

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DecodeType {
    Key(Key, KeyType),
    Mouse(Mouse),
}

impl Decoder {
    /// decode the input event into type enum
    pub fn decode(etype: usize, code: usize, value: usize) -> Result<DecodeType, ()> {
        match etype {
            3 | 2 => Ok(DecodeType::Mouse(
                MouseDecoder::decode(code, value).unwrap(),
            )),
            1 => {
                if code >= 0x150 {
                    // Ok(DecodeType::Mouse(MouseDecoder::decode(code, value).unwrap()))
                    Err(())
                } else {
                    Ok(DecodeType::Key(
                        KeyDecoder::decode(code).unwrap(),
                        KeyDecoder::key_type(value).unwrap(),
                    ))
                }
            }
            _ => Err(()),
        }
    }

    /// convert the key enum into char
    pub fn convert_key(key: Key) -> Result<char, ()> {
        KeyDecoder::convert(key)
    }
}
