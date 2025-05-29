//! # VirtIO 输入设备解码器
//! 仅包含部分键盘按键、鼠标的按键解码（virtio）
//! 解码需要传入 event_type、code、value 三个值
//! 鼠标滚轮会同时以 1、2 编码 even_type，为了避免出错，解码器只处理编号 2
//! # VirtIO Input Decoder
//! Only support part of keyboard and mouse input.
//! You should provide event_type, code and value to the deocder
//! MouseScroll has event_type both 1 and 2, in case of resulting error, decoder will only deal
//! with the event_type 2 for mouse scroll
//! ## Example
//! ```rust
//! use virtio_input_decoder::{
//!     Decoder, Mouse, DecodeType
//! };
//! let mouse = Decoder::decode(2, 8, 1).unwrap();
//! assert_eq!(mouse, DecodeType::Mouse(Mouse::ScrollUp));
//! ```
//!
//! 2021年4月15日 zg

mod decoder;
mod key;
mod mouse;
use key::KeyDecoder;
use mouse::MouseDecoder;

pub use decoder::{DecodeType, Decoder};
pub use key::{Key, KeyType};
pub use mouse::Mouse;
