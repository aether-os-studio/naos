pub struct MouseDecoder();

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Mouse {
    ScrollUp,
    ScrollDown,
    X(usize),
    Y(usize),
}

impl MouseDecoder {
    pub fn decode(code: usize, value: usize) -> Result<Mouse, ()> {
        if code == 8 && value == 1 || code == 0x151 && value == 0 {
            Ok(Mouse::ScrollUp)
        } else if code == 8 && value == 0xffffffff || code == 0x150 && value == 0 {
            Ok(Mouse::ScrollDown)
        } else if code == 0 {
            Ok(Mouse::X(value))
        } else if code == 1 {
            Ok(Mouse::Y(value))
        } else {
            Err(())
        }
    }
}
