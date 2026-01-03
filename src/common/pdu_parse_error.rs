#[derive(Debug, PartialEq, Eq)]
pub enum PduParseError {
    InvalidPduType { expected: u64, found: u64 },
    BufferEnded { field: &'static str },
    InvalidObitValue,
    InvalidType3ElemId { found: u64 },
    InvalidValue{ field: &'static str, value: u64 }
}

#[macro_export]
macro_rules! expect_pdu_type {
    ($value:expr, $expected:expr) => {{
        let raw_expected = $expected.into_raw();
        if $value == raw_expected {
            Ok(())
        } else {
            Err($crate::common::pdu_parse_error::PduParseError::InvalidPduType {
                expected: raw_expected as u64,
                found: $value,
            })
        }
    }};
}

#[macro_export]
macro_rules! expect_value {
    ($value:ident, $expected:expr) => {
        $crate::expect_value!(@inner $value, $expected, stringify!($value))
    };
    ($value:expr, $expected:expr, $field:expr) => {
        $crate::expect_value!(@inner $value, $expected, $field)
    };

    (@inner $value:expr, $expected:expr, $field:expr) => {{
        let val = $value;
        if val == $expected {
            Ok(())
        } else {
            Err($crate::common::pdu_parse_error::PduParseError::InvalidValue {
                field: $field,
                value: val,
            })
        }
    }};
}

#[macro_export]
macro_rules! let_field {
    ($buf:expr, $ident:ident, $bits:expr) => {
        let $ident = $buf.read_field($bits, stringify!($ident))?;
    };
}
