/// Helper functions for dealing with type2, type3 and type4 fields for MLE, CMCE, MM and SNDCP PDUs.

pub mod delimiters {
    use crate::common::{bitbuffer::BitBuffer, pdu_parse_error::PduParseError};

    /// Read the o-bit between type1 and type2/type3 elements
    pub fn read_obit(buffer: &mut BitBuffer) -> Result<bool, PduParseError> {
        Ok(buffer.read_field(1, "obit")? == 1)
    }

    /// Write the o-bit between type1 and type2/type3 elements
    pub fn write_obit(buffer: &mut BitBuffer, val: u8) {
        buffer.write_bit(val);
    }

    /// Read a p-bit preceding a type2 element
    pub fn read_pbit(buffer: &mut BitBuffer) -> Result<bool, PduParseError>{
        Ok(buffer.read_field(1, "pbit")? == 1)
    }

    /// Write the p-bit preceding a type2 element
    pub fn write_pbit(buffer: &mut BitBuffer, val: u8) {
        buffer.write_bit(val);
    }

    /// Read an m-bit found before a type3 or type4 element, and trailing the message
    pub fn read_mbit(buffer: &mut BitBuffer) -> Result<bool, PduParseError>{
        Ok(buffer.read_field(1, "mbit")? == 1)
    }

    /// Write the m-bit before a type3 or type4 element, and trailing the message
    pub fn write_mbit(buffer: &mut BitBuffer, val: u8) {
        buffer.write_bit(val);
    }
}

pub mod type2 {
    use crate::common::{bitbuffer::BitBuffer, pdu_parse_error::PduParseError};

    use super::delimiters;

    pub fn parse(buffer: &mut BitBuffer, num_bits: usize, field_name: &'static str) -> Result<Option<u64>, PduParseError> {
        match delimiters::read_pbit(buffer) {
            Ok(true) => {
                match buffer.read_field(num_bits, field_name) {
                    Ok(v) => Ok(Some(v)),
                    Err(e) => Err(e),
                }
            },
            Ok(false) => Ok(None), // Field not present
            Err(e) => Err(e),
        }
    }

    /// Parse a Type-2 element into a struct that implements `from_bitbuf`.
    pub fn parse_struct<T, F>(
        buffer: &mut BitBuffer, 
        parser: F
    ) -> Result<Option<T>, PduParseError> 
    where
        F: FnOnce(&mut BitBuffer) -> Result<T, PduParseError>
    {
        match delimiters::read_pbit(buffer) {
            Ok(true) => {
                let value = parser(buffer)?;
                Ok(Some(value))
            },
            Ok(false) => Ok(None), // Field not present
            Err(e) => Err(e),
        }
    }

    /// Write one Type-2 element.
    /// If `value` is `Some(v)`, writes P-bit=1 then `len` bits of `v`. If `None`, writes P-bit=0.
    pub fn write(buffer: &mut BitBuffer, value: Option<u64>, len: usize) {
        match value {
            Some(v) => {
                delimiters::write_pbit(buffer, 1);
                buffer.write_bits(v, len);
            }
            None => {
                delimiters::write_pbit(buffer, 0);
            }
        }
    }

    /// Write a Type-2 element from a struct that implements `to_bitbuf`.
    pub fn write_struct<T, F>(
        buffer: &mut BitBuffer,
        value: &Option<T>,
        writer: F
    ) -> Result<(), PduParseError>
    where
        F: Fn(&T, &mut BitBuffer) -> Result<(), PduParseError>
    {
        match value {
            Some(v) => {
                delimiters::write_pbit(buffer, 1);
                writer(v, buffer)?;
                Ok(())
            },
            None => {
                delimiters::write_pbit(buffer, 0);
                Ok(())
            }
        }
    }    
}

pub mod type34 {
    use crate::common::{bitbuffer::BitBuffer, pdu_parse_error::PduParseError, typed_pdu_fields::delimiters::{write_mbit}};

    #[derive(Debug, PartialEq, Eq)]
    pub enum Type34Err {
        FieldNotPresent,
        InvalidId,
        OutOfBounds,
    }

    /// Read the m-bit for a type3 or type4 element without advancing the buffer pos
    fn check_peek_mbit(buffer: &BitBuffer) -> Result<bool, Type34Err> {
        match buffer.peek_bits(1) {
            Some(0) => Err(Type34Err::FieldNotPresent),
            Some(1) => Ok(true), // Field is present
            None => Err(Type34Err::OutOfBounds),
            _ => panic!() // Never happens
        }
    }

    /// Returns Ok() if next field is the desired field, or Err(FieldNotPresent) if not.
    fn check_peek_id(buffer: &BitBuffer, expected_id: u64) -> Result<(), Type34Err> {
        let id_bits = match buffer.peek_bits_posoffset(1, 4) {
            Some(x) => x,
            None => return Err(Type34Err::OutOfBounds),
        };

        if id_bits == expected_id {
            Ok(())
        } else {
            Err(Type34Err::FieldNotPresent)
        }
    }

    pub fn parse_type3_generic(buffer: &mut BitBuffer, expected_id: u64) -> Result<(usize, u64), Type34Err> { 

        // Check that more elements are present. Returns FieldNotPresent if mbit is 0
        check_peek_mbit(buffer)?;

        // Check that next element is our searched id
        check_peek_id(buffer, expected_id)?;

        // Target field is present. Advance buffer position and read field contents
        buffer.seek_rel(5);
        let len_bits = match buffer.read_bits(11) {
            Some(x) => x as usize,
            None => return Err(Type34Err::OutOfBounds),
        };
        let data = match buffer.read_bits(len_bits) {
            Some(x) => x,
            None => return Err(Type34Err::OutOfBounds),
        };
        Ok((len_bits, data))
    }

    /// Parse a Type-3 element into a struct that implements `from_bitbuf`.
    /// Validates the m-bit and element ID, then calls the parser function directly on the buffer if present.
    pub fn parse_type3_struct<E, T, F>(
        buffer: &mut BitBuffer,
        expected_id: E,
        parser: F
    ) -> Result<Option<T>, Type34Err>
    where
        E: Into<u64>,
        F: FnOnce(&mut BitBuffer) -> Result<T, PduParseError>
    {
        // Check that more elements are present
        match check_peek_mbit(buffer) {
            Ok(_) => {},
            Err(Type34Err::FieldNotPresent) => return Ok(None),
            Err(e) => return Err(e),
        }

        // Check that next element is our searched id
        match check_peek_id(buffer, expected_id.into()) {
            Ok(_) => {},
            Err(Type34Err::FieldNotPresent) => return Ok(None),
            Err(e) => return Err(e),
        }

        // Target field is present. Advance buffer past m-bit (1) + id (4) + length (11)
        buffer.seek_rel(5); // m-bit + id
        let _len_bits = match buffer.read_bits(11) {
            Some(x) => x as usize,
            None => return Err(Type34Err::OutOfBounds),
        };

        // Now buffer is positioned at the data. Parse the struct directly.
        // The parser is responsible for reading exactly len_bits
        match parser(buffer) {
            Ok(value) => Ok(Some(value)),
            Err(_) => Err(Type34Err::OutOfBounds),
        }
    }


    /// Write an optional Type-3 element using a `to_bitbuf` function.
    pub fn write_type3_struct<E, T, F>(
        buffer: &mut BitBuffer,
        value: &Option<T>,
        field_id: E,
        writer: F
    ) -> Result<(), PduParseError>
    where
        E: Into<u64>,
        F: Fn(&T, &mut BitBuffer) -> Result<(), PduParseError>
    {
        if let Some(elem) = value {
            // Write m-bit and 4-bit field ID, then write the element itself
            write_type34_header_generic(buffer, field_id.into());
            writer(elem, buffer)?;
        } else {
            // Don't write anything (no m-bit)
        }
        Ok(())
    }

    pub fn parse_type4_header_generic(buffer: &mut BitBuffer, expected_id: u64) -> Result<(usize, usize), Type34Err> { 
        // Check that more elements are present. Returns FieldNotPresent if mbit is 0
        check_peek_mbit(buffer)?;

        // Check that next element is our searched id
        check_peek_id(buffer, expected_id)?;

        // Target field is present. Advance buffer position and read field contents
        buffer.seek_rel(5);
        let len_bits = match buffer.read_bits(11) {
            Some(x) => x as usize,
            None => return Err(Type34Err::OutOfBounds),
        };
        // tracing::debug!("MmType4FieldUl: len_bits: {}", len_bits);
        let num_elems = match buffer.read_bits(6) {
            Some(x) => x as usize,
            None => return Err(Type34Err::OutOfBounds),
        };

        Ok((num_elems, len_bits-6))
    }

    /// Write the type4 header start (1-bit mbit + 4-bit field type)
    pub fn write_type34_header_generic(buffer: &mut BitBuffer, field_type: u64) {
        write_mbit(buffer, 1);
        buffer.write_bits(field_type, 4);
    }

    /// Parse a Type-4 element into a Vec of structs that implement `from_bitbuf`.
    pub fn parse_type4_struct<E, T, F>(
        buffer: &mut BitBuffer,
        expected_id: E,
        parser: F
    ) -> Result<Option<Vec<T>>, Type34Err>
    where
        E: Into<u64>,
        F: Fn(&mut BitBuffer) -> Result<T, PduParseError>
    {
        match parse_type4_header_generic(buffer, expected_id.into()) {
            Ok((num_elems, _len_bits)) => {
                let mut elems = Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    match parser(buffer) {
                        Ok(elem) => elems.push(elem),
                        Err(_) => return Err(Type34Err::OutOfBounds),
                    }
                }
                Ok(Some(elems))
            },
            Err(e) => {
                if matches!(e, Type34Err::FieldNotPresent) {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Write a Type-4 element from a Vec of structs using a `to_bitbuf` function.
    pub fn write_type4_struct<E, T, F>(
        buffer: &mut BitBuffer,
        value: &Option<Vec<T>>,
        field_id: E,
        writer: F
    ) -> Result<(), PduParseError>
    where
        E: Into<u64>,
        F: Fn(&T, &mut BitBuffer) -> Result<(), PduParseError>
    {
        if let Some(elems) = value {
            if elems.is_empty() {
                // todo fixme we need to check the standards docs for knowing what to do here
                tracing::warn!("write_type4_struct called with empty elems vec. Check standard to see what is proper behavior");
            }

            // Write m-bit and field ID
            write_type34_header_generic(buffer, field_id.into());
            
            // Reserve space for length (11 bits) + num_elems (6 bits)
            let pos_len_field = buffer.get_raw_pos();
            buffer.write_bits(0, 17); // 11 + 6
            
            // Write all elements
            for elem in elems {
                writer(elem, buffer)?;
            }
            
            // Calculate actual length and backfill
            let pos_end = buffer.get_raw_pos();
            let len_bits = (pos_end - pos_len_field - 11) as u64;  // Total length minus the 11-bit length field itself
            let num_elems = elems.len() as u64;
            
            buffer.set_raw_pos(pos_len_field);
            buffer.write_bits(len_bits, 11);
            buffer.write_bits(num_elems, 6);
            buffer.set_raw_pos(pos_end);
        }
        // If None, don't write anything (no m-bit)
        Ok(())
    }
}