use core::fmt;

use crate::common::pdu_parse_error::PduParseError;
use crate::common::bitbuffer::BitBuffer;
use crate::common::typed_pdu_fields;
use crate::expect_pdu_type;
use crate::entities::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use crate::entities::mm::enums::type34_elem_id_ul::MmType34ElemIdUl;
use crate::entities::mm::components::type34_fields::{MmType3FieldUl,MmType4FieldUl};
use crate::entities::mm::fields::group_identity_uplink::GroupIdentityUplink;

/// Representation of the U-ATTACH/DETACH GROUP IDENTITY PDU (Clause 16.9.3.1).
/// The MS sends this message to the infrastructure to indicate attachment/detachment of group identities in the MS or to initiate a group report request or give a group report response.
/// Response expected: D-ATTACH/DETACH GROUP IDENTITY ACKNOWLEDGEMENT
/// Response to: -/D-ATTACH/DETACH GROUP IDENTITY (report request)

#[derive(Debug)]
pub struct UAttachDetachGroupIdentity {
    /// Type1, 1 bits, Group identity report
    pub group_identity_report: bool,
    /// Type1, 1 bits, Group identity attach/detach mode. 0 = amendment, 1 = detach all and attach to specified groups
    pub group_identity_attach_detach_mode: bool,
    /// Type3, Group report response
    pub group_report_response: Option<MmType3FieldUl>,
    /// Type4, Group identity uplink
    pub group_identity_uplink: Option<Vec<GroupIdentityUplink>>,
    /// Type3, Proprietary
    pub proprietary: Option<MmType3FieldUl>,
}

#[allow(unreachable_code)] // TODO FIXME review, finalize and remove this
impl UAttachDetachGroupIdentity {
    /// Parse from BitBuffer
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseError> {

        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeUl::UAttachDetachGroupIdentity)?;
        
        // Type1
        let group_identity_report = buffer.read_field(1, "group_identity_report")? != 0;
        // Type1
        let group_identity_attach_detach_mode = buffer.read_field(1, "group_identity_attach_detach_mode")? != 0;

        // obit designates presence of any further type2, type3 or type4 fields
        let mut obit = typed_pdu_fields::delimiters::read_obit(buffer)?;

        // Type3 - stores raw data, so use existing approach
        let group_report_response = if obit { 
            match MmType3FieldUl::parse(buffer, MmType34ElemIdUl::GroupReportResponse) {
                Ok(value) => Some(value),
                Err(_) => None
            }
        } else { None };
        
        // Type4 - parses to structs, use generic helper
        let group_identity_uplink = typed_pdu_fields::type34::parse_type4_struct(
            buffer,
            MmType34ElemIdUl::GroupIdentityUplink,
            GroupIdentityUplink::from_bitbuf
        ).map_err(|_| PduParseError::BufferEnded { field: "group_identity_uplink" })?;
        
        // Type3 - stores raw data
        let proprietary = if obit { 
            match MmType3FieldUl::parse(buffer, MmType34ElemIdUl::Proprietary) {
                Ok(value) => Some(value),
                Err(_) => None
            }
        } else { None };
        
        // Read trailing mbit (if not previously encountered)
        obit = if obit { buffer.read_field(1, "trailing_obit")? == 1 } else { obit };

        if obit {
            return Err(PduParseError::InvalidObitValue);
        }

        Ok(UAttachDetachGroupIdentity { 
            group_identity_report, 
            group_identity_attach_detach_mode, 
            group_report_response, 
            group_identity_uplink, 
            proprietary
        })
    }

    /// Serialize this PDU into the given BitBuffer.
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseError> {
        // PDU Type
        buffer.write_bits(MmPduTypeUl::UAttachDetachGroupIdentity.into_raw(), 4);
        // Type1
        buffer.write_bits(self.group_identity_report as u64, 1);
        // Type1
        buffer.write_bits(self.group_identity_attach_detach_mode as u64, 1);

        // Check if any optional field present and place o-bit
        let obit_val = self.group_report_response.is_some() || self.group_identity_uplink.is_some() || self.proprietary.is_some() ;
        typed_pdu_fields::delimiters::write_obit(buffer, obit_val as u8);
        if !obit_val { return Ok(()); }

        // Type3
        if let Some(ref value) = self.group_report_response {
            MmType3FieldUl::write(buffer, value.field_type, value.data, value.len);
        }
        // Type4
        typed_pdu_fields::type34::write_type4_struct(
            buffer,
            &self.group_identity_uplink,
            MmType34ElemIdUl::GroupIdentityUplink,
            GroupIdentityUplink::to_bitbuf
        )?;
        // Type3
        if let Some(ref value) = self.proprietary {
            MmType3FieldUl::write(buffer, value.field_type, value.data, value.len);
        }
        // Write terminating m-bit
        typed_pdu_fields::delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for UAttachDetachGroupIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UAttachDetachGroupIdentity {{ group_identity_report: {:?} group_identity_attach_detach_mode: {:?} group_report_response: {:?} group_identity_uplink: {:?} proprietary: {:?} }}",
            self.group_identity_report,
            self.group_identity_attach_detach_mode,
            self.group_report_response,
            self.group_identity_uplink,
            self.proprietary,
        )
    }
}


#[cfg(test)]
mod tests {
    use crate::common::debug::setup_logging_default;

    use super::*;

    #[test]
    fn decode_encode_test() {

        setup_logging_default();
        let test_vec = "011101111000000001001000000010100000000110101000110011100000";
        let mut buffer = BitBuffer::from_bitstr(test_vec);

        // 0111 0 1 1 11000000001001000000010100000000110101000110011100000
        // |--| PDU type
        //      | | group identity report = 0, group identity attach/detach mode = 1 (reset all prev and reattach to specified groups)
        //          | obit: fields follow
        //            | mbit:  group report response is present
        //             |--| field_id = 8 GroupIdentityUplink
        //                 |---------| len = 000 0010 0100 0x24 = 36
        //                            |----------------------------------| 	field contents
        //                                                                | trailing mbit

        let pdu = match UAttachDetachGroupIdentity::from_bitbuf(&mut buffer) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing UAttachDetachGroupIdentity: {:?} {}", e, buffer.dump_bin());
                return;
            }
        };
        
        tracing::info!("Parsed: {:?}", pdu);
        tracing::info!("Buf at end: {}", buffer.dump_bin());

        let mut buf = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut buf).unwrap();
        tracing::info!("Serialized: {}", buf.dump_bin());
        assert_eq!(buf.to_bitstr(), test_vec);

    }
}
