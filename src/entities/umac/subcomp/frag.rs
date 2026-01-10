use std::cmp::min;

use crate::entities::umac::{pdus::{mac_end_dl::MacEndDl, mac_frag_dl::MacFragDl, mac_resource::MacResource}, subcomp::fillbits};
use crate::common::bitbuffer::BitBuffer;


#[derive(Debug)]
pub struct DlFragger {
    resource: MacResource,
    mac_hdr_is_written: bool,
    sdu: BitBuffer
}

/// We won't start fragmentation if less than MIN_SLOT_CAP_FOR_FRAG_START bits are free in the slot
const MIN_SLOT_CAP_FOR_FRAG_START: usize = 32; 



impl DlFragger {

    pub fn new(resource: MacResource, sdu: BitBuffer) -> Self {
        assert!(sdu.get_pos() == 0, "SDU must be at the start of the buffer");
        // We set the length field now. If we do fragmentation, we'll set it to -1 later. 
        // resource.update_len_and_fill_ind(sdu.get_len());
        DlFragger { 
            resource,
            mac_hdr_is_written: false,
            sdu
        }
    }

    /// Writes MAC-RESOURCE to dest_buf, starting fragmentation if needed. 
    /// Then, writes as many SDU bits as possible. 
    /// Returns true if the entire SDU was consumed, false if the PDU is fragmented
    /// and more chunks are needed.
    fn get_resource_chunk(&mut self, mac_block: &mut BitBuffer) -> bool {
        
        // Some sanity checks
        assert!(self.sdu.get_pos() == 0, "SDU must be at the start of the buffer");
        assert!(!self.mac_hdr_is_written, "MAC header should not be written yet");
        assert!(!(self.resource.is_null_pdu() && self.sdu.get_len_remaining() > 0), "Null PDU cannot have SDU data");
        
        // Compute len of full resource, including sdu and fill bits
        let hdr_len_bits = self.resource.compute_header_len();
        let sdu_len_bits = self.sdu.get_len_remaining();
        let num_fill_bits = fillbits::addition::compute_required_naive(hdr_len_bits + sdu_len_bits);
        let total_len_bits = hdr_len_bits + sdu_len_bits + num_fill_bits;
        let total_len_bytes = total_len_bits / 8;
        let slot_cap_bits = mac_block.get_len_remaining();

        // tracing::error!("hdr_len_bits: {}, sdu_len_bits: {}, num_fill_bits: {}, total_len_bits: {}, slot_cap_bits: {}", 
        //     hdr_len_bits, sdu_len_bits, num_fill_bits, total_len_bits, slot_cap_bits);  

        assert!(total_len_bits % 8 == 0 || total_len_bits == mac_block.get_len_remaining(), "PDU must fill slot or have byte aligned end");

        // Check if we can fit all in a single MAC-RESOURCE
        if total_len_bits <= slot_cap_bits {
            
            // Fits in one MAC-RESOURCE
            // let num_fill_bits = if self.resource.is_null_pdu() { 0 } else { (8 - (sdu_len % 8)) % 8 };
            // let sdu_bits = self.sdu.get_len_remaining();

            // Update PDU fields
            self.resource.length_ind = total_len_bytes as u8;
            self.resource.fill_bits = num_fill_bits > 0;

            // Write MAC-RESOURCE header, followed by TM-SDU, to MAC block
            self.resource.to_bitbuf(mac_block);
            mac_block.copy_bits(&mut self.sdu, sdu_len_bits);
            fillbits::addition::write(mac_block, Some(num_fill_bits));

            tracing::debug!("Creating MAC-RESOURCE, len: {} (sdu bits: {}), fillbits: {}, pdu: {:?}", 
                sdu_len_bits, sdu_len_bits, num_fill_bits, self.resource);
            tracing::debug!("buffer: {}", mac_block.dump_bin());

            // We're done with this packet
            self.mac_hdr_is_written = true;
            true
            
        } else if slot_cap_bits < MIN_SLOT_CAP_FOR_FRAG_START {
            
            // Not worth starting fragmentation here. Rather wait for a new slot 
            // We don't update self.mac_hdr_is_written and simply return that more work is needed
            false

        } else {

            // We need to start fragmentation. No fill bits are needed
            self.resource.length_ind = 0b111111; // Start of fragmentation
            self.resource.fill_bits = false;

            let sdu_bits = slot_cap_bits - hdr_len_bits;

            tracing::debug!("Creating MAC-RESOURCE (fragged), len: {} (sdu bits: {}, remaining: {})", 
                sdu_len_bits, sdu_bits, self.sdu.get_len_remaining() - sdu_bits);

            self.resource.to_bitbuf(mac_block);
            mac_block.copy_bits(&mut self.sdu, sdu_bits);
            
            // More fragments follow
            self.mac_hdr_is_written = true;
            false
        }
    }

    /// After MAC-RESOURCE was output using get_first_chunk, call this function to consume
    /// next chunks. Based on capacity, will determine whether to make a MAC-FRAG or
    /// MAC-END. 
    /// Returns true when MAC-END (DL) was created and no further fragments are needed
    /// TODO FIXME: support adding ChanAlloc element in MAC-END
    fn get_frag_or_end_chunk(&mut self, mac_block: &mut BitBuffer) -> bool {
        
        // Some sanity checks
        assert!(self.mac_hdr_is_written, "MAC header should be previously written");
        assert!(mac_block.get_len_written() % 8 == 0, "MAC block must be byte aligned at start of writing");

        // Check if we can fit all in a MAC-END message
        let sdu_bits = self.sdu.get_len_remaining();
        let macend_len_bits = MacEndDl::compute_hdr_len(false, false) + sdu_bits;
        let macend_len_bytes = (macend_len_bits + 7) / 8;
        let slot_cap = mac_block.get_len_remaining();

        // tracing::trace!("MAC-END would have length: {} bits, {} bytes, slot capacity: {} bits", 
        //     macend_len_bits, macend_len_bytes, slot_cap);
        
        if macend_len_bytes * 8 <= slot_cap {
            // Fits in single MAC-END
            let num_fill_bits = fillbits::addition::compute_required_naive(macend_len_bits);
            let pdu = MacEndDl {
                fill_bits: num_fill_bits > 0,
                pos_of_grant: 0, 
                length_ind: macend_len_bytes as u8,
                slot_granting_element: None,
                chan_alloc_element: None,
            };

            tracing::debug!("Creating MAC-END with length: {} (sdu bits: {}) slot capacity: {} bits", 
                macend_len_bits, sdu_bits, slot_cap);
        
            // Write MAC-END header followed by TM-SDU
            pdu.to_bitbuf(mac_block);
            mac_block.copy_bits(&mut self.sdu, sdu_bits);
            
            // Write fill bits (if needed)
            if num_fill_bits > 0 {
                mac_block.write_bit(1);
                mac_block.write_zeroes(num_fill_bits - 1);
            }
            // We're done with this packet
            true

        } else {

            // Need MAC-FRAG, fill slot (or don't fill, if the MAC-END hdr size is the reason we go for MAC-FRAG)
            let macfrag_hdr_len = 4;
            let sdu_bits_in_frag = min(slot_cap - macfrag_hdr_len, sdu_bits);
            let num_fill_bits = slot_cap - macfrag_hdr_len - sdu_bits_in_frag;

            tracing::debug!("Creating MAC-FRAG, sdu bits: {}, remaining {}, slot capacity: {}, fillbits: {}", 
                sdu_bits_in_frag, sdu_bits - sdu_bits_in_frag, slot_cap, num_fill_bits);

            let pdu = MacFragDl {
                fill_bits: num_fill_bits > 0,
            };
            pdu.to_bitbuf(mac_block);
            mac_block.copy_bits(&mut self.sdu, sdu_bits_in_frag);

            if num_fill_bits > 0 {
                mac_block.write_bit(1);
                mac_block.write_zeroes(num_fill_bits - 1);
            }

            false
        }
    }

    pub fn get_next_chunk(&mut self, mac_block: &mut BitBuffer) -> bool {
        if !self.mac_hdr_is_written {
            // First chunk, write MAC-RESOURCE
            self.get_resource_chunk(mac_block)
        } else {
            // Subsequent chunks, write MAC-FRAG or MAC-END
            self.get_frag_or_end_chunk(mac_block)
        }
    }
}



#[cfg(test)]
mod tests {
    use crate::{common::{address::{SsiType, TetraAddress}, bitbuffer::BitBuffer, debug}, entities::umac::{pdus::mac_resource::MacResource, subcomp::{bs_sched::{SCH_F_CAP, SCH_HD_CAP}, frag::DlFragger}}};

    fn get_default_resource() -> MacResource {
        MacResource {
            fill_bits: false,
            pos_of_grant: 0, 
            encryption_mode: 0,
            random_access_flag: false,
            length_ind: 0,
            addr: Some(TetraAddress {
                encrypted: false,
                ssi_type: SsiType::Ssi,
                ssi: 1234
            }),
            event_label: None,
            usage_marker: None,
            power_control_element: None,
            slot_granting_element: None,
            chan_alloc_element: None,
        }
    }    

    #[test]
    fn test_single_chunk() { 
        debug::setup_logging_verbose();
        let pdu = get_default_resource();
        let sdu = BitBuffer::from_bitstr("111000111");
        let mut mac_block = BitBuffer::new(SCH_F_CAP);
        
        let mut fragger = DlFragger::new(pdu, sdu);
        let done = fragger.get_next_chunk(&mut mac_block);

        assert!(done, "Should be done in single chunk");
        tracing::info!("MAC block: {}", mac_block.dump_bin());
    }

    #[test]
    fn test_two_chunks() { 
        debug::setup_logging_verbose();
        let pdu = get_default_resource();
        let sdu = BitBuffer::from_bitstr("010101100100110000101010100100101101010101100100000001101001100111001011111001010010001011101011000001001000110100001100");
        let mut mac_block1 = BitBuffer::new(SCH_HD_CAP);
        let mut mac_block2 = BitBuffer::new(SCH_HD_CAP);
        
        let mut fragger = DlFragger::new(pdu, sdu);
        let done = fragger.get_next_chunk(&mut mac_block1);
        tracing::info!("MAC block1: {}", mac_block1.dump_bin());
        assert!(!done, "Should take two blocks");
        let done = fragger.get_next_chunk(&mut mac_block2);
        tracing::info!("MAC block2: {}", mac_block2.dump_bin());
        assert!(done, "Should take two blocks");
    }

    #[test]
    fn test_four_chunks() {

    }

    #[test]
    fn test_semifilled() {

    }

    #[test]
    fn test_boundary_conditions() {

    }
}