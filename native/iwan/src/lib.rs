#![deny(unsafe_op_in_unsafe_fn)]

pub const IWAN_HEADER_LEN: usize = 8;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IwanHeader {
    pub kind: u8,
    pub encrypt: u8,
    pub sid_be: u16,
    pub token_be: u32,
}

#[repr(C)]
pub struct IwanPacketDesc {
    pub header: IwanHeader,
    pub payload: *const u8,
    pub payload_len: usize,
    pub key: *const u8,
    pub output: *mut u8,
    pub output_cap: usize,
}

#[inline]
fn write_header(dst: &mut [u8], header: IwanHeader) {
    dst[0] = header.kind;
    dst[1] = header.encrypt;
    dst[2..4].copy_from_slice(&header.sid_be.to_be_bytes());
    dst[4..8].copy_from_slice(&header.token_be.to_be_bytes());
}

#[inline]
fn xor_payload(dst: &mut [u8], src: &[u8], key: &[u8]) {
    debug_assert!(key.len() >= 8);
    let key = &key[..8];
    let mut offset = 0;
    while offset + 8 <= src.len() {
        for i in 0..8 {
            dst[offset + i] = src[offset + i] ^ key[i];
        }
        offset += 8;
    }
    while offset < src.len() {
        dst[offset] = src[offset] ^ key[offset & 7];
        offset += 1;
    }
}

/// Build one DATA frame. Returns the encoded length, or a negative error:
/// -1 invalid pointers, -2 output too small, -3 encrypted frame without key.
#[no_mangle]
pub unsafe extern "C" fn iwan_native_build_data(
    header: *const IwanHeader,
    payload: *const u8,
    payload_len: usize,
    key: *const u8,
    output: *mut u8,
    output_cap: usize,
) -> isize {
    if header.is_null() || output.is_null() || (payload_len != 0 && payload.is_null()) {
        return -1;
    }
    let required = match IWAN_HEADER_LEN.checked_add(payload_len) {
        Some(value) => value,
        None => return -2,
    };
    if output_cap < required {
        return -2;
    }
    if unsafe { (*header).encrypt } != 0 && key.is_null() {
        return -3;
    }
    let header = unsafe { *header };
    let payload = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let output = unsafe { std::slice::from_raw_parts_mut(output, required) };
    write_header(&mut output[..IWAN_HEADER_LEN], header);
    if header.encrypt != 0 {
        let key = unsafe { std::slice::from_raw_parts(key, 8) };
        xor_payload(&mut output[IWAN_HEADER_LEN..], payload, key);
    } else {
        output[IWAN_HEADER_LEN..].copy_from_slice(payload);
    }
    required as isize
}

/// Build a batch without retaining any caller pointers after the call.
/// Returns the number of successful frames, or a negative validation error.
#[no_mangle]
pub unsafe extern "C" fn iwan_native_build_batch(
    packets: *const IwanPacketDesc,
    count: usize,
) -> isize {
    if count != 0 && packets.is_null() {
        return -1;
    }
    let packets = unsafe { std::slice::from_raw_parts(packets, count) };
    for packet in packets {
        let result = unsafe {
            iwan_native_build_data(
                &packet.header,
                packet.payload,
                packet.payload_len,
                packet.key,
                packet.output,
                packet.output_cap,
            )
        };
        if result < 0 {
            return result;
        }
    }
    count as isize
}

#[no_mangle]
pub extern "C" fn iwan_native_abi_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn c_abi_layout_is_stable() {
        assert_eq!(std::mem::size_of::<IwanHeader>(), 8);
        assert_eq!(std::mem::align_of::<IwanHeader>(), 4);
        assert_eq!(std::mem::size_of::<IwanPacketDesc>(), 48);
    }

    #[test]
    fn builds_plain_and_encrypted_frames() {
        let header = IwanHeader { kind: 0x14, encrypt: 0, sid_be: 7u16.to_be(), token_be: 11u32.to_be() };
        let payload = b"native iwan";
        let mut output = [0u8; 32];
        let written = unsafe { iwan_native_build_data(&header, payload.as_ptr(), payload.len(), ptr::null(), output.as_mut_ptr(), output.len()) };
        assert_eq!(written as usize, IWAN_HEADER_LEN + payload.len());
        assert_eq!(&output[8..written as usize], payload);

        let encrypted_header = IwanHeader { encrypt: 1, ..header };
        let key = [0x5au8; 8];
        let written = unsafe { iwan_native_build_data(&encrypted_header, payload.as_ptr(), payload.len(), key.as_ptr(), output.as_mut_ptr(), output.len()) };
        assert_eq!(written as usize, IWAN_HEADER_LEN + payload.len());
        for (actual, expected) in output[8..written as usize].iter().zip(payload) {
            assert_eq!(*actual, *expected ^ 0x5a);
        }
    }

    #[test]
    fn batch_rejects_short_output_without_claiming_success() {
        let header = IwanHeader { kind: 0x14, encrypt: 0, sid_be: 1, token_be: 2 };
        let payload = [1u8, 2, 3];
        let mut first = [0u8; 16];
        let mut second = [0u8; 8];
        let packets = [
            IwanPacketDesc { header, payload: payload.as_ptr(), payload_len: payload.len(), key: ptr::null(), output: first.as_mut_ptr(), output_cap: first.len() },
            IwanPacketDesc { header, payload: payload.as_ptr(), payload_len: payload.len(), key: ptr::null(), output: second.as_mut_ptr(), output_cap: second.len() },
        ];
        let result = unsafe { iwan_native_build_batch(packets.as_ptr(), packets.len()) };
        assert_eq!(result, -2);
        // The ABI reports failure for the whole batch; callers must discard
        // any frames built before the failing descriptor.
        assert_eq!(&first[..8], &[0x14, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(&second[..8], &[0; 8]);
    }
}
