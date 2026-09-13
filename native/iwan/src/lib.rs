#![deny(unsafe_op_in_unsafe_fn)]

pub const IWAN_HEADER_LEN: usize = 8;

pub const IWAN_CAP_TUN_VNET_HDR: u32 = 1 << 0;
pub const IWAN_CAP_TUN_MULTI_QUEUE: u32 = 1 << 1;
pub const IWAN_CAP_UDP_GRO: u32 = 1 << 2;
pub const IWAN_CAP_UDP_SEGMENT: u32 = 1 << 3;

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
fn xor_payload_in_place(dst: &mut [u8], key: &[u8]) {
    debug_assert!(key.len() >= 8);
    let key = &key[..8];
    let mut offset = 0;
    while offset + 8 <= dst.len() {
        for i in 0..8 {
            dst[offset + i] ^= key[i];
        }
        offset += 8;
    }
    while offset < dst.len() {
        dst[offset] ^= key[offset & 7];
        offset += 1;
    }
}

#[inline]
unsafe fn validate_data_inputs(
    header: *const IwanHeader,
    payload: *const u8,
    payload_len: usize,
    key: *const u8,
    output: *mut u8,
    output_cap: usize,
) -> Result<(IwanHeader, usize), isize> {
    if header.is_null() || output.is_null() || (payload_len != 0 && payload.is_null()) {
        return Err(-1);
    }
    // The ABI is byte-oriented and may be called by a packed C consumer. Read
    // the small header without imposing a Rust alignment requirement.
    let header_value = unsafe { std::ptr::read_unaligned(header) };
    let required = match IWAN_HEADER_LEN.checked_add(payload_len) {
        Some(value) => value,
        None => return Err(-2),
    };
    if output_cap < required {
        return Err(-2);
    }
    if header_value.encrypt != 0 && key.is_null() {
        return Err(-3);
    }
    Ok((header_value, required))
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
    let (header, required) = match unsafe {
        validate_data_inputs(header, payload, payload_len, key, output, output_cap)
    } {
        Ok(value) => value,
        Err(error) => return error,
    };
    // Copy the key before touching output. Apart from avoiding an aliasing
    // hazard, this lets callers keep key material in the same slab as input.
    let key_copy = if header.encrypt != 0 {
        let mut key_copy = [0u8; 8];
        unsafe { std::ptr::copy_nonoverlapping(key, key_copy.as_mut_ptr(), key_copy.len()) };
        Some(key_copy)
    } else {
        None
    };
    let output = unsafe { std::slice::from_raw_parts_mut(output, required) };
    // Use memmove semantics so an embedding caller may reuse one slab for
    // input and output. Move the payload before writing the header: the
    // destination header can otherwise overwrite an overlapping source.
    if payload_len != 0 {
        unsafe {
            std::ptr::copy(
                payload,
                output.as_mut_ptr().add(IWAN_HEADER_LEN),
                payload_len,
            );
        }
    }
    write_header(&mut output[..IWAN_HEADER_LEN], header);
    if let Some(key) = key_copy {
        xor_payload_in_place(&mut output[IWAN_HEADER_LEN..], &key);
    }
    required as isize
}

/// Build a batch without retaining any caller pointers after the call. The
/// descriptor array is preflighted before any output is touched, so a negative
/// result leaves every output buffer unchanged.
#[no_mangle]
pub unsafe extern "C" fn iwan_native_build_batch(
    packets: *const IwanPacketDesc,
    count: usize,
) -> isize {
    if count != 0 && packets.is_null() {
        return -1;
    }
    if count == 0 {
        return 0;
    }
    let packets = unsafe { std::slice::from_raw_parts(packets, count) };
    for packet in packets {
        if let Err(error) = unsafe {
            validate_data_inputs(
                &packet.header,
                packet.payload,
                packet.payload_len,
                packet.key,
                packet.output,
                packet.output_cap,
            )
        } {
            return error;
        }
    }
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

// Linux ioctl values are stable across the supported architectures. The
// probe is deliberately read-only: it never enables an offload or changes a
// socket, so a failed probe is safe to treat as a compatibility fallback.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "sparc64"
    )
))]
const TUNGETIFF: LibcUlong = 0x4004_54d2;
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "sparc64"
    ))
))]
const TUNGETIFF: LibcUlong = 0x8004_54d2;
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "sparc64"
    )
))]
const TUNGETVNETHDRSZ: LibcUlong = 0x4004_54d7;
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "sparc64"
    ))
))]
const TUNGETVNETHDRSZ: LibcUlong = 0x8004_54d7;
#[cfg(target_os = "linux")]
const IFF_MULTI_QUEUE: u16 = 0x0100;
#[cfg(target_os = "linux")]
const IFF_VNET_HDR: u16 = 0x4000;
#[cfg(target_os = "linux")]
type LibcUlong = usize;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn ioctl(fd: i32, request: LibcUlong, ...) -> i32;
    fn getsockopt(
        fd: i32,
        level: i32,
        name: i32,
        value: *mut core::ffi::c_void,
        length: *mut u32,
    ) -> i32;
}

/// Probe read-only features of an already opened Linux TUN fd. Returns zero
/// on non-Linux, invalid fd, or an ioctl failure.
#[no_mangle]
pub unsafe extern "C" fn iwan_native_probe_tun(fd: i32) -> u32 {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        return 0;
    }
    #[cfg(target_os = "linux")]
    {
        let mut ifr = [0u8; 40];
        if unsafe { ioctl(fd, TUNGETIFF, ifr.as_mut_ptr()) } < 0 {
            return 0;
        }
        let flags = u16::from_ne_bytes([ifr[16], ifr[17]]);
        let mut result = 0;
        if flags & IFF_VNET_HDR != 0 {
            let mut header_size = 0i32;
            if unsafe { ioctl(fd, TUNGETVNETHDRSZ, &mut header_size) } == 0 && header_size >= 10 {
                result |= IWAN_CAP_TUN_VNET_HDR;
            }
        }
        if flags & IFF_MULTI_QUEUE != 0 {
            result |= IWAN_CAP_TUN_MULTI_QUEUE;
        }
        result
    }
}

/// Probe the current read-only UDP offload settings on a socket. A zero
/// result means unavailable or disabled; callers may still use the ordinary
/// batched send/receive path.
#[no_mangle]
pub unsafe extern "C" fn iwan_native_probe_udp(fd: i32) -> u32 {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        return 0;
    }
    #[cfg(target_os = "linux")]
    {
        const SOL_UDP: i32 = 17;
        const UDP_GRO: i32 = 104;
        const UDP_SEGMENT: i32 = 103;
        let mut result = 0;
        for (name, capability) in [
            (UDP_GRO, IWAN_CAP_UDP_GRO),
            (UDP_SEGMENT, IWAN_CAP_UDP_SEGMENT),
        ] {
            // Both options are exposed as an int. Passing a one-byte buffer
            // with a four-byte length would let the kernel overwrite memory,
            // so keep the value and socklen_t-sized length explicit.
            let mut value = 0i32;
            let mut length = std::mem::size_of::<i32>() as u32;
            if unsafe {
                getsockopt(
                    fd,
                    SOL_UDP,
                    name,
                    (&mut value as *mut i32).cast(),
                    &mut length,
                )
            } == 0
                && length >= std::mem::size_of::<i32>() as u32
                && value != 0
            {
                result |= capability;
            }
        }
        result
    }
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
    fn capability_bits_are_disjoint() {
        let all = [
            IWAN_CAP_TUN_VNET_HDR,
            IWAN_CAP_TUN_MULTI_QUEUE,
            IWAN_CAP_UDP_GRO,
            IWAN_CAP_UDP_SEGMENT,
        ];
        for (index, bit) in all.iter().enumerate() {
            assert_eq!(bit.count_ones(), 1);
            for other in &all[index + 1..] {
                assert_eq!(bit & other, 0);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_probes_fail_closed_for_invalid_fds() {
        assert_eq!(unsafe { iwan_native_probe_tun(-1) }, 0);
        assert_eq!(unsafe { iwan_native_probe_udp(-1) }, 0);
    }

    #[test]
    fn empty_c_buffers_and_batches_are_safe() {
        let header = IwanHeader {
            kind: 0x14,
            encrypt: 0,
            sid_be: 0,
            token_be: 0,
        };
        let mut output = [0u8; IWAN_HEADER_LEN];
        let written = unsafe {
            iwan_native_build_data(
                &header,
                ptr::null(),
                0,
                ptr::null(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(written, IWAN_HEADER_LEN as isize);
        assert_eq!(unsafe { iwan_native_build_batch(ptr::null(), 0) }, 0);
    }

    #[test]
    fn overlapping_payload_and_output_use_memmove_semantics() {
        let header = IwanHeader {
            kind: 0x14,
            encrypt: 0,
            sid_be: 3,
            token_be: 5,
        };
        let payload = b"overlap-safe";
        let mut slab = [0u8; 64];
        slab[4..4 + payload.len()].copy_from_slice(payload);
        let written = unsafe {
            iwan_native_build_data(
                &header,
                slab.as_ptr().add(4),
                payload.len(),
                ptr::null(),
                slab.as_mut_ptr(),
                slab.len(),
            )
        };
        assert_eq!(written as usize, IWAN_HEADER_LEN + payload.len());
        assert_eq!(&slab[IWAN_HEADER_LEN..written as usize], payload);
    }

    #[test]
    fn packed_header_pointer_is_accepted() {
        let header = IwanHeader {
            kind: 0x14,
            encrypt: 0,
            sid_be: 9,
            token_be: 13,
        };
        let mut encoded = [0u8; 9];
        encoded[1] = header.kind;
        encoded[2] = header.encrypt;
        encoded[3..5].copy_from_slice(&header.sid_be.to_ne_bytes());
        encoded[5..9].copy_from_slice(&header.token_be.to_ne_bytes());
        let mut output = [0u8; IWAN_HEADER_LEN];
        let written = unsafe {
            iwan_native_build_data(
                encoded.as_ptr().add(1).cast(),
                ptr::null(),
                0,
                ptr::null(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(written, IWAN_HEADER_LEN as isize);
        assert_eq!(output, [0x14, 0, 0, 9, 0, 0, 0, 13]);
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
    fn batch_preflight_rejects_short_output_without_partial_writes() {
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
        // Preflight happens before the first descriptor is touched.
        assert_eq!(&first[..], &[0; 16]);
        assert_eq!(&second[..8], &[0; 8]);
    }
}
