#ifndef IWAN_NATIVE_H
#define IWAN_NATIVE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t kind;
    uint8_t encrypt;
    uint16_t sid_be;
    uint32_t token_be;
} iwan_native_header;

typedef struct {
    iwan_native_header header;
    const uint8_t *payload;
    size_t payload_len;
    const uint8_t *key;
    uint8_t *output;
    size_t output_cap;
} iwan_native_packet_desc;

#define IWAN_CAP_TUN_VNET_HDR  (1u << 0)
#define IWAN_CAP_TUN_MULTI_QUEUE (1u << 1)
#define IWAN_CAP_UDP_GRO       (1u << 2)
#define IWAN_CAP_UDP_SEGMENT   (1u << 3)

uint32_t iwan_native_abi_version(void);
intptr_t iwan_native_build_data(const iwan_native_header *header,
                               const uint8_t *payload, size_t payload_len,
                               const uint8_t *key,
                               uint8_t *output, size_t output_cap);
intptr_t iwan_native_build_batch(const iwan_native_packet_desc *packets,
                                size_t count);
uint32_t iwan_native_probe_tun(int fd);
uint32_t iwan_native_probe_udp(int fd);

#endif
