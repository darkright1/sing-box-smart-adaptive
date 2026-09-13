#include <stddef.h>
#include <stdint.h>

#include "../include/iwan_native.h"

_Static_assert(sizeof(iwan_native_header) == 8, "iWAN header ABI size changed");
_Static_assert(offsetof(iwan_native_header, sid_be) == 2, "iWAN SID offset changed");
_Static_assert(offsetof(iwan_native_header, token_be) == 4, "iWAN token offset changed");

/* The native library currently publishes 64-bit Linux artifacts. Keep the
 * descriptor assertion conditional so the header remains usable by a future
 * 32-bit port without baking an incorrect pointer size into that build. */
#if UINTPTR_MAX == UINT64_MAX
_Static_assert(sizeof(iwan_native_packet_desc) == 48, "iWAN descriptor ABI size changed");
_Static_assert(offsetof(iwan_native_packet_desc, payload) == 8, "iWAN payload offset changed");
_Static_assert(offsetof(iwan_native_packet_desc, output) == 32, "iWAN output offset changed");
#endif

int main(void) {
    return 0;
}
