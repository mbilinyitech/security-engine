#ifndef SOV_SHIM_STDINT_H
#define SOV_SHIM_STDINT_H

/* The kernel does not ship <stdint.h>. The vendored reference code uses uint8_t/
uint32_t/uint64_t/int32_t, so map those onto the kernel's own fixed-width types
instead of dragging in a libc header. */

#include <linux/types.h>

typedef u8  uint8_t;
typedef u16 uint16_t;
typedef u32 uint32_t;
typedef u64 uint64_t;
typedef s8  int8_t;
typedef s16 int16_t;
typedef s32 int32_t;
typedef s64 int64_t;

#endif
