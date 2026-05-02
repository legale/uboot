#ifndef __L2SH_H
#define __L2SH_H

#ifdef __UBOOT__

#include <asm/byteorder.h>
#include <linux/types.h>

typedef __be16 be16;
typedef __be32 be32;
typedef __be64 be64;

#else

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

typedef u16 be16;
typedef u32 be32;
typedef u64 be64;

#define cpu_to_be16(x) htons(x)
#define cpu_to_be32(x) htonl(x)
#define be16_to_cpu(x) ntohs(x)
#define be32_to_cpu(x) ntohl(x)

#endif

typedef u8 be8;

#if defined(CONFIG_L2SH) && !defined(CONFIG_XPL_BUILD)
s32 l2sh_init(void);
void l2sh_poll(void);
void l2sh_rx(const u8 *packet, u32 len);
s32 l2sh_tstc(void);
s32 l2sh_getc(void);
void l2sh_putc(const char c);
void l2sh_puts(const char *s);
#else
static inline s32 l2sh_init(void)
{
  return 0;
}

static inline void l2sh_poll(void)
{
}

static inline void l2sh_rx(const u8 *packet, u32 len)
{
  (void)packet;
  (void)len;
}

static inline s32 l2sh_tstc(void)
{
  return 0;
}

static inline s32 l2sh_getc(void)
{
  return -1;
}

static inline void l2sh_putc(const char c)
{
  (void)c;
}

static inline void l2sh_puts(const char *s)
{
  (void)s;
}
#endif

#endif
