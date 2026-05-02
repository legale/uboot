// l2sh_proto.h - portable header-only protocol helpers for L2 shell

#ifndef L2SH_PROTO_H
#define L2SH_PROTO_H

#ifdef __UBOOT__
#include <asm/byteorder.h>
#include <linux/string.h>
#include <linux/types.h>
typedef __be16 be16;
typedef __be32 be32;
typedef __be64 be64;
typedef unsigned long l2s_uptr_t;
#elif defined(__KERNEL__)
#include <asm/byteorder.h>
#include <linux/string.h>
#include <linux/types.h>
typedef __be16 be16;
typedef __be32 be32;
typedef __be64 be64;
typedef unsigned long l2s_uptr_t;
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef u16 be16;
typedef u32 be32;
typedef u64 be64;
typedef uintptr_t l2s_uptr_t;

static inline u16 l2s_bswap16(u16 v) {
  return (u16)((u16)(v << 8) | (u16)(v >> 8));
}

static inline u32 l2s_bswap32(u32 v) {
  return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
         ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

static inline u64 l2s_bswap64(u64 v) {
  return ((v & 0x00000000000000FFULL) << 56) |
         ((v & 0x000000000000FF00ULL) << 40) |
         ((v & 0x0000000000FF0000ULL) << 24) |
         ((v & 0x00000000FF000000ULL) << 8) |
         ((v & 0x000000FF00000000ULL) >> 8) |
         ((v & 0x0000FF0000000000ULL) >> 24) |
         ((v & 0x00FF000000000000ULL) >> 40) |
         ((v & 0xFF00000000000000ULL) >> 56);
}

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define cpu_to_be16(x) ((be16)(x))
#define cpu_to_be32(x) ((be32)(x))
#define cpu_to_be64(x) ((be64)(x))
#define be16_to_cpu(x) ((u16)(x))
#define be32_to_cpu(x) ((u32)(x))
#define be64_to_cpu(x) ((u64)(x))
#else
#define cpu_to_be16(x) ((be16)l2s_bswap16((u16)(x)))
#define cpu_to_be32(x) ((be32)l2s_bswap32((u32)(x)))
#define cpu_to_be64(x) ((be64)l2s_bswap64((u64)(x)))
#define be16_to_cpu(x) l2s_bswap16((u16)(x))
#define be32_to_cpu(x) l2s_bswap32((u32)(x))
#define be64_to_cpu(x) l2s_bswap64((u64)(x))
#endif

typedef u8 be8;
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define L2SH_ETHERTYPE 0x88B5
#define L2SH_CLIENT_SIGNATURE 0xAABBCCDDu
#define L2SH_SERVER_SIGNATURE 0xDDCCBBAAu
#define L2SH_HELLO_VERSION 0x01
#define L2SH_PROTO_V1 0x01
#define L2SH_PROTO_V2 0x02
#define L2SH_PROTO_CUR L2SH_PROTO_V2
#define L2SH_HELLO_T_SPAWN 0x01
#define L2SH_HELLO_T_SHELL 0x02
#define L2SH_HELLO_T_NONCE 0x03
#define L2SH_HELLO_T_IDLE_TIMEOUT 0x04
#define L2SH_HELLO_T_HEARTBEAT 0x05
#define L2SH_HELLO_T_PROTO_VERSION 0x06
#define L2SH_NONCE_LEN 16
#define L2SH_MAX_PAYLOAD 1024
#define L2SH_MAX_DATA (L2SH_MAX_PAYLOAD - L2SH_NONCE_LEN)
#define L2SH_ARQ_T_DATA 0x80
#define L2SH_ARQ_T_ACK 0x81
#define L2SH_ARQ_HDR_LEN 3
#define L2SH_ARQ_MAX_DATA (L2SH_MAX_DATA - L2SH_ARQ_HDR_LEN)
#define L2SH_PRNG32_MULT 1664525u
#define L2SH_PRNG32_ADD 1013904223u

#define L2S_MSG_UNKNOWN ((u8)0)
#define L2S_MSG_HELLO ((u8)1)
#define L2S_MSG_DATA ((u8)2)
#define L2S_MSG_CONTROL ((u8)3)

#define L2S_FRAME_OK ((s32)0)
#define L2S_FRAME_ERR_ARG ((s32)-1)
#define L2S_FRAME_ERR_LEN ((s32)-2)
#define L2S_FRAME_ERR_RANGE ((s32)-3)
#define L2S_FRAME_ERR_SIGNATURE ((s32)-4)
#define L2S_FRAME_ERR_SHORT ((s32)-5)
#define L2S_FRAME_ERR_CRC ((s32)-6)
#define L2S_FRAME_ERR_FMT ((s32)-7)

typedef struct l2s_eth_hdr {
  u8 ether_dhost[ETH_ALEN];
  u8 ether_shost[ETH_ALEN];
  be16 ether_type;
} __packed l2s_eth_hdr_t;

typedef struct l2s_frame_header {
  l2s_eth_hdr_t eth_hdr;
  be32 signature;
  be32 payload_size;
  be32 crc;
} __packed l2s_frame_header_t;

typedef struct l2s_frame {
  l2s_frame_header_t header;
  u8 payload[L2SH_MAX_PAYLOAD];
} __packed l2s_frame_t;

typedef struct l2s_frame_meta {
  const u8 *src_mac;
  const u8 *dst_mac;
  u32 signature;
  u8 type;
  u8 flags;
} l2s_frame_meta_t;

typedef struct hello_view {
  const u8 *server_bin_path;
  u32 server_bin_path_len;
  const u8 *cmd;
  u32 cmd_len;
  u64 nonce;
  u32 proto_version;
  s32 idle_timeout_seconds;
  u8 server_started;
  u8 shell_started;
  u8 have_nonce;
  u8 have_idle_timeout;
  u8 have_heartbeat;
  u8 have_proto_version;
} hello_view_t;

typedef struct hello_builder {
  const char *spawn_cmd;
  const char *shell_cmd;
  u64 nonce;
  u32 proto_version;
  s32 idle_timeout_seconds;
  u8 include_spawn;
  u8 include_nonce;
  u8 include_idle_timeout;
  u8 include_proto_version;
} hello_builder_t;

typedef struct l2s_arq_view {
  const u8 *data;
  u32 data_len;
  u8 type;
  u8 seq;
  u8 ack;
  u8 is_data;
  u8 is_ack;
} l2s_arq_view_t;

static const u8 l2s_shared_key[4] = {0x4a, 0x17, 0x59, 0xc3};

static inline u16 l2s_get_be16(const u8 *buf) {
  return ((u16)buf[0] << 8) | (u16)buf[1];
}

static inline u32 l2s_get_be32(const u8 *buf) {
  return ((u32)buf[0] << 24) | ((u32)buf[1] << 16) |
         ((u32)buf[2] << 8) | (u32)buf[3];
}

static inline u64 l2s_get_be64(const u8 *buf) {
  return ((u64)buf[0] << 56) | ((u64)buf[1] << 48) |
         ((u64)buf[2] << 40) | ((u64)buf[3] << 32) |
         ((u64)buf[4] << 24) | ((u64)buf[5] << 16) |
         ((u64)buf[6] << 8) | (u64)buf[7];
}

static inline void l2s_put_be16(u8 *buf, u16 val) {
  buf[0] = (u8)(val >> 8);
  buf[1] = (u8)val;
}

static inline void l2s_put_be32(u8 *buf, u32 val) {
  buf[0] = (u8)(val >> 24);
  buf[1] = (u8)(val >> 16);
  buf[2] = (u8)(val >> 8);
  buf[3] = (u8)val;
}

static inline void l2s_put_be64(u8 *buf, u64 val) {
  buf[0] = (u8)(val >> 56);
  buf[1] = (u8)(val >> 48);
  buf[2] = (u8)(val >> 40);
  buf[3] = (u8)(val >> 32);
  buf[4] = (u8)(val >> 24);
  buf[5] = (u8)(val >> 16);
  buf[6] = (u8)(val >> 8);
  buf[7] = (u8)val;
}

static inline u32 csum32(const u8 *p, size_t n) {
  u32 s = 0;
  size_t i;

  if (!p)
    return 0;

  for (i = 0; i < n; i++)
    s += p[i];
  return s;
}

static inline void enc_dec(const u8 *input, u8 *output, const u8 *key,
                           size_t len) {
  u32 s;
  size_t i;

  if (!input || !output || !key || !len)
    return;

  s = 0;
  s ^= (u32)key[0];
  s ^= (u32)key[1] << 8;
  s ^= (u32)key[2] << 16;
  s ^= (u32)key[3] << 24;
  s ^= (u32)len;

  for (i = 0; i < len; i++) {
    u8 ks;

    s = s * L2SH_PRNG32_MULT + L2SH_PRNG32_ADD;
    ks = (u8)(s ^ (s >> 8) ^ (s >> 16) ^ (s >> 24));
    ks ^= (u8)i;
    ks = (u8)(ks + key[i & 3]);
    output[i] = input[i] ^ ks;
  }
}

static inline u64 hello_nonce_seed(void) {
  static u64 seed = 0x9e3779b97f4a7c15ULL;

  seed ^= seed << 7;
  seed ^= seed >> 9;
  seed += 0x7f4a7c159e3779b9ULL;
  seed ^= (u64)(l2s_uptr_t)&seed;
  return seed;
}

static inline void hello_generate_nonce(u8 *nonce, size_t len) {
  static u64 hello_nonce_counter;
  u64 state;
  size_t i = 0;

  if (!nonce || len == 0)
    return;

  state = hello_nonce_seed() ^ (++hello_nonce_counter);
  while (i < len) {
    size_t chunk = len - i;
    u64 mixed;

    if (chunk > sizeof(mixed))
      chunk = sizeof(mixed);

    mixed = state ^ (state >> 12) ^ (state << 25);
    memcpy(nonce + i, &mixed, chunk);
    state = (state * 6364136223846793005ULL) + 1ULL + hello_nonce_seed();
    i += chunk;
  }
}

static inline s32 hello_write_tlv(u8 *buf, size_t buf_len, size_t *offset,
                                  u8 type, const u8 *data, u16 data_len) {
  size_t need;

  if (!buf || !offset)
    return -1;

  need = (size_t)data_len + 3U;
  if (*offset > buf_len || buf_len - *offset < need)
    return -1;

  buf[*offset] = type;
  l2s_put_be16(buf + *offset + 1, data_len);
  if (data_len > 0 && data)
    memcpy(buf + *offset + 3, data, data_len);
  *offset += need;

  return 0;
}

static inline s32 hello_write_string_tlv(u8 *buf, size_t buf_len,
                                         size_t *offset, u8 type,
                                         const char *str) {
  const u8 *ptr = NULL;
  size_t len = 0;

  if (str) {
    len = strlen(str);
    if (len > 0xFFFFu)
      return -1;
    ptr = (const u8 *)str;
  }

  return hello_write_tlv(buf, buf_len, offset, type, ptr, (u16)len);
}

static inline s32 hello_build(u8 *buf, size_t buf_len,
                              const hello_builder_t *builder) {
  size_t offset = 0;

  if (!buf || !builder || buf_len == 0)
    return -1;

  buf[offset++] = L2SH_HELLO_VERSION;
  if (builder->include_spawn && builder->spawn_cmd && builder->spawn_cmd[0]) {
    if (hello_write_string_tlv(buf, buf_len, &offset, L2SH_HELLO_T_SPAWN,
                               builder->spawn_cmd) != 0)
      return -1;
  }
  if (hello_write_string_tlv(buf, buf_len, &offset, L2SH_HELLO_T_SHELL,
                             builder->shell_cmd ? builder->shell_cmd : "") != 0)
    return -1;
  if (builder->include_nonce) {
    u8 tmp[sizeof(u64)];
    l2s_put_be64(tmp, builder->nonce);
    if (hello_write_tlv(buf, buf_len, &offset, L2SH_HELLO_T_NONCE, tmp,
                        (u16)sizeof(tmp)) != 0)
      return -1;
  }
  if (builder->include_idle_timeout) {
    u8 tmp[sizeof(u32)];
    l2s_put_be32(tmp, (u32)builder->idle_timeout_seconds);
    if (hello_write_tlv(buf, buf_len, &offset, L2SH_HELLO_T_IDLE_TIMEOUT, tmp,
                        (u16)sizeof(tmp)) != 0)
      return -1;
  }
  if (builder->include_proto_version) {
    u8 tmp[sizeof(u32)];
    l2s_put_be32(tmp, builder->proto_version);
    if (hello_write_tlv(buf, buf_len, &offset, L2SH_HELLO_T_PROTO_VERSION,
                        tmp,
                        (u16)sizeof(tmp)) != 0)
      return -1;
  }

  return (s32)offset;
}

static inline s32 hello_build_heartbeat(u8 *buf, size_t buf_len) {
  size_t offset = 0;

  if (!buf || buf_len == 0)
    return -1;

  buf[offset++] = L2SH_HELLO_VERSION;
  if (hello_write_tlv(buf, buf_len, &offset, L2SH_HELLO_T_HEARTBEAT, NULL,
                      0) != 0)
    return -1;
  return (s32)offset;
}

static inline s32 hello_parse(const u8 *buf, size_t buf_len,
                              hello_view_t *view) {
  size_t offset = 0;

  if (!buf || !view || buf_len == 0)
    return -1;

  memset(view, 0, sizeof(*view));
  if (buf[offset++] != L2SH_HELLO_VERSION)
    return -1;

  while (offset + 3 <= buf_len) {
    u8 type = buf[offset++];
    u16 tlv_len = l2s_get_be16(buf + offset);

    offset += 2;
    if (offset + tlv_len > buf_len)
      return -1;

    switch (type) {
    case L2SH_HELLO_T_SPAWN:
      view->server_bin_path = buf + offset;
      view->server_bin_path_len = tlv_len;
      view->server_started = 1;
      break;
    case L2SH_HELLO_T_SHELL:
      view->cmd = buf + offset;
      view->cmd_len = tlv_len;
      view->shell_started = 1;
      break;
    case L2SH_HELLO_T_NONCE:
      if (tlv_len != sizeof(u64))
        return -1;
      view->nonce = l2s_get_be64(buf + offset);
      view->have_nonce = 1;
      break;
    case L2SH_HELLO_T_IDLE_TIMEOUT:
      if (tlv_len != sizeof(u32))
        return -1;
      view->idle_timeout_seconds = (s32)l2s_get_be32(buf + offset);
      view->have_idle_timeout = 1;
      break;
    case L2SH_HELLO_T_HEARTBEAT:
      view->have_heartbeat = 1;
      break;
    case L2SH_HELLO_T_PROTO_VERSION:
      if (tlv_len != sizeof(u32))
        return -1;
      view->proto_version = l2s_get_be32(buf + offset);
      view->have_proto_version = 1;
      break;
    default:
      break;
    }
    offset += tlv_len;
  }

  if (offset != buf_len)
    return -1;

  return 0;
}

static inline size_t l2s_frame_wire_size(size_t payload_len) {
  if (payload_len > L2SH_MAX_DATA)
    return 0;
  return sizeof(l2s_frame_header_t) + L2SH_NONCE_LEN + payload_len;
}

static inline s32 l2s_build_frame(l2s_frame_t *frame, size_t frame_capacity,
                                  const l2s_frame_meta_t *meta,
                                  const void *payload, size_t payload_len) {
  u8 scratch[L2SH_MAX_DATA];
  const u8 *src_payload;
  u8 *nonce_ptr;
  u8 *data_ptr;
  size_t frame_len;
  size_t enc_payload_len;
  u32 crc;
  size_t i;

  if (!frame || !meta || !meta->src_mac || !meta->dst_mac)
    return L2S_FRAME_ERR_ARG;
  if (payload_len > 0 && !payload)
    return L2S_FRAME_ERR_ARG;
  if (payload_len > L2SH_MAX_DATA)
    return L2S_FRAME_ERR_RANGE;

  src_payload = payload;
  if (payload_len > 0 && (const u8 *)payload >= (const u8 *)frame &&
      (const u8 *)payload < (const u8 *)frame + sizeof(*frame)) {
    memcpy(scratch, payload, payload_len);
    src_payload = scratch;
  }

  frame_len = l2s_frame_wire_size(payload_len);
  if (frame_capacity < sizeof(l2s_frame_header_t) || frame_capacity < frame_len)
    return L2S_FRAME_ERR_LEN;

  enc_payload_len = L2SH_NONCE_LEN + payload_len;
  memset(&frame->header, 0, sizeof(frame->header));
  memcpy(frame->header.eth_hdr.ether_shost, meta->src_mac, ETH_ALEN);
  memcpy(frame->header.eth_hdr.ether_dhost, meta->dst_mac, ETH_ALEN);
  l2s_put_be16((u8 *)&frame->header.eth_hdr.ether_type, L2SH_ETHERTYPE);
  l2s_put_be32((u8 *)&frame->header.signature, meta->signature);
  l2s_put_be32((u8 *)&frame->header.payload_size, (u32)enc_payload_len);
  frame->header.crc = 0;

  nonce_ptr = frame->payload;
  data_ptr = frame->payload + L2SH_NONCE_LEN;
  hello_generate_nonce(nonce_ptr, L2SH_NONCE_LEN);
  if (payload_len > 0)
    memcpy(data_ptr, src_payload, payload_len);

  if (payload_len > 0) {
    for (i = 0; i < payload_len; i++)
      data_ptr[i] ^= nonce_ptr[i & (L2SH_NONCE_LEN - 1)];
    enc_dec(data_ptr, data_ptr, l2s_shared_key, payload_len);
  }

  frame->header.crc = 0;
  crc = csum32((const u8 *)frame, frame_len);
  l2s_put_be32((u8 *)&frame->header.crc, crc);

  if (payload_len > 0)
    enc_dec(data_ptr, data_ptr, (const u8 *)&frame->header.crc, payload_len);

  return (s32)frame_len;
}

static inline s32 l2s_parse_frame(l2s_frame_t *frame, size_t frame_len,
                                  u32 expected_signature,
                                  size_t *payload_len_out) {
  size_t payload_size;
  size_t expected_len;
  size_t data_len;
  u32 recv_crc;
  u32 calc_crc;
  be32 saved_crc;
  u8 nonce[L2SH_NONCE_LEN];
  u8 *nonce_ptr;
  u8 *data_ptr;
  size_t i;

  if (!frame)
    return L2S_FRAME_ERR_ARG;
  if (frame_len < sizeof(l2s_frame_header_t))
    return L2S_FRAME_ERR_SHORT;
  if (l2s_get_be16((const u8 *)&frame->header.eth_hdr.ether_type) !=
      L2SH_ETHERTYPE)
    return L2S_FRAME_ERR_ARG;
  if (l2s_get_be32((const u8 *)&frame->header.signature) != expected_signature)
    return L2S_FRAME_ERR_SIGNATURE;

  payload_size = l2s_get_be32((const u8 *)&frame->header.payload_size);
  if (payload_size > L2SH_MAX_PAYLOAD)
    return L2S_FRAME_ERR_RANGE;
  if (payload_size < L2SH_NONCE_LEN)
    return L2S_FRAME_ERR_FMT;

  expected_len = sizeof(l2s_frame_header_t) + payload_size;
  if (frame_len < expected_len)
    return L2S_FRAME_ERR_SHORT;

  data_len = payload_size - L2SH_NONCE_LEN;
  nonce_ptr = frame->payload;
  data_ptr = frame->payload + L2SH_NONCE_LEN;
  recv_crc = l2s_get_be32((const u8 *)&frame->header.crc);

  if (data_len > 0)
    enc_dec(data_ptr, data_ptr, (const u8 *)&frame->header.crc, data_len);

  saved_crc = frame->header.crc;
  frame->header.crc = 0;
  calc_crc = csum32((const u8 *)frame, expected_len);
  frame->header.crc = saved_crc;
  if (recv_crc != calc_crc)
    return L2S_FRAME_ERR_CRC;

  if (data_len > 0) {
    memcpy(nonce, nonce_ptr, sizeof(nonce));
    enc_dec(data_ptr, data_ptr, l2s_shared_key, data_len);
    for (i = 0; i < data_len; i++)
      frame->payload[i] = data_ptr[i] ^ nonce[i & (L2SH_NONCE_LEN - 1)];
  }

  if (payload_len_out)
    *payload_len_out = data_len;
  return L2S_FRAME_OK;
}

static inline s32 build_packet(l2s_frame_t *packet, size_t payload_size,
                               const u8 src_mac[ETH_ALEN],
                               const u8 dst_mac[ETH_ALEN], u32 signature) {
  l2s_frame_meta_t meta = {
      .src_mac = src_mac,
      .dst_mac = dst_mac,
      .signature = signature,
      .type = L2S_MSG_DATA,
      .flags = 0,
  };

  return l2s_build_frame(packet, sizeof(*packet), &meta,
                         payload_size > 0 ? packet->payload : NULL,
                         payload_size);
}

static inline s32 parse_packet(l2s_frame_t *packet, s32 frame_len,
                               u32 expected_signature) {
  size_t payload_len = 0;
  s32 rc;

  if (frame_len < 0)
    return L2S_FRAME_ERR_SHORT;

  rc = l2s_parse_frame(packet, (size_t)frame_len, expected_signature,
                       &payload_len);
  if (rc != L2S_FRAME_OK)
    return rc;
  return (s32)payload_len;
}

static inline s32 l2s_arq_build_data(u8 *buf, size_t buf_len, u8 seq, u8 ack,
                                     const void *data, size_t data_len) {
  if (!buf)
    return -1;
  if (data_len > 0 && !data)
    return -1;
  if (data_len > L2SH_ARQ_MAX_DATA)
    return -1;
  if (buf_len < L2SH_ARQ_HDR_LEN + data_len)
    return -1;

  buf[0] = L2SH_ARQ_T_DATA;
  buf[1] = seq;
  buf[2] = ack;
  if (data_len > 0)
    memcpy(buf + L2SH_ARQ_HDR_LEN, data, data_len);
  return (s32)(L2SH_ARQ_HDR_LEN + data_len);
}

static inline s32 l2s_arq_build_ack(u8 *buf, size_t buf_len, u8 ack) {
  if (!buf || buf_len < L2SH_ARQ_HDR_LEN)
    return -1;

  buf[0] = L2SH_ARQ_T_ACK;
  buf[1] = 0;
  buf[2] = ack;
  return L2SH_ARQ_HDR_LEN;
}

static inline s32 l2s_arq_parse(const u8 *buf, size_t len,
                                l2s_arq_view_t *view) {
  if (!buf || !view)
    return -1;

  memset(view, 0, sizeof(*view));
  if (len == 0)
    return 0;
  if (buf[0] != L2SH_ARQ_T_DATA && buf[0] != L2SH_ARQ_T_ACK)
    return 0;
  if (len < L2SH_ARQ_HDR_LEN)
    return -1;

  view->type = buf[0];
  view->seq = buf[1];
  view->ack = buf[2];

  if (view->type == L2SH_ARQ_T_ACK) {
    if (len != L2SH_ARQ_HDR_LEN)
      return -1;
    view->is_ack = 1;
    return 1;
  }

  view->is_data = 1;
  view->data = buf + L2SH_ARQ_HDR_LEN;
  view->data_len = (u32)(len - L2SH_ARQ_HDR_LEN);
  return 1;
}

#endif /* L2SH_PROTO_H */
