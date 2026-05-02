// l2sh.c - L2SH core implementation

#include <config.h>
#include <dm.h>
#include <env.h>
#include <l2sh.h>
#include <l2sh_proto.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <net.h>
#include <serial.h>
#include <stdarg.h>
#include <time.h>
#include <vsprintf.h>

#define L2SH_DEDUP_SLOTS 16
#define L2SH_DEDUP_WINDOW_US 2000UL
#define L2SH_HELLO_TIMEOUT_MAX 600
#define L2SH_ETH_RETRY_MIN_MS 5000UL
#define L2SH_ETH_RETRY_MAX_MS 30000UL
#define L2SH_TX_BUDGET 8

struct l2sh_ring {
  u32 head;
  u32 tail;
  u32 count;
};

struct l2sh_dedup_entry {
  u64 ts_us;
  size_t len;
  u32 checksum;
  s32 valid;
};

enum l2sh_state {
  L2SH_IDLE = 0,
  L2SH_WAIT_CONFIRM,
  L2SH_ACTIVE,
};

struct l2sh_ctx {
  s32 inited;
  s32 polling;
  enum l2sh_state state;
  u64 last_rx_ms;
  u64 timeout_ms;
  u64 eth_last_try_ms;
  u64 eth_retry_ms;
  u64 pending_nonce;
  u8 peer_mac[ARP_HLEN];
  struct l2sh_ring rx_ring;
  struct l2sh_ring tx_ring;
  l2s_frame_t tx_frame;
  u8 rx_buf[CONFIG_L2SH_RX_SIZE];
  u8 tx_buf[CONFIG_L2SH_TX_SIZE];
  struct l2sh_dedup_entry dedup[L2SH_DEDUP_SLOTS];
  u32 dedup_next;
};

static struct l2sh_ctx l2sh;
extern int net_busy_flag;
static void l2sh_reset_session(void);

static s32 l2sh_dbg_enabled(void) {
  return env_get_yesno("l2sh_debug") == 1;
}

static const char *l2sh_state_name(enum l2sh_state state) {
  switch (state) {
  case L2SH_IDLE:
    return "idle";
  case L2SH_WAIT_CONFIRM:
    return "wait_confirm";
  case L2SH_ACTIVE:
    return "active";
  default:
    return "unknown";
  }
}

static const char *l2sh_fmt_mac(const u8 *mac, char *buf, size_t len) {
  if (!buf || !len) return "";

  if (!mac) {
    snprintf(buf, len, "<nil>");
    return buf;
  }

  snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return buf;
}

static void l2sh_dbg(const char *fmt, ...) {
  char buf[256];
  s32 len;
  va_list ap;

  if (!l2sh_dbg_enabled()) return;

  va_start(ap, fmt);
  len = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (len < 0) return;

  serial_puts("[l2sh] ");
  serial_puts(buf);
  serial_putc('\n');
}

static u32 l2sh_ring_space(const struct l2sh_ring *ring,
                           u32 size) {
  return size - ring->count;
}

static u32 l2sh_ring_push(struct l2sh_ring *ring, u8 *buf,
                          u32 size, const u8 *data,
                          u32 len) {
  u32 pushed;
  u32 n;

  if (!ring || !buf || !data || !size) return 0;

  pushed = 0;
  while (pushed < len && ring->count < size) {
    n = len - pushed;
    if (n > size - ring->head) n = size - ring->head;
    if (n > size - ring->count) n = size - ring->count;

    memcpy(buf + ring->head, data + pushed, n);
    ring->head = (ring->head + n) % size;
    ring->count += n;
    pushed += n;
  }

  return pushed;
}

static u32 l2sh_ring_pop(struct l2sh_ring *ring, u8 *buf, u32 size, u8 *data, u32 len) {
  u32 popped;
  u32 n;

  if (!ring || !buf || !data || !size) return 0;

  popped = 0;
  while (popped < len && ring->count) {
    n = len - popped;
    if (n > size - ring->tail) n = size - ring->tail;
    if (n > ring->count) n = ring->count;

    memcpy(data + popped, buf + ring->tail, n);
    ring->tail = (ring->tail + n) % size;
    ring->count -= n;
    popped += n;
  }

  return popped;
}

static s32 l2sh_parse_nonce_confirm(const u8 *buf, size_t len, u64 *nonce) {
  char tmp[64];
  char *end;
  u32 n;

  if (!buf || !len || !nonce) return -1;

  if (len < 15) return -1;

  if (memcmp(buf, "nonce_confirm=", 14)) return -1;

  n = len;
  if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;

  memcpy(tmp, buf, n);
  tmp[n] = '\0';

  *nonce = simple_strtoull(tmp + 14, &end, 16);
  if (end == tmp + 14) return -1;

  return 0;
}

static void l2sh_update_timeout(const hello_view_t *hello) {
  u64 timeout_ms;

  timeout_ms = CONFIG_L2SH_TIMEOUT_MS;
  if (hello && hello->have_idle_timeout) {
    if (hello->idle_timeout_seconds <= 0)
      timeout_ms = CONFIG_L2SH_TIMEOUT_MS;
    else if (hello->idle_timeout_seconds > L2SH_HELLO_TIMEOUT_MAX)
      timeout_ms = L2SH_HELLO_TIMEOUT_MAX * 1000UL;
    else
      timeout_ms = (u64)hello->idle_timeout_seconds * 1000UL;
  }

  l2sh.timeout_ms = timeout_ms;
}

static void l2sh_touch_rx(void) {
  l2sh.last_rx_ms = get_timer(0);
}

static s32 l2sh_runtime_enabled(void) {
  s32 ret;

  ret = env_get_yesno("l2sh");
  if (ret == 0)
    return 0;

  return 1;
}

static void l2sh_reset_rings(void) {
  memset(&l2sh.rx_ring, 0, sizeof(l2sh.rx_ring));
  memset(&l2sh.tx_ring, 0, sizeof(l2sh.tx_ring));
}

static void l2sh_reset_session(void) {
  if (l2sh.state != L2SH_IDLE) l2sh_dbg("session reset from=%s", l2sh_state_name(l2sh.state));

  l2sh.state = L2SH_IDLE;
  l2sh.pending_nonce = 0;
  memset(l2sh.peer_mac, 0, sizeof(l2sh.peer_mac));
  l2sh_reset_rings();
  l2sh_update_timeout(NULL);
}

static s32 l2sh_ensure_eth(void) {
  struct udevice *dev;
  s32 ret;

  dev = eth_get_dev();
  if (!dev) {
    l2sh_dbg("eth current device is null");
    return -ENODEV;
  }

  if (eth_is_active(dev)) {
    l2sh.eth_last_try_ms = 0;
    l2sh.eth_retry_ms = 0;
    return 0;
  }

  if (l2sh.eth_retry_ms && get_timer(l2sh.eth_last_try_ms) < l2sh.eth_retry_ms) return -EAGAIN;

  l2sh_dbg("eth start dev=%s", dev->name);
  ret = eth_start_udev(dev);
  l2sh.eth_last_try_ms = get_timer(0);
  if (ret) {
    if (l2sh.eth_retry_ms < L2SH_ETH_RETRY_MIN_MS) l2sh.eth_retry_ms = L2SH_ETH_RETRY_MIN_MS;
    // double the retry window until the max cap
    // сдвиг влево на один бит здесь просто умножает окно повтора на два
    else if (l2sh.eth_retry_ms < L2SH_ETH_RETRY_MAX_MS)
      l2sh.eth_retry_ms <<= 1;

    if (l2sh.eth_retry_ms > L2SH_ETH_RETRY_MAX_MS) l2sh.eth_retry_ms = L2SH_ETH_RETRY_MAX_MS;

    l2sh_dbg("eth start failed ret=%d retry_ms=%lu", ret, l2sh.eth_retry_ms);
    return ret;
  }

  l2sh_dbg("eth start ok dev=%s", dev->name);
  l2sh.eth_last_try_ms = 0;
  l2sh.eth_retry_ms = 0;

  return 0;
}

static s32 l2sh_build_frame(l2s_frame_t *frame, const u8 *src,
                            const u8 *dst, u32 signature,
                            const void *payload, size_t payload_len) {
  l2s_frame_meta_t meta = {
    .src_mac = src,
    .dst_mac = dst,
    .signature = signature,
    .type = L2S_MSG_DATA,
    .flags = 0,
  };
  s32 ret;

  if (!frame || !src || !dst) return -EINVAL;
  ret = l2s_build_frame(frame, sizeof(*frame), &meta, payload, payload_len);
  if (ret < 0) return -EINVAL;

  return ret;
}

static u32 l2sh_frame_fingerprint(const l2s_frame_t *frame, size_t len) {
  u32 crc;
  u32 sig;
  u32 plen;

  if (!frame || len < sizeof(frame->header)) return 0;

  crc = be32_to_cpu(frame->header.crc);
  sig = be32_to_cpu(frame->header.signature);
  plen = be32_to_cpu(frame->header.payload_size);

  // fold the stable header fields into one cheap duplicate key
  // xor crc, signature и длины дает дешевый ключ для отсева дублей без полного сравнения буфера
  return crc ^ sig ^ plen;
}

static s32 l2sh_drop_dup(const l2s_frame_t *frame, size_t len) {
  u64 now_us;
  u32 i;
  u32 checksum;
  struct l2sh_dedup_entry *ent;

  // some eth paths can hand us the same frame more than once
  // некоторые eth-драйверы могут отдать один и тот же кадр повторно
  now_us = timer_get_us();
  checksum = l2sh_frame_fingerprint(frame, len);

  for (i = 0; i < L2SH_DEDUP_SLOTS; i++) {
    ent = &l2sh.dedup[i];
    if (!ent->valid)
      continue;
    if (now_us > ent->ts_us &&
        now_us - ent->ts_us > L2SH_DEDUP_WINDOW_US) {
      ent->valid = 0;
      continue;
    }
    if (ent->valid && ent->len == len && ent->checksum == checksum) {
      ent->ts_us = now_us;
      return 1;
    }
  }

  ent = &l2sh.dedup[l2sh.dedup_next];
  ent->valid = 1;
  ent->ts_us = now_us;
  ent->len = len;
  ent->checksum = checksum;
  l2sh.dedup_next = (l2sh.dedup_next + 1) % L2SH_DEDUP_SLOTS;

  return 0;
}

static s32 l2sh_accept_dst_mac(const u8 *dst, const u8 *our) {
  if (!dst || !our) return 0;

  if (!memcmp(dst, our, ARP_HLEN)) return 1;

  if (!memcmp(dst, net_bcast_ethaddr, ARP_HLEN)) return 1;

  return 0;
}

static s32 l2sh_rx_enq(const u8 *data, size_t len) {
  u32 pushed;

  if (!data || !len) return 0;

  pushed = l2sh_ring_push(&l2sh.rx_ring, l2sh.rx_buf,
                          ARRAY_SIZE(l2sh.rx_buf), data, len);
  if (pushed != len) l2sh_dbg("rx ring full pushed=%u dropped=%zu", pushed, len - pushed);

  return pushed;
}

static s32 l2sh_send_payload(const void *data, size_t len) {
  struct udevice *dev;
  const u8 *src;
  char src_mac[18];
  char dst_mac[18];
  s32 frame_len;
  s32 ret;

  if (l2sh.state == L2SH_IDLE) return -EINVAL;
  if (!data && len) return -EINVAL;

  ret = l2sh_ensure_eth();
  if (ret) return ret;

  dev = eth_get_dev();
  src = eth_get_ethaddr();
  if (!dev || !src) return -ENODEV;

  frame_len = l2sh_build_frame(&l2sh.tx_frame, src, l2sh.peer_mac, L2SH_SERVER_SIGNATURE, data, len);
  if (frame_len < 0) return frame_len;

  l2sh_dbg("tx frame len=%d payload=%zu src=%s dst=%s state=%s",
           frame_len, len,
           l2sh_fmt_mac(src, src_mac, sizeof(src_mac)),
           l2sh_fmt_mac(l2sh.peer_mac, dst_mac, sizeof(dst_mac)),
           l2sh_state_name(l2sh.state));
  ret = eth_send(&l2sh.tx_frame, frame_len);
  if (ret < 0) {
    l2sh_dbg("tx failed ret=%d len=%d", ret, frame_len);
    return ret;
  }

  l2sh_dbg("tx ok ret=%d len=%d", ret, frame_len);

  return 0;
}

static void l2sh_send_ready(u64 nonce) {
  char msg[64];
  s32 len;

  len = snprintf(msg, sizeof(msg),
                 "ready nonce=%016llx source=userland\n",
                 (u64)nonce);
  if (len <= 0) return;

  l2sh_dbg("send ready nonce=%016llx", (u64)nonce);
  if (l2sh_send_payload(msg, len) < 0) l2sh_reset_session();
}

static void l2sh_handle_hello(const u8 *src_mac, const hello_view_t *hello) {
  char mac[18];

  if (!src_mac || !hello || !hello->have_nonce) return;

  // keep one peer until the session is reset
  // пока сессия не сброшена, принимаем hello только от уже выбранного peer
  if (l2sh.state != L2SH_IDLE && memcmp(l2sh.peer_mac, src_mac, ARP_HLEN)) {
    l2sh_dbg("ignore hello from foreign mac=%s state=%s",
             l2sh_fmt_mac(src_mac, mac, sizeof(mac)), l2sh_state_name(l2sh.state));
    return;
  }

  memcpy(l2sh.peer_mac, src_mac, ARP_HLEN);
  l2sh.pending_nonce = hello->nonce;
  l2sh_update_timeout(hello);
  l2sh_touch_rx();
  l2sh.state = L2SH_WAIT_CONFIRM;
  l2sh_dbg("hello mac=%s nonce=%016llx timeout_ms=%lu",
           l2sh_fmt_mac(src_mac, mac, sizeof(mac)),
           (u64)hello->nonce, l2sh.timeout_ms);
  l2sh_send_ready(hello->nonce);
}

static void l2sh_handle_payload(const u8 *src_mac, const u8 *data, size_t len) {
  hello_view_t hello;
  u64 nonce;
  char mac[18];

  if (!src_mac || !data) return;

  if (!memcmp(src_mac, l2sh.peer_mac, ARP_HLEN)) l2sh_touch_rx();

  if (!hello_parse(data, len, &hello)) {
    if (hello.have_heartbeat) {
      if (l2sh.state != L2SH_IDLE && !memcmp(src_mac, l2sh.peer_mac, ARP_HLEN)) l2sh_touch_rx();
      l2sh_dbg("heartbeat mac=%s", l2sh_fmt_mac(src_mac, mac, sizeof(mac)));
      return;
    }

    l2sh_handle_hello(src_mac, &hello);
    return;
  }

  if (l2sh.state == L2SH_WAIT_CONFIRM &&
      !memcmp(src_mac, l2sh.peer_mac, ARP_HLEN) &&
      !l2sh_parse_nonce_confirm(data, len, &nonce) &&
      nonce == l2sh.pending_nonce) {
    l2sh.pending_nonce = 0;
    l2sh_touch_rx();
    l2sh.state = L2SH_ACTIVE;
    l2sh_dbg("nonce confirm mac=%s session active", l2sh_fmt_mac(src_mac, mac, sizeof(mac)));
    return;
  }

  if (l2sh.state != L2SH_ACTIVE)
    return;

  if (memcmp(src_mac, l2sh.peer_mac, ARP_HLEN))
    return;

  (void)l2sh_rx_enq(data, len);
  l2sh_dbg("rx data mac=%s len=%zu", l2sh_fmt_mac(src_mac, mac, sizeof(mac)), len);
}

static void l2sh_check_timeout(void) {
  if (l2sh.state == L2SH_IDLE)
    return;

  if (get_timer(l2sh.last_rx_ms) >= l2sh.timeout_ms) {
    l2sh_dbg("session timeout state=%s timeout_ms=%lu", l2sh_state_name(l2sh.state), l2sh.timeout_ms);
    l2sh_reset_session();
  }
}

static void l2sh_tx_drain(void) {
  u8 plain[L2SH_MAX_DATA];
  u32 count;
  s32 sent;
  s32 budget;

  if (l2sh.state != L2SH_ACTIVE) return;

  budget = L2SH_TX_BUDGET;
  while (l2sh.tx_ring.count && budget--) {
    count = l2sh.tx_ring.count;
    if (count > sizeof(plain))
      count = sizeof(plain);

    count = l2sh_ring_pop(&l2sh.tx_ring, l2sh.tx_buf,
                          ARRAY_SIZE(l2sh.tx_buf), plain, count);
    if (!count) break;

    sent = l2sh_send_payload(plain, count);
    if (sent < 0) {
      l2sh_reset_session();
      break;
    }
  }
}

void l2sh_rx(const u8 *packet, u32 len) {
  l2s_frame_t *frame;
  const u8 *payload;
  const u8 *our_mac;
  size_t payload_len;
  u32 sig;
  be16 etype;
  s32 parse_ret;
  char src_mac[18];
  char dst_mac[18];

  l2sh_init();

  if (!l2sh_runtime_enabled())
    return;

  if (!packet || len < sizeof(l2s_frame_header_t))
    return;

  our_mac = eth_get_ethaddr();
  if (!our_mac)
    return;

  frame = (l2s_frame_t *)packet;
  etype = frame->header.eth_hdr.ether_type;
  if (be16_to_cpu(etype) != L2SH_ETHERTYPE)
    return;

  if (!l2sh_accept_dst_mac(frame->header.eth_hdr.ether_dhost, our_mac))
    return;

  sig = be32_to_cpu(frame->header.signature);
  l2sh_dbg("rx raw len=%u src=%s dst=%s sig=%08x state=%s",
           len,
           l2sh_fmt_mac(frame->header.eth_hdr.ether_shost,
                        src_mac, sizeof(src_mac)),
           l2sh_fmt_mac(frame->header.eth_hdr.ether_dhost,
                        dst_mac, sizeof(dst_mac)),
           sig, l2sh_state_name(l2sh.state));

  parse_ret = l2s_parse_frame(frame, len, L2SH_CLIENT_SIGNATURE, &payload_len);
  if (parse_ret) {
    l2sh_dbg("parse failed ret=%d sig=%08x len=%u", parse_ret, sig, len);
    return;
  }

  if (l2sh_drop_dup(frame, len))
    return;

  payload = frame->payload;
  l2sh_handle_payload(frame->header.eth_hdr.ether_shost, payload, payload_len);
}

s32 l2sh_init(void) {
  if (l2sh.inited) return 0;

  memset(&l2sh, 0, sizeof(l2sh));
  l2sh.inited = 1;
  l2sh_update_timeout(NULL);
  l2sh_reset_session();

  return 0;
}

void l2sh_poll(void) {
  s32 ret;

  l2sh_init();

  // console paths can re-enter here through getc and putc
  // getc и putc могут зайти сюда повторно, поэтому защищаемся от рекурсии
  if (l2sh.polling)
    return;

  l2sh.polling = 1;

  if (!l2sh_runtime_enabled()) {
    if (l2sh.state != L2SH_IDLE)
      l2sh_reset_session();
    goto out;
  }

  if (!net_busy_flag) {
    ret = l2sh_ensure_eth();
    if (!ret) {
      ret = net_init();
      if (!ret)
        (void)eth_rx();
    }
  }

  l2sh_check_timeout();
  l2sh_tx_drain();

out:
  l2sh.polling = 0;
}

s32 l2sh_tstc(void) {
  if (!l2sh_runtime_enabled()) return 0;

  return l2sh.rx_ring.count > 0;
}

s32 l2sh_getc(void) {
  u8 ch;

  if (!l2sh_tstc()) return -1;

  if (!l2sh_ring_pop(&l2sh.rx_ring, l2sh.rx_buf, ARRAY_SIZE(l2sh.rx_buf), &ch, 1)) return -1;

  return ch;
}

void l2sh_putc(const char c) {
  u8 ch;

  if (!l2sh_runtime_enabled() || l2sh.state != L2SH_ACTIVE) return;

  l2sh_poll();

  ch = c;
  if (!l2sh_ring_push(&l2sh.tx_ring, l2sh.tx_buf, ARRAY_SIZE(l2sh.tx_buf), &ch, 1)) return;

  if (c == '\n' || l2sh.tx_ring.count >= L2SH_MAX_DATA) l2sh_tx_drain();
}

void l2sh_puts(const char *s) {
  size_t len;
  u32 pushed;

  if (!s || !l2sh_runtime_enabled() || l2sh.state != L2SH_ACTIVE) return;

  l2sh_poll();

  len = strlen(s);
  while (len) {
    if (!l2sh_ring_space(&l2sh.tx_ring, ARRAY_SIZE(l2sh.tx_buf))) {
      l2sh_tx_drain();
      if (!l2sh_ring_space(&l2sh.tx_ring, ARRAY_SIZE(l2sh.tx_buf))) break;
    }

    pushed = l2sh_ring_push(&l2sh.tx_ring, l2sh.tx_buf, ARRAY_SIZE(l2sh.tx_buf), (const u8 *)s, len);
    s += pushed;
    len -= pushed;

    if (l2sh.tx_ring.count >= L2SH_MAX_DATA)
      l2sh_tx_drain();
  }

  l2sh_tx_drain();
}
