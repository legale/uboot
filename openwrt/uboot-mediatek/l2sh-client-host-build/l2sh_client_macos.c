// l2shell_client_macos.c - macOS host client for l2shell_repo

#include "l2sh_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define L2SH_READY_TIMEOUT_NS 1000000000ULL
#define L2SH_IDLE_TIMEOUT_DEFAULT 30
#define L2SH_HANDSHAKE_ATTEMPTS 5
#define L2SH_ARQ_RETRY_NS 100000000ULL
#define L2SH_ARQ_MAX_RETRIES 20
#define NSEC_PER_USEC 1000ULL
#define NSEC_PER_SEC 1000000000ULL

struct l2sh_args {
  const char *iface;
  const char *mac_str;
  const char *spawn_cmd;
  const char *shell;
  const char *cmd;
  s32 local_echo;
  s32 idle_timeout;
};

struct l2sh_ctx {
  s32 bpf_fd;
  u8 local_mac[ETH_ALEN];
  u8 peer_mac[ETH_ALEN];
  u32 peer_proto_version;
  s32 arq_enabled;
  u64 heartbeat_interval_ns;
  u64 next_heartbeat_ns;
  u8 tx_seq;
  u8 rx_expect_seq;
  u8 tx_buf[L2SH_MAX_DATA];
  size_t tx_len;
  u64 tx_deadline_ns;
  s32 tx_retries;
  s32 tx_waiting;
  u8 *rx_buf;
  size_t rx_buf_len;
  size_t rx_off;
  size_t rx_len;
};

struct l2sh_ready_msg {
  u64 nonce;
  u32 proto_version;
  s32 have_nonce;
  s32 have_proto_version;
  s32 from_userland;
  s32 from_kernel;
};

static struct termios saved_stdin_termios;
static s32 stdin_raw_mode_enabled;

static ssize_t l2sh_write_all(int fd, const void *buf, size_t count);

static void l2sh_err(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

static void l2sh_dbg(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

static void l2sh_err(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  fprintf(stderr, "l2shell: ");
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
}

static void l2sh_perror(const char *what) { fprintf(stderr, "l2shell: %s: %s\n", what, strerror(errno)); }

static s32 l2sh_debug_enabled(void) {
  static s32 init;
  static s32 enabled;
  const char *env;

  if (init)
    return enabled;

  env = getenv("L2SH_DEBUG");
  enabled = env && env[0] != '\0' && strcmp(env, "0") != 0;
  init = 1;
  return enabled;
}

static void l2sh_dbg(const char *fmt, ...) {
  va_list ap;

  if (!l2sh_debug_enabled())
    return;

  va_start(ap, fmt);
  fprintf(stderr, "l2shell: debug: ");
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
}

static void usage(const char *prog) {
  fprintf(stderr,
          "usage: %s [-e|--echo] [--spawn <cmd>] [--shell <path>] "
          "[--idle-timeout <sec>] <iface> <server-mac> [cmd]\n",
          prog);
}

static void l2sh_restore_stdin(void) {
  if (!stdin_raw_mode_enabled)
    return;

  tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_stdin_termios);
  stdin_raw_mode_enabled = 0;
}

static s32 l2sh_enable_raw_mode(void) {
  struct termios raw;

  if (!isatty(STDIN_FILENO))
    return 0;
  if (tcgetattr(STDIN_FILENO, &saved_stdin_termios) < 0)
    return -1;

  raw = saved_stdin_termios;
  raw.c_lflag &= (tcflag_t) ~(ICANON | ECHO);
  raw.c_cc[VMIN] = 1;
  raw.c_cc[VTIME] = 0;

  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0)
    return -1;

  stdin_raw_mode_enabled = 1;
  if (atexit(l2sh_restore_stdin) != 0)
    l2sh_restore_stdin();

  return 0;
}

static u64 l2sh_mono_ns(void) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (u64)ts.tv_sec * NSEC_PER_SEC + (u64)ts.tv_nsec;
}

static u64 l2sh_nonce_seed(void) {
  struct timespec ts;

  clock_gettime(CLOCK_REALTIME, &ts);
  return ((u64)ts.tv_sec << 32) ^ (u64)ts.tv_nsec ^ (u64)getpid();
}

static u64 l2sh_calc_heartbeat_interval_ns(int idle_timeout_sec) {
  s32 secs;
  s32 interval;

  secs = idle_timeout_sec;
  if (secs <= 0)
    secs = L2SH_IDLE_TIMEOUT_DEFAULT;

  interval = secs / 2;
  if (interval < 1)
    interval = 1;

  return (u64)(u32)interval * NSEC_PER_SEC;
}

static void l2sh_reset_arq_state(struct l2sh_ctx *ctx) {
  if (!ctx)
    return;

  ctx->tx_seq = 0;
  ctx->rx_expect_seq = 0;
  ctx->tx_len = 0;
  ctx->tx_deadline_ns = 0;
  ctx->tx_retries = 0;
  ctx->tx_waiting = 0;
}

static void l2sh_set_peer_proto(struct l2sh_ctx *ctx, u32 proto_version) {
  if (!ctx)
    return;

  if (proto_version >= L2SH_PROTO_V2) {
    ctx->peer_proto_version = L2SH_PROTO_V2;
    ctx->arq_enabled = 1;
  } else {
    ctx->peer_proto_version = L2SH_PROTO_V1;
    ctx->arq_enabled = 0;
  }
  l2sh_reset_arq_state(ctx);
}

static s32 l2sh_parse_mac(const char *s, u8 mac[ETH_ALEN]) {
  u8 tmp[ETH_ALEN];
  s32 n;

  if (!s || !mac)
    return -1;

  n = sscanf(s, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
  if (n != ETH_ALEN)
    return -1;

  memcpy(mac, tmp, ETH_ALEN);
  return 0;
}

static s32 l2sh_parse_ready_message(const u8 *payload, size_t len, struct l2sh_ready_msg *msg) {
  char buf[128];
  char *nonce_str;
  char *source_str;
  char *proto_str;
  char *endptr;
  size_t copy;
  u64 nonce;
  u32 proto_version;

  if (!payload || !len || !msg)
    return 0;

  copy = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
  memcpy(buf, payload, copy);
  buf[copy] = '\0';

  if (strncmp(buf, "ready", 5) != 0)
    return 0;

  memset(msg, 0, sizeof(*msg));
  msg->proto_version = L2SH_PROTO_V1;
  nonce_str = strstr(buf, "nonce=");
  if (nonce_str && sscanf(nonce_str, "nonce=%llx", &nonce) == 1) {
    msg->have_nonce = 1;
    msg->nonce = (u64)nonce;
  }

  source_str = strstr(buf, "source=");
  if (source_str) {
    if (strncmp(source_str, "source=userland", 15) == 0)
      msg->from_userland = 1;
    else if (strncmp(source_str, "source=kernel", 13) == 0)
      msg->from_kernel = 1;
  }

  proto_str = strstr(buf, "proto=");
  if (proto_str) {
    endptr = NULL;
    proto_version = strtoul(proto_str + strlen("proto="), &endptr, 0);
    if (endptr != proto_str + strlen("proto=")) {
      msg->have_proto_version = 1;
      msg->proto_version = (u32)proto_version;
    }
  }

  return 1;
}

static void l2sh_dbg_payload(const u8 *payload, size_t len) {
  char text[49];
  size_t i;
  size_t n;

  if (!l2sh_debug_enabled() || !payload)
    return;

  n = len < sizeof(text) - 1 ? len : sizeof(text) - 1;
  for (i = 0; i < n; i++) {
    u8 ch = payload[i];
    text[i] = (ch >= 32 && ch <= 126) ? (char)ch : '.';
  }
  text[n] = '\0';
  l2sh_dbg("rx payload len=%zu text='%s'", len, text);
}

static void l2sh_dbg_mac(const char *tag, const u8 mac[ETH_ALEN]) {
  if (!l2sh_debug_enabled() || !tag || !mac)
    return;

  l2sh_dbg("%s %02x:%02x:%02x:%02x:%02x:%02x", tag, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static s32 l2sh_get_iface_mac(const char *iface, u8 mac[ETH_ALEN]) {
  struct ifaddrs *ifaddr;
  struct ifaddrs *ifa;
  struct sockaddr_dl *sdl;
  s32 ret;

  if (!iface || !mac)
    return -1;

  if (getifaddrs(&ifaddr) < 0) {
    l2sh_perror("getifaddrs");
    return -1;
  }

  ret = -1;
  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name || strcmp(ifa->ifa_name, iface) != 0)
      continue;
    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_LINK)
      continue;

    sdl = (struct sockaddr_dl *)ifa->ifa_addr;
    if (sdl->sdl_alen != ETH_ALEN)
      continue;

    memcpy(mac, LLADDR(sdl), ETH_ALEN);
    ret = 0;
    break;
  }

  freeifaddrs(ifaddr);
  if (ret < 0)
    l2sh_err("failed to get mac address for %s", iface);
  return ret;
}

static void l2sh_free_rx_buf(struct l2sh_ctx *ctx) {
  if (!ctx)
    return;

  free(ctx->rx_buf);
  ctx->rx_buf = NULL;
  ctx->rx_buf_len = 0;
  ctx->rx_off = 0;
  ctx->rx_len = 0;
}

static void l2sh_close_socket(struct l2sh_ctx *ctx) {
  if (!ctx)
    return;

  if (ctx->bpf_fd >= 0) {
    close(ctx->bpf_fd);
    ctx->bpf_fd = -1;
  }
  l2sh_free_rx_buf(ctx);
}

static s32 l2sh_open_bpf(void) {
  char path[32];
  s32 fd;
  s32 i;

  for (i = 0; i < 256; i++) {
    snprintf(path, sizeof(path), "/dev/bpf%d", i);
    fd = open(path, O_RDWR);
    if (fd >= 0)
      return fd;
    if (errno != EBUSY)
      break;
  }

  l2sh_perror("open(/dev/bpf*)");
  return -1;
}

static s32 l2sh_install_bpf_filter(struct l2sh_ctx *ctx) {
  struct bpf_insn insns[] = {
      BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, L2SH_ETHERTYPE, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, (u_int)-1),
      BPF_STMT(BPF_RET | BPF_K, 0),
  };
  struct bpf_program prog;

  if (!ctx || ctx->bpf_fd < 0)
    return -1;

  memset(&prog, 0, sizeof(prog));
  prog.bf_len = (u_int)(sizeof(insns) / sizeof(insns[0]));
  prog.bf_insns = insns;
  if (ioctl(ctx->bpf_fd, BIOCSETF, &prog) < 0) {
    l2sh_perror("ioctl(BIOCSETF)");
    return -1;
  }

  return 0;
}

static s32 l2sh_open_socket(struct l2sh_ctx *ctx, const char *iface) {
  struct ifreq ifr;
  u32 one;
  u32 zero;
  u32 dlt;
  u32 buf_len;
  s32 flags;

  if (!ctx || !iface || !iface[0])
    return -1;

  if (l2sh_get_iface_mac(iface, ctx->local_mac) < 0)
    return -1;

  ctx->bpf_fd = l2sh_open_bpf();
  if (ctx->bpf_fd < 0)
    return -1;

  flags = fcntl(ctx->bpf_fd, F_GETFL, 0);
  if (flags < 0) {
    l2sh_perror("fcntl(F_GETFL)");
    l2sh_close_socket(ctx);
    return -1;
  }
  if (fcntl(ctx->bpf_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    l2sh_perror("fcntl(F_SETFL)");
    l2sh_close_socket(ctx);
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
  if (ioctl(ctx->bpf_fd, BIOCSETIF, &ifr) < 0) {
    l2sh_perror("ioctl(BIOCSETIF)");
    l2sh_close_socket(ctx);
    return -1;
  }

  dlt = 0;
  if (ioctl(ctx->bpf_fd, BIOCGDLT, &dlt) < 0) {
    l2sh_perror("ioctl(BIOCGDLT)");
    l2sh_close_socket(ctx);
    return -1;
  }
  if (dlt != DLT_EN10MB) {
    l2sh_err("interface %s is not ethernet (dlt=%u)", iface, dlt);
    l2sh_close_socket(ctx);
    return -1;
  }

  one = 1;
  if (ioctl(ctx->bpf_fd, BIOCIMMEDIATE, &one) < 0) {
    l2sh_perror("ioctl(BIOCIMMEDIATE)");
    l2sh_close_socket(ctx);
    return -1;
  }
  if (ioctl(ctx->bpf_fd, BIOCSHDRCMPLT, &one) < 0) {
    l2sh_perror("ioctl(BIOCSHDRCMPLT)");
    l2sh_close_socket(ctx);
    return -1;
  }

  zero = 0;
  if (ioctl(ctx->bpf_fd, BIOCSSEESENT, &zero) < 0) {
    l2sh_perror("ioctl(BIOCSSEESENT)");
    l2sh_close_socket(ctx);
    return -1;
  }
  if (l2sh_install_bpf_filter(ctx) < 0) {
    l2sh_close_socket(ctx);
    return -1;
  }
  if (ioctl(ctx->bpf_fd, BIOCFLUSH, NULL) < 0) {
    l2sh_perror("ioctl(BIOCFLUSH)");
    l2sh_close_socket(ctx);
    return -1;
  }

  buf_len = 0;
  if (ioctl(ctx->bpf_fd, BIOCGBLEN, &buf_len) < 0) {
    l2sh_perror("ioctl(BIOCGBLEN)");
    l2sh_close_socket(ctx);
    return -1;
  }
  if (!buf_len) {
    l2sh_err("bpf returned zero buffer length");
    l2sh_close_socket(ctx);
    return -1;
  }

  ctx->rx_buf = malloc((size_t)buf_len);
  if (!ctx->rx_buf) {
    l2sh_perror("malloc");
    l2sh_close_socket(ctx);
    return -1;
  }
  ctx->rx_buf_len = (size_t)buf_len;
  ctx->rx_off = 0;
  ctx->rx_len = 0;

  return 0;
}

static s32 l2sh_send_payload(struct l2sh_ctx *ctx, const void *payload, size_t payload_len) {
  l2s_frame_meta_t meta;
  l2s_frame_t frame;
  s32 frame_len;
  ssize_t sent;

  if (!ctx || ctx->bpf_fd < 0)
    return -1;
  if (!payload && payload_len)
    return -1;

  meta.src_mac = ctx->local_mac;
  meta.dst_mac = ctx->peer_mac;
  meta.signature = L2SH_CLIENT_SIGNATURE;
  meta.type = L2S_MSG_DATA;
  meta.flags = 0;
  frame_len = l2s_build_frame(&frame, sizeof(frame), &meta, payload, payload_len);
  if (frame_len < 0)
    return -1;

  sent = write(ctx->bpf_fd, &frame, (size_t)frame_len);
  if (sent < 0 || (size_t)sent != (size_t)frame_len) {
    l2sh_perror("write(bpf)");
    return -1;
  }

  return 0;
}

static void l2sh_arq_ack_rx(struct l2sh_ctx *ctx, u8 ack) {
  if (!ctx || !ctx->tx_waiting)
    return;
  if (ack != ctx->tx_seq)
    return;

  ctx->tx_waiting = 0;
  ctx->tx_len = 0;
  ctx->tx_retries = 0;
  ctx->tx_deadline_ns = 0;
  ctx->tx_seq ^= 1U;
}

static s32 l2sh_send_arq_ack(struct l2sh_ctx *ctx, u8 ack) {
  u8 payload[L2SH_ARQ_HDR_LEN];
  s32 len;

  len = l2s_arq_build_ack(payload, sizeof(payload), ack);
  if (len < 0)
    return -1;

  return l2sh_send_payload(ctx, payload, (size_t)len);
}

static s32 l2sh_send_payload_r(struct l2sh_ctx *ctx, const void *payload, size_t payload_len) {
  s32 len;

  if (!ctx || (!payload && payload_len))
    return -1;
  if (!ctx->arq_enabled)
    return l2sh_send_payload(ctx, payload, payload_len);
  if (ctx->tx_waiting)
    return -1;

  len = l2s_arq_build_data(ctx->tx_buf, sizeof(ctx->tx_buf), ctx->tx_seq, 0, payload, payload_len);
  if (len < 0)
    return -1;

  ctx->tx_len = (size_t)len;
  ctx->tx_retries = 0;
  ctx->tx_waiting = 1;
  ctx->tx_deadline_ns = l2sh_mono_ns() + L2SH_ARQ_RETRY_NS;
  if (l2sh_send_payload(ctx, ctx->tx_buf, ctx->tx_len) < 0) {
    ctx->tx_waiting = 0;
    ctx->tx_len = 0;
    return -1;
  }

  return 0;
}

static s32 l2sh_retransmit_if_needed(struct l2sh_ctx *ctx) {
  u64 now;

  if (!ctx || !ctx->arq_enabled || !ctx->tx_waiting)
    return 0;

  now = l2sh_mono_ns();
  if (now < ctx->tx_deadline_ns)
    return 0;
  if (ctx->tx_retries >= L2SH_ARQ_MAX_RETRIES)
    return -1;
  if (l2sh_send_payload(ctx, ctx->tx_buf, ctx->tx_len) < 0)
    return -1;

  ctx->tx_retries++;
  ctx->tx_deadline_ns = now + L2SH_ARQ_RETRY_NS;
  return 1;
}

static s32 l2sh_handle_session_payload(struct l2sh_ctx *ctx, const u8 *payload, size_t payload_len, s32 *delivered) {
  l2s_arq_view_t arq;
  struct l2sh_ready_msg ready_msg;
  s32 ret;

  if (!ctx || !payload)
    return -1;
  if (delivered)
    *delivered = 0;

  if (l2sh_parse_ready_message(payload, payload_len, &ready_msg)) {
    l2sh_dbg("session ignore_ready nonce=%016llx has_nonce=%d "
             "proto=0x%x",
             (u64)ready_msg.nonce, ready_msg.have_nonce, ready_msg.proto_version);
    return 0;
  }

  if (!ctx->arq_enabled) {
    if (payload_len && l2sh_write_all(STDOUT_FILENO, payload, payload_len) < 0) {
      l2sh_perror("write");
      return -1;
    }
    if (payload_len && delivered)
      *delivered = 1;
    return 0;
  }

  ret = l2s_arq_parse(payload, payload_len, &arq);
  if (ret < 0)
    return 0;
  if (!ret) {
    if (payload_len && l2sh_write_all(STDOUT_FILENO, payload, payload_len) < 0) {
      l2sh_perror("write");
      return -1;
    }
    if (payload_len && delivered)
      *delivered = 1;
    return 0;
  }

  if (arq.is_ack) {
    l2sh_arq_ack_rx(ctx, arq.ack);
    return 0;
  }

  if (l2sh_send_arq_ack(ctx, arq.seq) < 0)
    return -1;
  if (arq.seq != ctx->rx_expect_seq)
    return 0;

  if (arq.data_len && l2sh_write_all(STDOUT_FILENO, arq.data, arq.data_len) < 0) {
    l2sh_perror("write");
    return -1;
  }
  if (arq.data_len && delivered)
    *delivered = 1;
  ctx->rx_expect_seq ^= 1U;
  return 0;
}

static s32 l2sh_send_hello(struct l2sh_ctx *ctx, const struct l2sh_args *args, u64 *nonce_out) {
  u8 payload[L2SH_MAX_DATA];
  hello_builder_t builder;
  u64 nonce;
  s32 len;

  nonce = l2sh_nonce_seed();
  memset(&builder, 0, sizeof(builder));
  builder.spawn_cmd = args ? args->spawn_cmd : NULL;
  builder.shell_cmd = args ? args->shell : NULL;
  builder.nonce = nonce;
  builder.proto_version = L2SH_PROTO_CUR;
  builder.include_spawn = args && args->spawn_cmd && args->spawn_cmd[0];
  builder.include_nonce = 1;
  builder.include_idle_timeout = 1;
  builder.idle_timeout_seconds = L2SH_IDLE_TIMEOUT_DEFAULT;
  if (args)
    builder.idle_timeout_seconds = args->idle_timeout > 0 ? args->idle_timeout : 0;
  builder.include_proto_version = 1;
  len = hello_build(payload, sizeof(payload), &builder);
  if (len < 0)
    return -1;
  if (nonce_out)
    *nonce_out = nonce;

  return l2sh_send_payload(ctx, payload, (size_t)len);
}

static s32 l2sh_send_nonce_confirm(struct l2sh_ctx *ctx, u64 nonce) {
  char buf[64];
  s32 len;

  len = snprintf(buf, sizeof(buf), "nonce_confirm=%016llx\n", (u64)nonce);
  if (len <= 0 || len >= (int)sizeof(buf))
    return -1;

  return l2sh_send_payload(ctx, buf, (size_t)len);
}

static s32 l2sh_send_heartbeat(struct l2sh_ctx *ctx) {
  u8 payload[L2SH_MAX_DATA];
  s32 len;

  len = hello_build_heartbeat(payload, sizeof(payload));
  if (len < 0)
    return -1;

  return l2sh_send_payload(ctx, payload, (size_t)len);
}

static s32 l2sh_fill_rx_buf(struct l2sh_ctx *ctx) {
  ssize_t got;

  if (!ctx || ctx->bpf_fd < 0 || !ctx->rx_buf || !ctx->rx_buf_len)
    return -1;

  got = read(ctx->bpf_fd, ctx->rx_buf, ctx->rx_buf_len);
  if (got < 0) {
    if (errno == EINTR || errno == EAGAIN)
      return 0;
    l2sh_perror("read(bpf)");
    return -1;
  }
  if (!got)
    return 0;

  ctx->rx_off = 0;
  ctx->rx_len = (size_t)got;
  return 1;
}

static s32 l2sh_rx_pending(const struct l2sh_ctx *ctx) {
  if (!ctx)
    return 0;

  return ctx->rx_off < ctx->rx_len;
}

static s32 l2sh_recv_frame(struct l2sh_ctx *ctx, l2s_frame_t *frame, u8 **payload_out, size_t *payload_len_out) {
  struct bpf_hdr *bh;
  const u8 *pkt;
  size_t pkt_len;
  size_t pkt_end;
  size_t next_off;
  u32 sig;
  s32 ret;

  if (!ctx || !frame)
    return -1;

  for (;;) {
    if (ctx->rx_off >= ctx->rx_len) {
      ret = l2sh_fill_rx_buf(ctx);
      if (ret <= 0)
        return ret < 0 ? -1 : 0;
    }

    if (ctx->rx_len - ctx->rx_off < sizeof(*bh)) {
      ctx->rx_off = ctx->rx_len;
      continue;
    }

    bh = (struct bpf_hdr *)(ctx->rx_buf + ctx->rx_off);
    pkt_end = ctx->rx_off + bh->bh_hdrlen + bh->bh_caplen;
    next_off = ctx->rx_off + BPF_WORDALIGN((u_int)(bh->bh_hdrlen + bh->bh_caplen));
    if (bh->bh_hdrlen > ctx->rx_len - ctx->rx_off || pkt_end > ctx->rx_len) {
      ctx->rx_off = ctx->rx_len;
      continue;
    }
    if (next_off > ctx->rx_len)
      next_off = ctx->rx_len;

    pkt = ctx->rx_buf + ctx->rx_off + bh->bh_hdrlen;
    pkt_len = (size_t)bh->bh_caplen;
    ctx->rx_off = next_off;

    if (pkt_len < sizeof(l2s_frame_header_t) || pkt_len > sizeof(*frame)) {
      l2sh_dbg("rx drop_bad_len len=%zu", pkt_len);
      continue;
    }

    memcpy(frame, pkt, pkt_len);
    sig = l2s_get_be32((const u8 *)&frame->header.signature);
    if (memcmp(frame->header.eth_hdr.ether_shost, ctx->peer_mac, ETH_ALEN) != 0) {
      l2sh_dbg_mac("rx drop_src", frame->header.eth_hdr.ether_shost);
      continue;
    }
    if (memcmp(frame->header.eth_hdr.ether_dhost, ctx->local_mac, ETH_ALEN) != 0) {
      l2sh_dbg_mac("rx drop_dst", frame->header.eth_hdr.ether_dhost);
      continue;
    }
    if (l2s_parse_frame(frame, pkt_len, L2SH_SERVER_SIGNATURE, payload_len_out) != L2S_FRAME_OK) {
      l2sh_dbg("rx parse_drop len=%zu sig=0x%08x pay_be=%u", pkt_len, sig, l2s_get_be32((const u8 *)&frame->header.payload_size));
      continue;
    }

    l2sh_dbg("rx frame len=%zu sig=0x%08x payload_len=%zu", pkt_len, sig, payload_len_out ? *payload_len_out : 0);
    if (payload_out)
      *payload_out = frame->payload;
    if (payload_out && payload_len_out)
      l2sh_dbg_payload(*payload_out, *payload_len_out);

    return 1;
  }
}

static s32 l2sh_wait_socket_ready(struct l2sh_ctx *ctx, u64 deadline_ns) {
  fd_set rfds;
  struct timeval tv;
  u64 now;
  u64 rem;
  s32 ret;
  s32 fd;

  if (!ctx)
    return -1;
  if (l2sh_rx_pending(ctx))
    return 1;

  fd = ctx->bpf_fd;
  if (fd < 0)
    return -1;

  for (;;) {
    now = l2sh_mono_ns();
    if (now >= deadline_ns)
      return 0;

    rem = deadline_ns - now;
    tv.tv_sec = (time_t)(rem / NSEC_PER_SEC);
    tv.tv_usec = (suseconds_t)((rem % NSEC_PER_SEC) / NSEC_PER_USEC);
    if (tv.tv_usec >= 1000000)
      tv.tv_usec = 999999;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    ret = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0) {
      if (errno == EINTR)
        continue;
      l2sh_perror("select");
      return -1;
    }
    if (!ret)
      continue;
    if (FD_ISSET(fd, &rfds))
      return 1;
  }
}

static s32 l2sh_wait_ready(struct l2sh_ctx *ctx, u64 expected_nonce, struct l2sh_ready_msg *ready_out) {
  l2s_frame_t frame;
  struct l2sh_ready_msg ready_msg;
  u64 deadline;
  u8 *payload;
  size_t payload_len;
  s32 ret;

  deadline = l2sh_mono_ns() + L2SH_READY_TIMEOUT_NS;
  for (;;) {
    ret = l2sh_wait_socket_ready(ctx, deadline);
    if (ret <= 0)
      return ret < 0 ? -1 : 1;

    ret = l2sh_recv_frame(ctx, &frame, &payload, &payload_len);
    if (ret < 0)
      return -1;
    if (!ret)
      continue;

    if (!l2sh_parse_ready_message(payload, payload_len, &ready_msg)) {
      l2sh_dbg("wait_ready ignore_non_ready payload_len=%zu", payload_len);
      continue;
    }
    l2sh_dbg("wait_ready ready_rx expected=%016llx recv=%016llx "
             "has_nonce=%d "
             "src=userland:%d kernel:%d proto=0x%x have_proto=%d",
             (u64)expected_nonce, (u64)ready_msg.nonce, ready_msg.have_nonce, ready_msg.from_userland, ready_msg.from_kernel,
             ready_msg.proto_version, ready_msg.have_proto_version);
    if (ready_msg.from_kernel && (!ready_msg.have_nonce || ready_msg.nonce == expected_nonce))
      return 2;
    if (ready_msg.have_nonce && ready_msg.nonce == expected_nonce) {
      if (ready_msg.from_userland || (!ready_msg.from_userland && !ready_msg.from_kernel)) {
        if (ready_out)
          *ready_out = ready_msg;
        return 0;
      }
    }
    l2sh_dbg("wait_ready ignore_ready expected=%016llx recv=%016llx", (u64)expected_nonce, (u64)ready_msg.nonce);
  }
}

static s32 l2sh_handshake(struct l2sh_ctx *ctx, const struct l2sh_args *args) {
  struct l2sh_ready_msg ready_msg;
  u64 nonce;
  s32 attempt;
  s32 ret;

  for (attempt = 0; attempt < L2SH_HANDSHAKE_ATTEMPTS; attempt++) {
    if (l2sh_send_hello(ctx, args, &nonce) < 0)
      return -1;

    memset(&ready_msg, 0, sizeof(ready_msg));
    ret = l2sh_wait_ready(ctx, nonce, &ready_msg);
    if (ret == 0) {
      l2sh_set_peer_proto(ctx, ready_msg.have_proto_version ? ready_msg.proto_version : L2SH_PROTO_V1);
      if (l2sh_send_nonce_confirm(ctx, nonce) < 0)
        return -1;
      return 0;
    }
    if (ret == 2)
      continue;
    if (ret < 0)
      return -1;

    l2sh_err("ready timeout on attempt %d", attempt + 1);
  }

  return -1;
}

static void l2sh_norm_stdin(u8 *buf, size_t len) {
  size_t i;

  if (!buf)
    return;

  for (i = 0; i < len; i++) {
    if (buf[i] == '\n')
      buf[i] = '\r';
  }
}

static ssize_t l2sh_write_all(int fd, const void *buf, size_t count) {
  const u8 *ptr;
  size_t left;
  ssize_t written;

  if (fd < 0 || (!buf && count))
    return -1;

  ptr = buf;
  left = count;
  while (left) {
    written = write(fd, ptr, left);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (!written)
      break;
    ptr += written;
    left -= (size_t)written;
  }

  return (ssize_t)(count - left);
}

static s32 l2sh_recv_stdout(struct l2sh_ctx *ctx) {
  l2s_frame_t frame;
  s32 delivered;
  u8 *payload;
  size_t payload_len;
  s32 ret;

  ret = l2sh_recv_frame(ctx, &frame, &payload, &payload_len);
  if (ret <= 0)
    return ret < 0 ? -1 : 0;

  delivered = 0;
  if (l2sh_handle_session_payload(ctx, payload, payload_len, &delivered) < 0)
    return -1;
  return delivered > 0 ? 1 : 0;
}

static s32 l2sh_wait_response(struct l2sh_ctx *ctx) {
  u64 deadline;
  u64 now;
  u64 wait_ns;
  s32 seen;
  s32 ret;

  deadline = l2sh_mono_ns() + L2SH_READY_TIMEOUT_NS;
  seen = 0;
  for (;;) {
    ret = l2sh_retransmit_if_needed(ctx);
    if (ret < 0)
      return -1;
    now = l2sh_mono_ns();
    if (now >= deadline)
      return seen ? 0 : 1;
    wait_ns = deadline - now;
    if (ctx->tx_waiting && ctx->tx_deadline_ns > now && ctx->tx_deadline_ns - now < wait_ns)
      wait_ns = ctx->tx_deadline_ns - now;
    if (!wait_ns)
      continue;

    ret = l2sh_wait_socket_ready(ctx, now + wait_ns);
    if (ret < 0)
      return -1;
    if (!ret)
      continue;

    ret = l2sh_recv_stdout(ctx);
    if (ret < 0)
      return -1;
    if (ret > 0) {
      seen = 1;
      deadline = l2sh_mono_ns() + L2SH_READY_TIMEOUT_NS;
    }
  }
}

static s32 l2sh_handle_stdin(struct l2sh_ctx *ctx, s32 local_echo) {
  u8 buf[L2SH_ARQ_MAX_DATA];
  ssize_t len;

  len = read(STDIN_FILENO, buf, sizeof(buf));
  if (len < 0) {
    if (errno == EINTR)
      return 0;
    l2sh_perror("read");
    return -1;
  }
  if (!len)
    return 2;

  l2sh_norm_stdin(buf, (size_t)len);
  if (local_echo && l2sh_write_all(STDOUT_FILENO, buf, (size_t)len) < 0) {
    l2sh_perror("write");
    return -1;
  }
  if (l2sh_send_payload_r(ctx, buf, (size_t)len) < 0)
    return -1;

  return 1;
}

static s32 l2sh_loop(struct l2sh_ctx *ctx, s32 local_echo) {
  fd_set rfds;
  struct timeval tv;
  u64 now;
  u64 wait_ns;
  s32 ret;

  if (!ctx || ctx->bpf_fd < 0)
    return -1;

  if (ctx->heartbeat_interval_ns > 0 && !ctx->next_heartbeat_ns)
    ctx->next_heartbeat_ns = l2sh_mono_ns() + ctx->heartbeat_interval_ns;

  for (;;) {
    now = l2sh_mono_ns();
    ret = l2sh_retransmit_if_needed(ctx);
    if (ret < 0)
      return -1;
    if (l2sh_rx_pending(ctx)) {
      if (l2sh_recv_stdout(ctx) < 0)
        return -1;
      continue;
    }
    if (ctx->heartbeat_interval_ns > 0 && ctx->next_heartbeat_ns <= now) {
      if (l2sh_send_heartbeat(ctx) < 0)
        return -1;
      ctx->next_heartbeat_ns = now + ctx->heartbeat_interval_ns;
      now = l2sh_mono_ns();
    }

    wait_ns = NSEC_PER_SEC;
    if (ctx->heartbeat_interval_ns > 0) {
      if (ctx->next_heartbeat_ns > now)
        wait_ns = ctx->next_heartbeat_ns - now;
      else
        wait_ns = 1;
    }
    if (ctx->tx_waiting && ctx->tx_deadline_ns > now && ctx->tx_deadline_ns - now < wait_ns)
      wait_ns = ctx->tx_deadline_ns - now;
    if (wait_ns > NSEC_PER_SEC)
      wait_ns = NSEC_PER_SEC;
    if (!wait_ns)
      wait_ns = 1;

    tv.tv_sec = (time_t)(wait_ns / NSEC_PER_SEC);
    tv.tv_usec = (suseconds_t)((wait_ns % NSEC_PER_SEC) / NSEC_PER_USEC);

    FD_ZERO(&rfds);
    FD_SET(ctx->bpf_fd, &rfds);
    if (!ctx->tx_waiting)
      FD_SET(STDIN_FILENO, &rfds);

    ret = select(ctx->bpf_fd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0) {
      if (errno == EINTR)
        continue;
      l2sh_perror("select");
      return -1;
    }
    if (!ret)
      continue;

    if (!ctx->tx_waiting && FD_ISSET(STDIN_FILENO, &rfds)) {
      ret = l2sh_handle_stdin(ctx, local_echo);
      if (ret < 0)
        return -1;
      if (ret == 2)
        return 0;
      if (ret > 0 && ctx->heartbeat_interval_ns > 0)
        ctx->next_heartbeat_ns = l2sh_mono_ns() + ctx->heartbeat_interval_ns;
    }

    if (FD_ISSET(ctx->bpf_fd, &rfds)) {
      if (l2sh_recv_stdout(ctx) < 0)
        return -1;
    }
  }
}

static s32 l2sh_parse_timeout(const char *arg, s32 *timeout) {
  char *end;
  s64 value;

  if (!arg || !timeout)
    return -1;

  end = NULL;
  value = strtol(arg, &end, 10);
  if (!end || *end)
    return -1;
  if (value <= 0 || value > INT_MAX)
    return -1;

  *timeout = (int)value;
  return 0;
}

static s32 l2sh_parse_args(int argc, char **argv, struct l2sh_args *args) {
  s32 i;

  if (!args || !argv || argc < 1)
    return -1;

  memset(args, 0, sizeof(*args));
  args->idle_timeout = L2SH_IDLE_TIMEOUT_DEFAULT;

  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      usage(argv[0]);
      return 1;
    }
    if (!strcmp(argv[i], "-e") || !strcmp(argv[i], "--echo")) {
      args->local_echo = 1;
      continue;
    }
    if (!strcmp(argv[i], "--spawn")) {
      if (i + 1 >= argc) {
        l2sh_err("missing value after %s", argv[i]);
        return -1;
      }
      args->spawn_cmd = argv[++i];
      continue;
    }
    if (!strcmp(argv[i], "--shell")) {
      if (i + 1 >= argc) {
        l2sh_err("missing value after %s", argv[i]);
        return -1;
      }
      args->shell = argv[++i];
      continue;
    }
    if (!strcmp(argv[i], "--idle-timeout")) {
      if (i + 1 >= argc) {
        l2sh_err("missing value after %s", argv[i]);
        return -1;
      }
      if (l2sh_parse_timeout(argv[++i], &args->idle_timeout) < 0) {
        l2sh_err("invalid idle timeout: %s", argv[i]);
        return -1;
      }
      continue;
    }
    if (!args->iface) {
      args->iface = argv[i];
      continue;
    }
    if (!args->mac_str) {
      args->mac_str = argv[i];
      continue;
    }
    if (!args->cmd) {
      args->cmd = argv[i];
      continue;
    }

    l2sh_err("unexpected argument: %s", argv[i]);
    return -1;
  }

  if (!args->iface || !args->mac_str) {
    usage(argv[0]);
    return -1;
  }

  return 0;
}

int main(int argc, char **argv) {
  struct l2sh_args args;
  struct l2sh_ctx ctx;
  u8 cmd_buf[L2SH_ARQ_MAX_DATA];
  size_t cmd_len;
  s32 ret;
  s32 interactive;

  ret = l2sh_parse_args(argc, argv, &args);
  if (ret > 0)
    return EXIT_SUCCESS;
  if (ret < 0)
    return EXIT_FAILURE;

  memset(&ctx, 0, sizeof(ctx));
  ctx.bpf_fd = -1;
  l2sh_set_peer_proto(&ctx, L2SH_PROTO_V1);
  if (l2sh_parse_mac(args.mac_str, ctx.peer_mac) < 0) {
    l2sh_err("invalid mac address: %s", args.mac_str);
    return EXIT_FAILURE;
  }
  ctx.heartbeat_interval_ns = l2sh_calc_heartbeat_interval_ns(args.idle_timeout);

  if (l2sh_open_socket(&ctx, args.iface) < 0)
    return EXIT_FAILURE;

  interactive = args.cmd == NULL;
  if (interactive && l2sh_enable_raw_mode() < 0)
    l2sh_perror("tcsetattr");

  ret = l2sh_handshake(&ctx, &args);
  if (ret < 0) {
    l2sh_close_socket(&ctx);
    if (interactive)
      l2sh_restore_stdin();
    return EXIT_FAILURE;
  }

  ctx.next_heartbeat_ns = l2sh_mono_ns() + ctx.heartbeat_interval_ns;
  if (!args.cmd) {
    ret = l2sh_loop(&ctx, args.local_echo);
    l2sh_close_socket(&ctx);
    l2sh_restore_stdin();
    return ret < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
  }

  cmd_len = strlen(args.cmd);
  if (cmd_len + 2 > sizeof(cmd_buf)) {
    l2sh_err("command is too long");
    l2sh_close_socket(&ctx);
    return EXIT_FAILURE;
  }

  memcpy(cmd_buf, args.cmd, cmd_len);
  cmd_buf[cmd_len] = '\r';
  cmd_buf[cmd_len + 1] = '\n';
  if (args.local_echo) {
    if (l2sh_write_all(STDOUT_FILENO, cmd_buf, cmd_len) < 0 || l2sh_write_all(STDOUT_FILENO, "\n", 1) < 0)
      l2sh_perror("write");
  }
  if (l2sh_send_payload_r(&ctx, cmd_buf, cmd_len + 2) < 0) {
    l2sh_close_socket(&ctx);
    return EXIT_FAILURE;
  }

  ret = l2sh_wait_response(&ctx);
  l2sh_close_socket(&ctx);
  if (ret < 0)
    return EXIT_FAILURE;
  if (ret > 0) {
    l2sh_err("no response from server");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
