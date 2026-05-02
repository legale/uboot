/* client.c - Layer 2 shell client (positional with named flags)
 * usage: client [-e|--echo] [-h|--help] <iface> <server-mac> [shell] [cmd]
 */

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "cli_helper.h"
#include "common.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define RESPONSE_TIMEOUT_NS (1000ULL * NSEC_PER_MSEC)
#define CLIENT_IDLE_TIMEOUT_DEFAULT_SEC 30
#define CLIENT_ARQ_RETRY_NS (100ULL * NSEC_PER_MSEC)
#define CLIENT_ARQ_MAX_RETRIES 20

typedef struct {
  const char *iface;
  const char *mac_str;
  const char *spawn_cmd;
  const char *shell;
  const char *cmd;
  const char *log_path;
  s32 local_echo;
  s32 idle_timeout;
} client_args_t;

typedef struct {
  s32 sockfd;
  struct ifreq ifr;
  struct sockaddr_ll bind_addr;
  struct sockaddr_ll saddr;
  u8 server_mac[ETH_ALEN];
  s32 local_echo;
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
} client_ctx_t;

typedef struct ready_msg {
  u64 nonce;
  u32 proto_version;
  s32 have_nonce;
  s32 have_proto_version;
  s32 from_userland;
  s32 from_kernel;
} ready_msg_t;

static struct termios saved_stdin_termios;
static s32 stdin_raw_mode_enabled;

static const char *client_shell_name(const client_args_t *args) {
  if (!args || !args->shell || args->shell[0] == '\0')
    return "<default>";
  return args->shell;
}

static const char *client_spawn_name(const client_args_t *args) {
  if (!args || !args->spawn_cmd || args->spawn_cmd[0] == '\0')
    return "<none>";
  return args->spawn_cmd;
}

static const char *client_ready_source(const ready_msg_t *msg) {
  if (!msg)
    return "unknown";
  if (msg->from_kernel)
    return "kernel";
  if (msg->from_userland)
    return "userland";
  return "unknown";
}

static void client_restore_stdin(void) {
  if (!stdin_raw_mode_enabled)
    return;
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_stdin_termios);
  stdin_raw_mode_enabled = 0;
}

static s32 client_enable_raw_mode(void) {
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
  if (atexit(client_restore_stdin) != 0)
    client_restore_stdin();
  return 0;
}

// forward declarations
static void usage(const char *p);
static s32 client_ctx_init(client_ctx_t *ctx, const client_args_t *args);
static void client_ctx_deinit(client_ctx_t *ctx);

static u64 client_generate_nonce(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return ((u64)ts.tv_sec << 32) ^ (u64)ts.tv_nsec ^ (u64)getpid();
}

static u64 client_calc_heartbeat_interval_ns(s32 idle_timeout_sec) {
  s32 secs = idle_timeout_sec;
  if (secs <= 0)
    secs = CLIENT_IDLE_TIMEOUT_DEFAULT_SEC;
  s32 interval = secs / 2;
  if (interval < 1)
    interval = 1;
  return (u64)interval * NSEC_PER_SEC;
}

static void client_reset_arq_state(client_ctx_t *ctx) {
  if (!ctx)
    return;

  ctx->tx_seq = 0;
  ctx->rx_expect_seq = 0;
  ctx->tx_len = 0;
  ctx->tx_deadline_ns = 0;
  ctx->tx_retries = 0;
  ctx->tx_waiting = 0;
}

static void client_set_peer_proto(client_ctx_t *ctx, u32 proto_version) {
  if (!ctx)
    return;

  if (proto_version >= L2SH_PROTO_V2) {
    ctx->peer_proto_version = L2SH_PROTO_V2;
    ctx->arq_enabled = 1;
  } else {
    ctx->peer_proto_version = L2SH_PROTO_V1;
    ctx->arq_enabled = 0;
  }
  client_reset_arq_state(ctx);
}

static s32 parse_ready_message(const u8 *payload, size_t len, ready_msg_t *msg) {
  char buf[128];
  size_t copy;

  if (!payload || len == 0 || !msg)
    return 0;
  copy = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
  memcpy(buf, payload, copy);
  buf[copy] = '\0';

  if (strncmp(buf, "ready", 5) != 0)
    return 0;

  msg->have_nonce = 0;
  msg->nonce = 0;
  msg->have_proto_version = 0;
  msg->proto_version = L2SH_PROTO_V1;
  msg->from_userland = 0;
  msg->from_kernel = 0;

  char *nonce_str = strstr(buf, "nonce=");
  if (nonce_str) {
    u64 tmp;
    if (sscanf(nonce_str, "nonce=%" PRIx64, &tmp) == 1) {
      msg->have_nonce = 1;
      msg->nonce = (u64)tmp;
    }
  }
  char *source_str = strstr(buf, "source=");
  if (source_str) {
    if (strncmp(source_str, "source=userland", 15) == 0)
      msg->from_userland = 1;
    else if (strncmp(source_str, "source=kernel", 13) == 0)
      msg->from_kernel = 1;
  }

  char *proto_str = strstr(buf, "proto=");
  if (proto_str) {
    u64 tmp;
    char *endptr = NULL;

    tmp = strtoul(proto_str + strlen("proto="), &endptr, 0);
    if (endptr != proto_str + strlen("proto=")) {
      msg->have_proto_version = 1;
      msg->proto_version = (u32)tmp;
    }
  }
  return 1;
}

/* parse mac aa:bb:cc:dd:ee:ff */
static inline s32 a2mac(const char *s, u8 mac[ETH_ALEN]) {
  u8 v[ETH_ALEN];
  if (!s)
    return -1;
  s32 n = sscanf(s, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
  if (n != ETH_ALEN)
    return -1;
  memcpy(mac, v, ETH_ALEN);
  return 0;
}

static s32 init_client_sock(client_ctx_t *ctx, const char *iface) {
  assert(ctx);
  assert(iface);

  if (init_packet_socket(&ctx->sockfd, &ctx->ifr, &ctx->bind_addr, iface, 0) != 0) {
    return -1;
  }

  memset(&ctx->saddr, 0, sizeof(ctx->saddr));
  ctx->saddr.sll_family = AF_PACKET;
  ctx->saddr.sll_protocol = htons(L2SH_ETHERTYPE);
  ctx->saddr.sll_ifindex = ctx->bind_addr.sll_ifindex;
  ctx->saddr.sll_halen = ETH_ALEN;
  memcpy(ctx->saddr.sll_addr, ctx->server_mac, ETH_ALEN);

  return 0;
}

static void client_ctx_deinit(client_ctx_t *ctx) {
  if (!ctx)
    return;
  deinit_packet_socket(&ctx->sockfd);
}

static s32 client_ctx_init(client_ctx_t *ctx, const client_args_t *args) {
  if (!ctx || !args || !args->iface || !args->mac_str)
    return -1;
  memset(ctx, 0, sizeof(*ctx));
  ctx->sockfd = -1;
  ctx->local_echo = args->local_echo;
  client_set_peer_proto(ctx, L2SH_PROTO_V1);
  ctx->heartbeat_interval_ns = client_calc_heartbeat_interval_ns(args->idle_timeout);
  ctx->next_heartbeat_ns = 0;

  if (a2mac(args->mac_str, ctx->server_mac) < 0) {
    log_error("client_args", "event=invalid_mac value=%s", args->mac_str);
    return -1;
  }

  if (init_client_sock(ctx, args->iface) != 0) {
    client_ctx_deinit(ctx);
    return -1;
  }
  return 0;
}

/* crlf normalize for stdin */
static void norm_in(u8 *buf, size_t len) {
  for (size_t i = 0; i < len; i++)
    if (buf[i] == '\n')
      buf[i] = '\r';
}

static s32 client_recv_packet(client_ctx_t *ctx, l2s_frame_t *pack, s32 *payload_len) {
  struct sockaddr_ll peer;
  socklen_t plen = sizeof(peer);
  ssize_t got;
  size_t parsed_len = 0;

  assert(ctx);
  assert(pack);

  got = recvfrom(ctx->sockfd, pack, sizeof(*pack), 0, (struct sockaddr *)&peer, &plen);
  if (got < 0) {
    if (errno == EINTR || errno == EAGAIN)
      return 0;
    log_error_errno("client_recv", "recvfrom");
    return -1;
  }
  if (got == 0)
    return 0;
  if (peer.sll_ifindex != ctx->bind_addr.sll_ifindex)
    return 0;

  s32 rc = l2s_parse_frame(pack, (size_t)got, L2SH_SERVER_SIGNATURE, &parsed_len);
  if (rc != L2S_FRAME_OK)
    return 0;
  if (memcmp(pack->header.eth_hdr.ether_shost, ctx->server_mac, ETH_ALEN) != 0)
    return 0;
  debug_dump_frame("client_rx frame ", (const u8 *)pack, (size_t)got);
  if (payload_len)
    *payload_len = (int)parsed_len;
  return 1;
}

static s32 client_send_payload(client_ctx_t *ctx, const void *payload, size_t payload_len) {
  l2s_frame_meta_t meta = {
      .src_mac = (u8 *)ctx->ifr.ifr_hwaddr.sa_data,
      .dst_mac = ctx->server_mac,
      .signature = L2SH_CLIENT_SIGNATURE,
      .type = L2S_MSG_DATA,
      .flags = 0,
  };
  s32 frame_len = l2s_send_frame_to_socket(ctx->sockfd, &ctx->saddr, &meta, payload, payload_len, "client_tx frame ");
  if (frame_len < 0) {
    log_error_errno("client_send", "event=sendto");
    return -1;
  }
  return 0;
}

static void client_arq_ack_rx(client_ctx_t *ctx, u8 ack) {
  if (!ctx || !ctx->tx_waiting)
    return;
  if (ack != ctx->tx_seq) {
    log_info("client_arq", "event=ack_ignored ack=%u expect=%u", ack, ctx->tx_seq);
    return;
  }

  log_info("client_arq", "event=ack_rx ack=%u retries=%d", ack, ctx->tx_retries);
  ctx->tx_waiting = 0;
  ctx->tx_len = 0;
  ctx->tx_retries = 0;
  ctx->tx_deadline_ns = 0;
  ctx->tx_seq ^= 1U;
}

static s32 client_send_arq_ack(client_ctx_t *ctx, u8 ack) {
  u8 payload[L2SH_ARQ_HDR_LEN];
  s32 len = l2s_arq_build_ack(payload, sizeof(payload), ack);

  if (len < 0)
    return -1;
  log_info("client_arq", "event=ack_tx ack=%u", ack);
  return client_send_payload(ctx, payload, (size_t)len);
}

static s32 client_send_reliable_payload(client_ctx_t *ctx, const void *payload, size_t payload_len) {
  s32 len;

  if (!ctx || (payload_len > 0 && !payload))
    return -1;
  if (!ctx->arq_enabled)
    return client_send_payload(ctx, payload, payload_len);
  if (ctx->tx_waiting) {
    log_error("client_arq", "event=send_while_waiting");
    return -1;
  }

  len = l2s_arq_build_data(ctx->tx_buf, sizeof(ctx->tx_buf), ctx->tx_seq, 0, payload, payload_len);
  if (len < 0) {
    log_error("client_arq", "event=build_failed len=%zu", payload_len);
    return -1;
  }

  ctx->tx_len = (size_t)len;
  ctx->tx_retries = 0;
  ctx->tx_waiting = 1;
  ctx->tx_deadline_ns = l2s_mono_ns() + CLIENT_ARQ_RETRY_NS;
  log_info("client_arq", "event=data_tx seq=%u len=%zu", ctx->tx_seq, payload_len);
  if (client_send_payload(ctx, ctx->tx_buf, ctx->tx_len) != 0) {
    ctx->tx_waiting = 0;
    ctx->tx_len = 0;
    return -1;
  }

  return 0;
}

static s32 client_retransmit_if_needed(client_ctx_t *ctx) {
  u64 now;

  if (!ctx || !ctx->arq_enabled || !ctx->tx_waiting)
    return 0;

  now = l2s_mono_ns();
  if (now < ctx->tx_deadline_ns)
    return 0;
  if (ctx->tx_retries >= CLIENT_ARQ_MAX_RETRIES) {
    log_error("client_arq", "event=retry_limit retries=%d", ctx->tx_retries);
    return -1;
  }
  log_info("client_arq", "event=retransmit seq=%u retry=%d len=%zu", ctx->tx_seq, ctx->tx_retries + 1, ctx->tx_len);
  if (client_send_payload(ctx, ctx->tx_buf, ctx->tx_len) != 0)
    return -1;

  ctx->tx_retries++;
  ctx->tx_deadline_ns = now + CLIENT_ARQ_RETRY_NS;
  return 1;
}

static s32 client_handle_session_payload(client_ctx_t *ctx, const u8 *payload, size_t payload_len, s32 *delivered) {
  l2s_arq_view_t arq;
  ready_msg_t ready_msg;
  s32 rc;

  if (!ctx || !payload)
    return -1;
  if (delivered)
    *delivered = 0;

  if (parse_ready_message(payload, payload_len, &ready_msg)) {
    log_info("client_ready", "event=ignore_session_ready nonce=%" PRIx64 " proto=0x%x", (u64)ready_msg.nonce, ready_msg.proto_version);
    return 0;
  }

  if (!ctx->arq_enabled) {
    if (payload_len > 0) {
      (void)write(STDOUT_FILENO, payload, payload_len);
      if (delivered)
        *delivered = 1;
    }
    return 0;
  }

  rc = l2s_arq_parse(payload, payload_len, &arq);
  if (rc < 0)
    return 0;
  if (rc == 0) {
    log_info("client_arq", "event=plain_rx len=%zu", payload_len);
    if (payload_len > 0) {
      (void)write(STDOUT_FILENO, payload, payload_len);
      if (delivered)
        *delivered = 1;
    }
    return 0;
  }

  if (arq.is_ack) {
    client_arq_ack_rx(ctx, arq.ack);
    return 0;
  }

  log_info("client_arq", "event=data_rx seq=%u expect=%u len=%u", arq.seq, ctx->rx_expect_seq, arq.data_len);
  if (client_send_arq_ack(ctx, arq.seq) != 0)
    return -1;
  if (arq.seq != ctx->rx_expect_seq) {
    log_info("client_arq", "event=data_dup seq=%u expect=%u", arq.seq, ctx->rx_expect_seq);
    return 0;
  }

  if (arq.data_len > 0) {
    (void)write(STDOUT_FILENO, arq.data, arq.data_len);
    if (delivered)
      *delivered = 1;
  }
  ctx->rx_expect_seq ^= 1U;
  return 0;
}

static s32 recv_once_and_process(client_ctx_t *ctx, s32 *delivered) {
  l2s_frame_t pack;
  s32 payload_len = 0;
  s32 rc = client_recv_packet(ctx, &pack, &payload_len);

  if (delivered)
    *delivered = 0;
  if (rc <= 0)
    return rc < 0 ? -1 : 0;

  return client_handle_session_payload(ctx, pack.payload, (size_t)payload_len, delivered);
}

static s32 client_send_heartbeat(client_ctx_t *ctx) {
  u8 payload[L2SH_MAX_DATA] = {0};
  s32 len = hello_build_heartbeat(payload, sizeof(payload));
  if (len < 0) {
    log_error("client_heartbeat", "event=build_failed");
    return -1;
  }
  s32 rc = client_send_payload(ctx, payload, (size_t)len);
  if (rc != 0) {
    log_error("client_heartbeat", "event=send_failed interval_ns=%" PRIu64 "", (u64)ctx->heartbeat_interval_ns);
  }
  return rc;
}

static s32 client_send_nonce_confirm(client_ctx_t *ctx, u64 nonce) {
  char buf[64];
  s32 len = snprintf(buf, sizeof(buf), "nonce_confirm=%" PRIx64 "\n", (u64)nonce);
  if (len <= 0 || len >= (int)sizeof(buf)) {
    log_error("client_nonce", "event=format_failed");
    return -1;
  }
  log_info("client_nonce", "event=send nonce=%" PRIx64 "", (u64)nonce);
  return client_send_payload(ctx, buf, (size_t)len);
}

static s32 client_send_hello(client_ctx_t *ctx, const client_args_t *args, u64 *nonce_out) {
  const char *shell_cmd = (args && args->shell) ? args->shell : NULL;
  const char *spawn_cmd = NULL;
  s32 include_spawn = 0;
  if (args && args->spawn_cmd && args->spawn_cmd[0] != '\0') {
    spawn_cmd = args->spawn_cmd;
    include_spawn = 1;
  }
  u8 payload[L2SH_MAX_DATA] = {0};
  u64 nonce = client_generate_nonce();
  s32 timeout = CLIENT_IDLE_TIMEOUT_DEFAULT_SEC;
  if (args && args->idle_timeout > 0)
    timeout = args->idle_timeout;
  hello_builder_t builder = {
      .spawn_cmd = spawn_cmd,
      .shell_cmd = shell_cmd,
      .nonce = nonce,
      .proto_version = L2SH_PROTO_CUR,
      .include_spawn = (u8)include_spawn,
      .include_nonce = 1,
      .include_idle_timeout = 1,
      .idle_timeout_seconds = timeout,
      .include_proto_version = 1,
  };
  s32 hello_len = hello_build(payload, sizeof(payload), &builder);
  if (hello_len < 0) {
    log_error("client_hello", "event=build_failed");
    return -1;
  }
  if (nonce_out)
    *nonce_out = nonce;
  log_info("client_hello",
           "event=send nonce=%" PRIx64 " shell='%s' spawn='%s' idle_timeout=%d "
           "proto=0x%x",
           (u64)nonce, client_shell_name(args), client_spawn_name(args), timeout, (s32)L2SH_PROTO_CUR);
  return client_send_payload(ctx, payload, (size_t)hello_len);
}

static s32 client_wait_socket_ready(client_ctx_t *ctx, u64 deadline_ns, const char *log_tag) {
  assert(ctx);
  while (1) {
    u64 now = l2s_mono_ns();
    if (now >= deadline_ns)
      return 0;

    u64 rem = deadline_ns - now;
    struct timeval tv = {
        .tv_sec = (time_t)(rem / NSEC_PER_SEC),
        .tv_usec = (suseconds_t)((rem % NSEC_PER_SEC) / NSEC_PER_USEC),
    };
    if (tv.tv_usec >= 1000000)
      tv.tv_usec = 999999;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(ctx->sockfd, &rfds);

    s32 rc = select(ctx->sockfd + 1, &rfds, NULL, NULL, &tv);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      log_error_errno(log_tag, "select");
      return -1;
    }
    if (rc == 0)
      continue;
    if (FD_ISSET(ctx->sockfd, &rfds))
      return 1;
  }
}

static s32 client_wait_ready(client_ctx_t *ctx, u64 expected_nonce, u64 timeout_ns, ready_msg_t *ready_out) {
  u64 deadline = l2s_mono_ns() + timeout_ns;
  l2s_frame_t pack;

  while (1) {
    s32 ready = client_wait_socket_ready(ctx, deadline, "client_wait_ready");
    if (ready <= 0)
      return ready < 0 ? -1 : 1;

    ready_msg_t ready_msg;
    s32 payload_len = 0;
    s32 got = client_recv_packet(ctx, &pack, &payload_len);
    if (got < 0)
      return -1;
    if (got == 0)
      continue;

    if (parse_ready_message(pack.payload, (size_t)payload_len, &ready_msg)) {
      log_info("client_wait_ready",
               "event=ready_rx expected=%" PRIx64 " recv=%" PRIx64 " has_nonce=%d "
               "source=%s proto=0x%x have_proto=%d",
               (u64)expected_nonce, (u64)ready_msg.nonce, ready_msg.have_nonce, client_ready_source(&ready_msg), ready_msg.proto_version,
               ready_msg.have_proto_version);
      if (ready_msg.from_kernel && (!ready_msg.have_nonce || ready_msg.nonce == expected_nonce))
        return 2;
      if (ready_msg.have_nonce && ready_msg.nonce == expected_nonce) {
        if (ready_msg.from_userland || (!ready_msg.from_userland && !ready_msg.from_kernel)) {
          if (ready_out)
            *ready_out = ready_msg;
          return 0;
        }
      }
      log_info("client_wait_ready",
               "event=ready_ignored expected=%" PRIx64 " recv=%" PRIx64 " has_nonce=%d "
               "src=userland:%d kernel:%d proto=0x%x have_proto=%d",
               (u64)expected_nonce, (u64)ready_msg.nonce, ready_msg.have_nonce, ready_msg.from_userland, ready_msg.from_kernel,
               ready_msg.proto_version, ready_msg.have_proto_version);
      continue;
    }
  }
}

static s32 client_handshake(client_ctx_t *ctx, const client_args_t *args) {
  const s32 max_attempts = 5;
  s32 attempt = 0;

  log_info("client_handshake",
           "event=start iface=%s server_mac=%s shell='%s' spawn='%s' "
           "idle_timeout=%d",
           args && args->iface ? args->iface : "<none>", args && args->mac_str ? args->mac_str : "<none>", client_shell_name(args),
           client_spawn_name(args), args ? args->idle_timeout : 0);

  while (attempt < max_attempts) {
    u64 nonce = 0;
    ready_msg_t ready_msg = {0};

    log_info("client_handshake", "event=attempt num=%d max=%d", attempt + 1, max_attempts);
    if (client_send_hello(ctx, args, &nonce) != 0)
      return -1;
    s32 ready = client_wait_ready(ctx, nonce, RESPONSE_TIMEOUT_NS, &ready_msg);
    if (ready == 0) {
      client_set_peer_proto(ctx, ready_msg.have_proto_version ? ready_msg.proto_version : L2SH_PROTO_V1);
      if (client_send_nonce_confirm(ctx, nonce) != 0)
        return -1;
      log_info("client_handshake", "event=ready nonce=%" PRIx64 " source=%s proto=0x%x arq=%d", (u64)nonce, client_ready_source(&ready_msg),
               ctx->peer_proto_version, ctx->arq_enabled);
      return 0;
    }
    if (ready == 2) {
      log_info("client_handshake", "event=kernel_stage nonce=%" PRIx64 " action=wait_userland", (u64)nonce);
      attempt++;
      continue;
    }
    if (ready < 0)
      return -1;
    log_error("client_handshake", "event=timeout attempt=%d stage=wait_ready", attempt + 1);
    attempt++;
  }

  log_error("client_handshake", "event=ready_failed attempts=%d", max_attempts);
  return -1;
}
static s32 client_handle_socket_event(client_ctx_t *ctx) {
  assert(ctx);
  s32 delivered = 0;
  s32 rc = recv_once_and_process(ctx, &delivered);
  return (rc < 0) ? -1 : 0;
}

static s32 client_handle_stdin_event(client_ctx_t *ctx) {
  assert(ctx);
  u8 ibuf[L2SH_ARQ_MAX_DATA];
  ssize_t r = read(STDIN_FILENO, ibuf, sizeof(ibuf));
  if (r < 0) {
    if (errno == EINTR)
      return 0;
    log_error_errno("client_stdin", "read");
    return -1;
  }
  if (r == 0)
    return 0;

  norm_in(ibuf, (size_t)r);
  if (ctx->local_echo)
    (void)write(STDOUT_FILENO, ibuf, (size_t)r);
  if (client_send_reliable_payload(ctx, ibuf, (size_t)r) != 0)
    return -1;
  return 1;
}

static s32 wait_resp(client_ctx_t *ctx, u64 deadline_ns) {
  s32 seen = 0;

  for (;;) {
    u64 now;
    u64 wait_ns;
    struct timeval tv;
    fd_set rfds;
    s32 ready;

  rc:
    ready = client_retransmit_if_needed(ctx);
    if (ready < 0)
      return -1;
    now = l2s_mono_ns();
    if (now >= deadline_ns)
      return seen ? 1 : 0;
    wait_ns = deadline_ns - now;
    if (ctx->tx_waiting && ctx->tx_deadline_ns > now && ctx->tx_deadline_ns - now < wait_ns) {
      wait_ns = ctx->tx_deadline_ns - now;
    }
    if (wait_ns > NSEC_PER_SEC)
      wait_ns = NSEC_PER_SEC;
    if (wait_ns == 0)
      goto rc;

    tv.tv_sec = (time_t)(wait_ns / NSEC_PER_SEC);
    tv.tv_usec = (suseconds_t)((wait_ns % NSEC_PER_SEC) / NSEC_PER_USEC);
    FD_ZERO(&rfds);
    FD_SET(ctx->sockfd, &rfds);
    ready = select(ctx->sockfd + 1, &rfds, NULL, NULL, &tv);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      log_error_errno("client_wait", "select");
      return -1;
    }
    if (ready == 0)
      continue;

    s32 delivered = 0;
    if (recv_once_and_process(ctx, &delivered) != 0)
      return -1;
    if (delivered > 0)
      seen = 1;
  }
}

/* interactive loop using shared recv path */
static s32 client_loop(client_ctx_t *ctx) {
  if (!ctx || ctx->sockfd < 0)
    return -1;

  if (ctx->heartbeat_interval_ns > 0 && ctx->next_heartbeat_ns == 0)
    ctx->next_heartbeat_ns = l2s_mono_ns() + ctx->heartbeat_interval_ns;

  for (;;) {
    u64 now = l2s_mono_ns();
    u64 wait_ns = NSEC_PER_SEC;
    struct timeval tv;
    fd_set rfds;
    s32 maxfd = ctx->sockfd;
    s32 rc;

    rc = client_retransmit_if_needed(ctx);
    if (rc < 0)
      return -1;

    if (ctx->heartbeat_interval_ns > 0 && ctx->next_heartbeat_ns <= now) {
      if (client_send_heartbeat(ctx) != 0)
        return -1;
      ctx->next_heartbeat_ns = now + ctx->heartbeat_interval_ns;
      now = l2s_mono_ns();
    }

    if (ctx->heartbeat_interval_ns > 0) {
      if (ctx->next_heartbeat_ns > now)
        wait_ns = ctx->next_heartbeat_ns - now;
      else
        wait_ns = 0;
    }
    if (ctx->tx_waiting && ctx->tx_deadline_ns > now && ctx->tx_deadline_ns - now < wait_ns) {
      wait_ns = ctx->tx_deadline_ns - now;
    }
    if (wait_ns > NSEC_PER_SEC)
      wait_ns = NSEC_PER_SEC;
    if (wait_ns == 0)
      wait_ns = 1;

    tv.tv_sec = (time_t)(wait_ns / NSEC_PER_SEC);
    tv.tv_usec = (suseconds_t)((wait_ns % NSEC_PER_SEC) / NSEC_PER_USEC);
    FD_ZERO(&rfds);
    FD_SET(ctx->sockfd, &rfds);
    if (!ctx->tx_waiting) {
      FD_SET(STDIN_FILENO, &rfds);
      if (STDIN_FILENO > maxfd)
        maxfd = STDIN_FILENO;
    }

    rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      log_error_errno("client_loop", "select");
      return -1;
    }

    s32 stdin_activity = 0;
    if (!ctx->tx_waiting && FD_ISSET(STDIN_FILENO, &rfds)) {
      s32 handled = client_handle_stdin_event(ctx);
      if (handled < 0)
        return -1;
      if (handled > 0)
        stdin_activity = 1;
    }

    if (stdin_activity && ctx->heartbeat_interval_ns > 0)
      ctx->next_heartbeat_ns = l2s_mono_ns() + ctx->heartbeat_interval_ns;

    if (FD_ISSET(ctx->sockfd, &rfds)) {
      if (client_handle_socket_event(ctx) != 0)
        return -1;
    }
  }
}

/* cli parser using cli_helper.h style */
static s32 parse_idle_timeout_value(const char *arg, s32 *value) {
  if (!arg || !value)
    return -1;
  char *endptr = NULL;
  long parsed = strtol(arg, &endptr, 10);
  if (!endptr || *endptr != '\0')
    return -1;
  if (parsed <= 0 || parsed > INT_MAX)
    return -1;
  *value = (int)parsed;
  return 0;
}

static s32 parse_client_args(s32 argc, char **argv, client_args_t *args) {
  if (!args || !argv)
    return 1;
  memset(args, 0, sizeof(*args));

  const char *argv0 = argv[0];

  while (argc > 1) {
    NEXT_ARG();
    if (matches(*argv, "-h") || matches(*argv, "--help")) {
      usage(argv0);
      return 1;
    }
    if (matches(*argv, "-e") || matches(*argv, "--echo")) {
      args->local_echo = 1;
      continue;
    }
    if (matches(*argv, "--spawn")) {
      NEXT_ARG();
      args->spawn_cmd = *argv;
      continue;
    }
    if (matches(*argv, "--idle-timeout")) {
      NEXT_ARG();
      s32 value = 0;
      if (parse_idle_timeout_value(*argv, &value) != 0) {
        log_error("client_args", "event=invalid_timeout value=%s", *argv);
        return 1;
      }
      args->idle_timeout = value;
      continue;
    }
    if (matches(*argv, "--log-file")) {
      NEXT_ARG();
      args->log_path = *argv;
      continue;
    }
    if (!args->iface) {
      args->iface = *argv;
      continue;
    }
    if (!args->mac_str) {
      args->mac_str = *argv;
      continue;
    }
    if (!args->shell) {
      args->shell = *argv;
      continue;
    }
    if (!args->cmd) {
      args->cmd = *argv;
      continue;
    }
    log_error("client_args", "event=unexpected_arg value=%s", *argv);
    return 1;
  }

  if (!args->iface || !args->mac_str) {
    usage(argv0);
    return 1;
  }
  return 0;
}

static s32 client_main(s32 argc, char **argv) {
  client_args_t a = {0};
  s32 pr = parse_client_args(argc, argv, &a);
  if (pr != 0)
    return pr > 0 ? 0 : 1;
  if (a.idle_timeout <= 0)
    a.idle_timeout = CLIENT_IDLE_TIMEOUT_DEFAULT_SEC;
  if (a.log_path && log_redirect_stdio(a.log_path) != 0) {
    log_error_errno("client_args", "event=log_file_open path=%s", a.log_path);
    return 1;
  }

  client_ctx_t ctx;
  if (client_ctx_init(&ctx, &a) != 0)
    return 1;

  const s32 interactive = (a.cmd == NULL);
  if (interactive && client_enable_raw_mode() != 0) {
    log_error_errno("client_tty", "event=raw_mode");
  }

  if (client_handshake(&ctx, &a) != 0) {
    client_ctx_deinit(&ctx);
    if (interactive)
      client_restore_stdin();
    return 1;
  }

  if (ctx.heartbeat_interval_ns > 0)
    ctx.next_heartbeat_ns = l2s_mono_ns() + ctx.heartbeat_interval_ns;

  if (a.cmd) {
    u8 buf[L2SH_ARQ_MAX_DATA];
    size_t len = strlen(a.cmd);

    if (len + 2 > sizeof(buf)) {
      log_error("client_cmd", "event=command_too_long len=%zu", len);
      client_ctx_deinit(&ctx);
      return 1;
    }
    memcpy(buf, a.cmd, len);
    buf[len] = '\r';
    buf[len + 1] = '\n';
    if (ctx.local_echo) {
      (void)write(STDOUT_FILENO, buf, len);
      (void)write(STDOUT_FILENO, "\n", 1);
    }
    if (client_send_reliable_payload(&ctx, buf, len + 2) != 0) {
      client_ctx_deinit(&ctx);
      if (interactive)
        client_restore_stdin();
      return 1;
    }

    u64 dl = l2s_mono_ns() + RESPONSE_TIMEOUT_NS;
    s32 seen = wait_resp(&ctx, dl);
    if (seen <= 0) {
      if (seen == 0)
        log_error("client_wait", "event=no_response timeout_ns=%" PRIu64 "", (u64)RESPONSE_TIMEOUT_NS);
      client_ctx_deinit(&ctx);
      if (interactive)
        client_restore_stdin();
      return 1;
    }
    client_ctx_deinit(&ctx);
    if (interactive)
      client_restore_stdin();
    return 0;
  }

  {
    s32 rc = client_loop(&ctx);
    client_ctx_deinit(&ctx);
    if (interactive)
      client_restore_stdin();
    return rc == 0 ? 0 : 1;
  }
}

int main(int argc, char **argv) { return client_main((s32)argc, argv); }

/* usage printer */
static void usage(const char *p) {
  fprintf(stderr,
          "usage: %s [-e|--echo] [--spawn <cmd>] [--idle-timeout <sec>] "
          "[--log-file <path>] [-h|--help] <iface> <server-mac> [shell] [cmd]\n",
          p);
}
