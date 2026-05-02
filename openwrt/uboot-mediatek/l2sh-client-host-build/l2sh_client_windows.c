// l2shell_client_windows.c - Windows host client for l2shell_repo

#include "l2sh_proto.h"

#include <errno.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include <winsock2.h>

#include <ws2tcpip.h>

#include <windows.h>

#include <iphlpapi.h>

#include <limits.h>
#include <pcap.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define L2SH_READY_TIMEOUT_NS 1000000000ULL
#define L2SH_IDLE_TIMEOUT_DEFAULT 30
#define L2SH_HANDSHAKE_ATTEMPTS 5
#define L2SH_ARQ_RETRY_NS 100000000ULL
#define L2SH_ARQ_MAX_RETRIES 20
#define NSEC_PER_MSEC 1000000ULL
#define NSEC_PER_SEC 1000000000ULL
#define L2SH_WAIT_SLICE_NS NSEC_PER_SEC

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif

struct l2sh_args {
  const char *iface;
  const char *mac_str;
  const char *spawn_cmd;
  const char *shell;
  const char *cmd;
  s32 local_echo;
  s32 idle_timeout;
  s32 list_ifaces;
};

struct l2sh_ctx {
  pcap_t *pcap;
  HANDLE pcap_event;
  HANDLE stdin_handle;
  HANDLE stdout_handle;
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
  s32 stdin_waitable;
  s32 stdin_is_console;
  s32 stdin_is_file;
};

struct l2sh_ready_msg {
  u64 nonce;
  u32 proto_version;
  s32 have_nonce;
  s32 have_proto_version;
  s32 from_userland;
  s32 from_kernel;
};

static HANDLE saved_stdin_handle;
static DWORD saved_stdin_mode;
static s32 stdin_raw_mode_enabled;
static HANDLE saved_stdout_handle;
static DWORD saved_stdout_mode;
static s32 stdout_vt_mode_enabled;

static void l2sh_err(const char *fmt, ...)
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

static void l2sh_winerr(const char *what, DWORD err) {
  char *msg;
  DWORD flags;
  size_t len;

  msg = NULL;
  flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
  if (!FormatMessageA(flags, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL) || !msg) {
    l2sh_err("%s: win32 error %lu", what, (unsigned long)err);
    return;
  }

  len = strlen(msg);
  while (len && (msg[len - 1] == '\r' || msg[len - 1] == '\n'))
    msg[--len] = '\0';

  l2sh_err("%s: %s", what, msg);
  LocalFree(msg);
}

static void usage(const char *prog) {
  fprintf(stderr,
          "usage: %s [--list-ifaces] [-e|--echo] [--spawn <cmd>] "
          "[--shell <path>] [--idle-timeout <sec>] <iface> <server-mac> [cmd]\n",
          prog);
}

static void l2sh_restore_stdin(void) {
  if (!stdin_raw_mode_enabled)
    return;

  SetConsoleMode(saved_stdin_handle, saved_stdin_mode);
  stdin_raw_mode_enabled = 0;
}

static void l2sh_restore_stdout(void) {
  if (!stdout_vt_mode_enabled)
    return;

  SetConsoleMode(saved_stdout_handle, saved_stdout_mode);
  stdout_vt_mode_enabled = 0;
}

static s32 l2sh_enable_raw_mode(HANDLE stdin_handle) {
  DWORD mode;

  if (!stdin_handle || stdin_handle == INVALID_HANDLE_VALUE)
    return 0;
  if (!GetConsoleMode(stdin_handle, &saved_stdin_mode))
    return 0;

  mode = saved_stdin_mode;
  mode &= ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
                   ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT);
  mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
  if (!SetConsoleMode(stdin_handle, mode)) {
    l2sh_winerr("SetConsoleMode(stdin)", GetLastError());
    return -1;
  }

  saved_stdin_handle = stdin_handle;
  stdin_raw_mode_enabled = 1;
  if (atexit(l2sh_restore_stdin) != 0)
    l2sh_restore_stdin();

  return 0;
}

static void l2sh_enable_stdout_vt(HANDLE stdout_handle) {
  DWORD mode;

  if (!stdout_handle || stdout_handle == INVALID_HANDLE_VALUE)
    return;
  if (!GetConsoleMode(stdout_handle, &saved_stdout_mode))
    return;

  mode = saved_stdout_mode;
  mode |= ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  if (!SetConsoleMode(stdout_handle, mode))
    return;

  saved_stdout_handle = stdout_handle;
  stdout_vt_mode_enabled = 1;
  if (atexit(l2sh_restore_stdout) != 0)
    l2sh_restore_stdout();
}

static u64 l2sh_mono_ns(void) {
  static LARGE_INTEGER freq;
  LARGE_INTEGER now;

  if (!freq.QuadPart)
    QueryPerformanceFrequency(&freq);

  QueryPerformanceCounter(&now);
  return (u64)((now.QuadPart * (LONGLONG)NSEC_PER_SEC) / freq.QuadPart);
}

static u64 l2sh_nonce_seed(void) {
  FILETIME ft;
  ULARGE_INTEGER u;

  GetSystemTimeAsFileTime(&ft);
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  return u.QuadPart ^ (u64)GetCurrentProcessId();
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

static const char *l2sh_fmt_mac(const u8 *mac, char *buf, size_t len) {
  if (!buf || !len)
    return "";
  if (!mac) {
    buf[0] = '\0';
    return buf;
  }

  snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return buf;
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

static s32 l2sh_copy_string(char *dst, size_t dst_len, const char *src) {
  size_t len;

  if (!dst || !dst_len || !src)
    return -1;

  len = strlen(src);
  if (len + 1 > dst_len)
    return -1;

  memcpy(dst, src, len + 1);
  return 0;
}

static s32 l2sh_trim_guid(char *dst, size_t dst_len, const char *src) {
  size_t off;

  if (!dst || !dst_len || !src)
    return -1;

  off = 0;
  while (*src) {
    if (*src != '{' && *src != '}') {
      if (off + 1 >= dst_len)
        return -1;
      dst[off++] = *src;
    }
    src++;
  }
  if (!off)
    return -1;

  dst[off] = '\0';
  return 0;
}

static s32 l2sh_guid_equal(const char *a, const char *b) {
  char guid_a[64];
  char guid_b[64];

  if (l2sh_trim_guid(guid_a, sizeof(guid_a), a) < 0)
    return 0;
  if (l2sh_trim_guid(guid_b, sizeof(guid_b), b) < 0)
    return 0;

  return _stricmp(guid_a, guid_b) == 0;
}

static s32 l2sh_extract_guid(const char *name, char *guid, size_t guid_len) {
  const char *start;
  const char *end;
  size_t len;

  if (!name || !guid || !guid_len)
    return -1;

  start = strrchr(name, '{');
  end = strrchr(name, '}');
  if (!start || !end || end < start)
    return -1;

  len = (size_t)(end - start + 1);
  if (len + 1 > guid_len)
    return -1;

  memcpy(guid, start, len);
  guid[len] = '\0';
  return 0;
}

static s32 l2sh_get_guid_mac(const char *guid, u8 mac[ETH_ALEN]) {
  IP_ADAPTER_ADDRESSES *head;
  IP_ADAPTER_ADDRESSES *addr;
  ULONG flags;
  ULONG size;
  DWORD ret;

  if (!guid || !mac)
    return -1;

  head = NULL;
  flags = GAA_FLAG_INCLUDE_ALL_INTERFACES;
  size = 16 * 1024;
  for (;;) {
    head = malloc(size);
    if (!head) {
      l2sh_err("malloc failed");
      return -1;
    }

    ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, head, &size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
      free(head);
      head = NULL;
      continue;
    }
    if (ret != NO_ERROR) {
      l2sh_winerr("GetAdaptersAddresses", ret);
      free(head);
      return -1;
    }
    break;
  }

  ret = ERROR_NOT_FOUND;
  for (addr = head; addr; addr = addr->Next) {
    if (!addr->AdapterName)
      continue;
    if (!l2sh_guid_equal(addr->AdapterName, guid))
      continue;
    if (addr->PhysicalAddressLength != ETH_ALEN)
      continue;

    memcpy(mac, addr->PhysicalAddress, ETH_ALEN);
    ret = NO_ERROR;
    break;
  }

  free(head);
  if (ret != NO_ERROR) {
    l2sh_err("failed to get mac address for adapter %s", guid);
    return -1;
  }

  return 0;
}

static s32 l2sh_iface_matches(const pcap_if_t *dev, const char *iface) {
  char guid[64];

  if (!dev || !iface)
    return 0;
  if (dev->name && _stricmp(dev->name, iface) == 0)
    return 1;
  if (dev->description && _stricmp(dev->description, iface) == 0)
    return 1;
  if (dev->name && l2sh_extract_guid(dev->name, guid, sizeof(guid)) == 0 && l2sh_guid_equal(guid, iface))
    return 1;

  return 0;
}

static s32 l2sh_list_ifaces(void) {
  pcap_if_t *all_devs;
  pcap_if_t *dev;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&all_devs, errbuf) < 0) {
    l2sh_err("pcap_findalldevs: %s", errbuf);
    return -1;
  }

  for (dev = all_devs; dev; dev = dev->next) {
    printf("%s", dev->name ? dev->name : "<unnamed>");
    if (dev->description && dev->description[0])
      printf("  %s", dev->description);
    putchar('\n');
  }

  pcap_freealldevs(all_devs);
  return 0;
}

static s32 l2sh_resolve_iface(const char *iface, char *pcap_name, size_t pcap_name_len, u8 mac[ETH_ALEN]) {
  pcap_if_t *all_devs;
  pcap_if_t *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  char guid[64];
  s32 ret;
  s32 matched;

  if (!iface || !pcap_name || !pcap_name_len || !mac)
    return -1;

  if (pcap_findalldevs(&all_devs, errbuf) < 0) {
    l2sh_err("pcap_findalldevs: %s", errbuf);
    return -1;
  }

  ret = -1;
  matched = 0;
  for (dev = all_devs; dev; dev = dev->next) {
    if (!l2sh_iface_matches(dev, iface))
      continue;

    matched = 1;
    if (!dev->name || l2sh_copy_string(pcap_name, pcap_name_len, dev->name) < 0) {
      l2sh_err("interface name is too long");
      break;
    }
    if (l2sh_extract_guid(dev->name, guid, sizeof(guid)) < 0) {
      l2sh_err("cannot parse adapter guid from %s", dev->name);
      break;
    }
    if (l2sh_get_guid_mac(guid, mac) < 0)
      break;

    ret = 0;
    break;
  }

  pcap_freealldevs(all_devs);
  if (ret < 0 && !matched)
    l2sh_err("interface not found: %s", iface);

  return ret;
}

static void l2sh_close_socket(struct l2sh_ctx *ctx) {
  if (!ctx || !ctx->pcap)
    return;

  pcap_close(ctx->pcap);
  ctx->pcap = NULL;
  ctx->pcap_event = NULL;
}

static s32 l2sh_init_stdio(struct l2sh_ctx *ctx) {
  DWORD mode;
  DWORD file_type;

  if (!ctx)
    return -1;

  ctx->stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
  if (!ctx->stdin_handle || ctx->stdin_handle == INVALID_HANDLE_VALUE) {
    l2sh_winerr("GetStdHandle(stdin)", GetLastError());
    return -1;
  }

  ctx->stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
  if (!ctx->stdout_handle || ctx->stdout_handle == INVALID_HANDLE_VALUE) {
    l2sh_winerr("GetStdHandle(stdout)", GetLastError());
    return -1;
  }
  l2sh_enable_stdout_vt(ctx->stdout_handle);

  file_type = GetFileType(ctx->stdin_handle);
  if (file_type == FILE_TYPE_CHAR) {
    if (GetConsoleMode(ctx->stdin_handle, &mode)) {
      ctx->stdin_waitable = 1;
      ctx->stdin_is_console = 1;
    }
  } else if (file_type == FILE_TYPE_PIPE) {
    ctx->stdin_waitable = 1;
  } else if (file_type == FILE_TYPE_DISK) {
    ctx->stdin_is_file = 1;
  }

  return 0;
}

/*
 * Console handles wake up on window, focus and mouse events too.
 * Drop those here so the main loop does not block in ReadFile() and
 * miss heartbeat deadlines while the session is idle.
 */
static s32 l2sh_console_stdin_ready(struct l2sh_ctx *ctx) {
  INPUT_RECORD rec;
  DWORD got;

  if (!ctx || !ctx->stdin_is_console)
    return 1;

  for (;;) {
    got = 0;
    if (!PeekConsoleInput(ctx->stdin_handle, &rec, 1, &got)) {
      l2sh_winerr("PeekConsoleInput", GetLastError());
      return -1;
    }
    if (!got)
      return 0;
    if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown)
      return 1;
    if (!ReadConsoleInput(ctx->stdin_handle, &rec, 1, &got)) {
      l2sh_winerr("ReadConsoleInput", GetLastError());
      return -1;
    }
  }
}

static s32 l2sh_install_pcap_filter(struct l2sh_ctx *ctx) {
  struct bpf_program prog;
  char filter[128];
  char src_mac[18];
  char dst_mac[18];

  if (!ctx || !ctx->pcap)
    return -1;

  snprintf(filter, sizeof(filter), "ether proto 0x%04x and ether src %s and ether dst %s", L2SH_ETHERTYPE,
           l2sh_fmt_mac(ctx->peer_mac, src_mac, sizeof(src_mac)), l2sh_fmt_mac(ctx->local_mac, dst_mac, sizeof(dst_mac)));

  if (pcap_compile(ctx->pcap, &prog, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
    l2sh_err("pcap_compile: %s", pcap_geterr(ctx->pcap));
    return -1;
  }
  if (pcap_setfilter(ctx->pcap, &prog) < 0) {
    l2sh_err("pcap_setfilter: %s", pcap_geterr(ctx->pcap));
    pcap_freecode(&prog);
    return -1;
  }

  pcap_freecode(&prog);
  return 0;
}

static s32 l2sh_open_socket(struct l2sh_ctx *ctx, const char *iface) {
  char pcap_name[512];
  char errbuf[PCAP_ERRBUF_SIZE];
  s32 ret;
  s32 dlt;

  if (!ctx || !iface || !iface[0])
    return -1;

  if (l2sh_resolve_iface(iface, pcap_name, sizeof(pcap_name), ctx->local_mac) < 0)
    return -1;

  ctx->pcap = pcap_create(pcap_name, errbuf);
  if (!ctx->pcap) {
    l2sh_err("pcap_create: %s", errbuf);
    return -1;
  }

  if (pcap_set_snaplen(ctx->pcap, (int)sizeof(l2s_frame_t)) < 0) {
    l2sh_err("pcap_set_snaplen: %s", pcap_geterr(ctx->pcap));
    l2sh_close_socket(ctx);
    return -1;
  }
  if (pcap_set_promisc(ctx->pcap, 0) < 0) {
    l2sh_err("pcap_set_promisc: %s", pcap_geterr(ctx->pcap));
    l2sh_close_socket(ctx);
    return -1;
  }
  if (pcap_set_timeout(ctx->pcap, 1) < 0) {
    l2sh_err("pcap_set_timeout: %s", pcap_geterr(ctx->pcap));
    l2sh_close_socket(ctx);
    return -1;
  }
  if (pcap_set_immediate_mode(ctx->pcap, 1) < 0) {
    l2sh_err("pcap_set_immediate_mode: %s", pcap_geterr(ctx->pcap));
    l2sh_close_socket(ctx);
    return -1;
  }

  ret = pcap_activate(ctx->pcap);
  if (ret < 0) {
    l2sh_err("pcap_activate: %s", pcap_geterr(ctx->pcap));
    l2sh_close_socket(ctx);
    return -1;
  }
  if (ret > 0)
    l2sh_err("pcap_activate warning: %s", pcap_statustostr(ret));

  dlt = pcap_datalink(ctx->pcap);
  if (dlt != DLT_EN10MB) {
    l2sh_err("interface %s is not ethernet (dlt=%d)", iface, dlt);
    l2sh_close_socket(ctx);
    return -1;
  }

  if (l2sh_install_pcap_filter(ctx) < 0) {
    l2sh_close_socket(ctx);
    return -1;
  }

  if (pcap_setnonblock(ctx->pcap, 1, errbuf) < 0) {
    l2sh_err("pcap_setnonblock: %s", errbuf);
    l2sh_close_socket(ctx);
    return -1;
  }

  ctx->pcap_event = pcap_getevent(ctx->pcap);
  if (!ctx->pcap_event) {
    l2sh_err("pcap_getevent failed");
    l2sh_close_socket(ctx);
    return -1;
  }

  return l2sh_init_stdio(ctx);
}

static s32 l2sh_send_payload(struct l2sh_ctx *ctx, const void *payload, size_t payload_len) {
  l2s_frame_meta_t meta;
  l2s_frame_t frame;
  s32 frame_len;

  if (!ctx || !ctx->pcap)
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

  if (pcap_sendpacket(ctx->pcap, (const u_char *)&frame, frame_len) != 0) {
    l2sh_err("pcap_sendpacket: %s", pcap_geterr(ctx->pcap));
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

static s32 l2sh_recv_frame(struct l2sh_ctx *ctx, l2s_frame_t *frame, u8 **payload_out, size_t *payload_len_out) {
  struct pcap_pkthdr *hdr;
  const u_char *pkt;
  size_t pkt_len;
  s32 ret;

  if (!ctx || !ctx->pcap || !frame)
    return -1;

  for (;;) {
    ret = pcap_next_ex(ctx->pcap, &hdr, &pkt);
    if (ret == 0 || ret == PCAP_ERROR_BREAK)
      return 0;
    if (ret < 0) {
      l2sh_err("pcap_next_ex: %s", pcap_geterr(ctx->pcap));
      return -1;
    }

    pkt_len = hdr->caplen;
    if (pkt_len < sizeof(l2s_frame_header_t) || pkt_len > sizeof(*frame))
      continue;

    memcpy(frame, pkt, pkt_len);
    if (memcmp(frame->header.eth_hdr.ether_shost, ctx->peer_mac, ETH_ALEN) != 0)
      continue;
    if (memcmp(frame->header.eth_hdr.ether_dhost, ctx->local_mac, ETH_ALEN) != 0)
      continue;
    if (l2s_parse_frame(frame, pkt_len, L2SH_SERVER_SIGNATURE, payload_len_out) != L2S_FRAME_OK)
      continue;

    if (payload_out)
      *payload_out = frame->payload;
    return 1;
  }
}

static DWORD l2sh_wait_ms(u64 wait_ns) {
  u64 wait_ms;

  wait_ms = wait_ns / NSEC_PER_MSEC;
  if (!wait_ms)
    wait_ms = 1;
  if (wait_ms > 0xffffffffULL)
    wait_ms = 0xffffffffULL;

  return (DWORD)wait_ms;
}

static s32 l2sh_wait_socket_ready(struct l2sh_ctx *ctx, u64 deadline_ns) {
  DWORD wait_ret;
  u64 now;
  u64 rem;

  if (!ctx || !ctx->pcap_event)
    return -1;

  for (;;) {
    now = l2sh_mono_ns();
    if (now >= deadline_ns)
      return 0;

    rem = deadline_ns - now;
    wait_ret = WaitForSingleObject(ctx->pcap_event, l2sh_wait_ms(rem));
    if (wait_ret == WAIT_OBJECT_0)
      return 1;
    if (wait_ret == WAIT_TIMEOUT)
      continue;

    l2sh_winerr("WaitForSingleObject(pcap)", GetLastError());
    return -1;
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

    if (!l2sh_parse_ready_message(payload, payload_len, &ready_msg))
      continue;
    if (ready_msg.from_kernel && (!ready_msg.have_nonce || ready_msg.nonce == expected_nonce))
      return 2;
    if (ready_msg.have_nonce && ready_msg.nonce == expected_nonce) {
      if (ready_msg.from_userland || (!ready_msg.from_userland && !ready_msg.from_kernel)) {
        if (ready_out)
          *ready_out = ready_msg;
        return 0;
      }
    }
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

static s32 l2sh_write_all(HANDLE handle, const void *buf, size_t count) {
  const u8 *ptr;
  size_t left;
  DWORD written;

  if (!handle || handle == INVALID_HANDLE_VALUE || (!buf && count))
    return -1;

  ptr = buf;
  left = count;
  while (left) {
    if (!WriteFile(handle, ptr, (DWORD)left, &written, NULL)) {
      l2sh_winerr("WriteFile", GetLastError());
      return -1;
    }
    if (!written)
      break;

    ptr += written;
    left -= written;
  }

  return left ? -1 : 0;
}

static s32 l2sh_handle_session_payload(struct l2sh_ctx *ctx, const u8 *payload, size_t payload_len, s32 *delivered) {
  l2s_arq_view_t arq;
  struct l2sh_ready_msg ready_msg;
  s32 ret;

  if (!ctx || !payload)
    return -1;
  if (delivered)
    *delivered = 0;

  if (l2sh_parse_ready_message(payload, payload_len, &ready_msg))
    return 0;

  if (!ctx->arq_enabled) {
    if (payload_len && l2sh_write_all(ctx->stdout_handle, payload, payload_len) < 0)
      return -1;
    if (payload_len && delivered)
      *delivered = 1;
    return 0;
  }

  ret = l2s_arq_parse(payload, payload_len, &arq);
  if (ret < 0)
    return 0;
  if (!ret) {
    if (payload_len && l2sh_write_all(ctx->stdout_handle, payload, payload_len) < 0)
      return -1;
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

  if (arq.data_len && l2sh_write_all(ctx->stdout_handle, arq.data, arq.data_len) < 0)
    return -1;
  if (arq.data_len && delivered)
    *delivered = 1;
  ctx->rx_expect_seq ^= 1U;
  return 0;
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
  return delivered > 0 ? 1 : 2;
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
    if (ret == 1) {
      seen = 1;
      deadline = l2sh_mono_ns() + L2SH_READY_TIMEOUT_NS;
    }
  }
}

static s32 l2sh_handle_stdin(struct l2sh_ctx *ctx, s32 local_echo) {
  u8 buf[L2SH_ARQ_MAX_DATA];
  DWORD got;

  if (!ctx || !ctx->stdin_handle || ctx->stdin_handle == INVALID_HANDLE_VALUE)
    return -1;

  if (!ReadFile(ctx->stdin_handle, buf, sizeof(buf), &got, NULL)) {
    l2sh_winerr("ReadFile", GetLastError());
    return -1;
  }
  if (!got)
    return 2;

  l2sh_norm_stdin(buf, got);
  if (local_echo && l2sh_write_all(ctx->stdout_handle, buf, got) < 0)
    return -1;
  if (l2sh_send_payload_r(ctx, buf, got) < 0)
    return -1;

  return 1;
}

static s32 l2sh_drain_stdout(struct l2sh_ctx *ctx) {
  s32 ret;

  for (;;) {
    ret = l2sh_recv_stdout(ctx);
    if (ret <= 0)
      return ret < 0 ? -1 : 0;
  }
}

static s32 l2sh_loop(struct l2sh_ctx *ctx, s32 local_echo) {
  HANDLE handles[2];
  DWORD wait_ret;
  DWORD wait_ms;
  u64 now;
  u64 wait_ns;
  s32 ret;
  s32 count;

  if (!ctx || !ctx->pcap_event)
    return -1;

  if (ctx->heartbeat_interval_ns > 0 && !ctx->next_heartbeat_ns)
    ctx->next_heartbeat_ns = l2sh_mono_ns() + ctx->heartbeat_interval_ns;

  for (;;) {
    now = l2sh_mono_ns();
    ret = l2sh_retransmit_if_needed(ctx);
    if (ret < 0)
      return -1;
    if (ctx->heartbeat_interval_ns > 0 && ctx->next_heartbeat_ns <= now) {
      if (l2sh_send_heartbeat(ctx) < 0)
        return -1;
      ctx->next_heartbeat_ns = now + ctx->heartbeat_interval_ns;
      now = l2sh_mono_ns();
    }

    if (ctx->stdin_is_file && !ctx->tx_waiting) {
      ret = l2sh_handle_stdin(ctx, local_echo);
      if (ret < 0)
        return -1;
      if (ret == 2)
        return 0;
      if (ret > 0 && ctx->heartbeat_interval_ns > 0)
        ctx->next_heartbeat_ns = l2sh_mono_ns() + ctx->heartbeat_interval_ns;
    }

    wait_ns = L2SH_WAIT_SLICE_NS;
    if (ctx->heartbeat_interval_ns > 0) {
      if (ctx->next_heartbeat_ns > now)
        wait_ns = ctx->next_heartbeat_ns - now;
      else
        wait_ns = 1;
    }
    if (ctx->tx_waiting && ctx->tx_deadline_ns > now && ctx->tx_deadline_ns - now < wait_ns)
      wait_ns = ctx->tx_deadline_ns - now;
    if (wait_ns > L2SH_WAIT_SLICE_NS)
      wait_ns = L2SH_WAIT_SLICE_NS;
    wait_ms = l2sh_wait_ms(wait_ns);

    count = 0;
    handles[count++] = ctx->pcap_event;
    if (ctx->stdin_waitable && !ctx->stdin_is_file && !ctx->tx_waiting)
      handles[count++] = ctx->stdin_handle;

    wait_ret = WaitForMultipleObjects((DWORD)count, handles, FALSE, wait_ms);
    if (wait_ret == WAIT_TIMEOUT)
      continue;
    if (wait_ret == WAIT_FAILED) {
      l2sh_winerr("WaitForMultipleObjects", GetLastError());
      return -1;
    }

    if (wait_ret == WAIT_OBJECT_0) {
      if (l2sh_drain_stdout(ctx) < 0)
        return -1;
      continue;
    }
    if (count > 1 && wait_ret == WAIT_OBJECT_0 + 1) {
      ret = l2sh_console_stdin_ready(ctx);
      if (ret < 0)
        return -1;
      if (!ret)
        continue;
      ret = l2sh_handle_stdin(ctx, local_echo);
      if (ret < 0)
        return -1;
      if (ret == 2)
        return 0;
      if (ret > 0 && ctx->heartbeat_interval_ns > 0)
        ctx->next_heartbeat_ns = l2sh_mono_ns() + ctx->heartbeat_interval_ns;
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
    if (!strcmp(argv[i], "--list-ifaces")) {
      args->list_ifaces = 1;
      continue;
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

  if (args->list_ifaces)
    return 0;
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

  if (args.list_ifaces)
    return l2sh_list_ifaces() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

  memset(&ctx, 0, sizeof(ctx));
  l2sh_set_peer_proto(&ctx, L2SH_PROTO_V1);
  if (l2sh_parse_mac(args.mac_str, ctx.peer_mac) < 0) {
    l2sh_err("invalid mac address: %s", args.mac_str);
    return EXIT_FAILURE;
  }
  ctx.heartbeat_interval_ns = l2sh_calc_heartbeat_interval_ns(args.idle_timeout);

  if (l2sh_open_socket(&ctx, args.iface) < 0)
    return EXIT_FAILURE;

  interactive = args.cmd == NULL;
  if (interactive && l2sh_enable_raw_mode(ctx.stdin_handle) < 0) {
    l2sh_close_socket(&ctx);
    return EXIT_FAILURE;
  }

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
    if (l2sh_write_all(ctx.stdout_handle, cmd_buf, cmd_len) < 0 || l2sh_write_all(ctx.stdout_handle, "\n", 1) < 0) {
      l2sh_close_socket(&ctx);
      return EXIT_FAILURE;
    }
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
