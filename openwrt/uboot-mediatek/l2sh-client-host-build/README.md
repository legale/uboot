# L2SH Host Build

This directory builds standalone host clients for the synced `l2shell`
protocol used by this tree.

## Source Of Truth

- Protocol helpers: `src/include/l2sh_proto.h`
- U-Boot side: `src/net/l2sh.c`
- Linux host client: `src/tools/l2sh/l2sh_client.c` and `src/tools/l2sh/common.c`
- macOS host client: `l2sh-client-host-build/l2sh_client_macos.c`
- Windows host client: `l2sh-client-host-build/l2sh_client_windows.c`

The wire format, hello TLVs, frame helpers, and ARQ helpers are defined in
`src/include/l2sh_proto.h`.

## Build

Start in this directory:

```sh
cd l2sh-client-host-build
make clean
```

### Linux

Default Linux build uses `musl-gcc` and produces a static `l2sh` binary.

```sh
make
```

If `musl-gcc` is not available and a dynamic glibc binary is acceptable:

```sh
make CC=cc LDFLAGS=
```

The Linux client uses raw Ethernet sockets and usually needs root or
equivalent raw-socket capability at runtime.

### macOS

Build on macOS with `clang`:

```sh
make CC=clang
```

The macOS client uses `/dev/bpf*` and also needs elevated privileges at
runtime.

### Windows

Cross-build from Linux with MinGW and the Npcap SDK unpacked in
`./npcap-sdk`:

```sh
make windows
```

Override paths if needed:

```sh
make windows \
  WIN_CC=x86_64-w64-mingw32-gcc \
  WIN_PCAP_INC=/path/to/Include \
  WIN_PCAP_LIB=/path/to/Lib/x64
```

The Windows client needs Npcap installed on the target machine.
