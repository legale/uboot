UNAME_S := $(shell uname -s)
Q ?= @
NPCAP_DIR ?= $(CURDIR)/npcap-sdk
WIN_PCAP_INC ?= $(NPCAP_DIR)/Include
WIN_PCAP_LIB ?= $(NPCAP_DIR)/Lib/x64
WIN_CC ?= x86_64-w64-mingw32-gcc
WIN_BIN ?= l2sh.exe
WIN_SRC := l2sh_client_windows.c
WIN_OPT_CFLAGS := -Os -ffunction-sections -fdata-sections -fomit-frame-pointer
WIN_WARN_CFLAGS := -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wundef \
	-Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
	-Wcast-qual -Wwrite-strings -Wconversion -Wsign-conversion -Werror
WIN_CFLAGS ?= $(WIN_OPT_CFLAGS) $(WIN_WARN_CFLAGS)
WIN_CPPFLAGS += -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600 \
	-I$(WIN_PCAP_INC) -iquote ../src/include
WIN_LDFLAGS += -L$(WIN_PCAP_LIB) -Wl,--gc-sections -s \
	$(WIN_PCAP_LIB)/wpcap.lib $(WIN_PCAP_LIB)/Packet.lib \
	-liphlpapi -lws2_32

ifeq ($(UNAME_S),Darwin)
CC ?= clang
BIN := l2sh
SRC := l2sh_client_macos.c
OPT_CFLAGS := -O2
WARN_CFLAGS := -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wundef \
	-Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
	-Wcast-qual -Wwrite-strings -Werror
CFLAGS ?= $(OPT_CFLAGS) $(WARN_CFLAGS)
CPPFLAGS += -iquote ../src/include
LDFLAGS +=
else
CC ?= musl-gcc
BIN := l2sh
SRC := ../src/tools/l2sh/l2sh_client.c \
	../src/tools/l2sh/common.c
OPT_CFLAGS := -Os -flto -ffunction-sections -fdata-sections -fomit-frame-pointer
WARN_CFLAGS := -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wundef \
	-Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes \
	-Wcast-qual -Wwrite-strings -Wconversion -Wsign-conversion -Werror
CFLAGS ?= $(OPT_CFLAGS) $(WARN_CFLAGS)
CPPFLAGS += -iquote ../src/include
LDFLAGS += -static -flto -Wl,--gc-sections -s
endif

.PHONY: all static windows clean

all: static

static: $(BIN)

$(BIN): $(SRC)
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) $(LDFLAGS) -o $@

windows: $(WIN_BIN)

$(WIN_BIN): $(WIN_SRC)
	$(Q)$(WIN_CC) $(WIN_CPPFLAGS) $(WIN_CFLAGS) $(WIN_SRC) $(WIN_LDFLAGS) -o $@

clean:
	$(Q)rm -f $(BIN) $(WIN_BIN)
