# =============================================================================
# hajimu_web — はじむ用 HTTP ウェブサーバープラグイン
# クロスプラットフォーム Makefile (macOS / Linux / Windows MinGW)
# =============================================================================

PLUGIN_NAME = hajimu_web
SRC         = src/hajimu_web.c
OUT         = $(PLUGIN_NAME).hjp

# vendored zlib (クロスコンパイル時に使用)
ZLIB_SRC = vendor/zlib/adler32.c vendor/zlib/compress.c \
           vendor/zlib/crc32.c vendor/zlib/deflate.c \
           vendor/zlib/infback.c vendor/zlib/inffast.c \
           vendor/zlib/inflate.c vendor/zlib/inftrees.c \
           vendor/zlib/trees.c vendor/zlib/uncompr.c \
           vendor/zlib/zutil.c

# クロスコンパイラ
LINUX_CC  ?= x86_64-linux-musl-gcc
WIN_CC    ?= x86_64-w64-mingw32-gcc

DIST = dist
# CC ?= gcc だと GNU make 組み込みデフォルト(cc)が優先されるため = で上書き
# コマンドラインから make CC=clang のように引き続きオーバーライド可能
CC         = gcc

# OS 判定 ($(OS) は Windows CMD/PowerShell で "Windows_NT" になる)
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    INSTALL_DIR := $(USERPROFILE)/.hajimu/plugins
else
    DETECTED_OS := $(shell uname -s 2>/dev/null || echo Unknown)
    INSTALL_DIR := $(HOME)/.hajimu/plugins
endif

# はじむインクルードパス自動検出
ifeq ($(OS),Windows_NT)
    ifndef HAJIMU_INCLUDE
        HAJIMU_INCLUDE := $(or \
            $(if $(wildcard ../../jp/include/hajimu.h),../../jp/include),\
            $(if $(wildcard ../jp/include/hajimu.h),../jp/include),\
            ./include)
    endif
else
    ifndef HAJIMU_INCLUDE
        HAJIMU_INCLUDE := $(shell \
            if [ -d "../../jp/include" ]; then echo "../../jp/include"; \
            elif [ -d "../jp/include" ]; then echo "../jp/include"; \
            elif [ -d "/usr/local/include/hajimu" ]; then echo "/usr/local/include/hajimu"; \
            else echo "include"; fi)
    endif
endif

# コンパイル / リンクフラグ
ifeq ($(OS),Windows_NT)
    CFLAGS  = -Wall -Wextra -O2 -std=gnu11 -D_WIN32_WINNT=0x0601 -DWIN32_LEAN_AND_MEAN
    CFLAGS += -I$(HAJIMU_INCLUDE)
    CFLAGS += -shared
    LDFLAGS = -lws2_32 -lwinmm -lz -static-libgcc
else ifeq ($(DETECTED_OS),Darwin)
    CFLAGS  = -Wall -Wextra -O2 -std=gnu11 -fPIC -I$(HAJIMU_INCLUDE)
    CFLAGS += -shared -dynamiclib
    LDFLAGS = -lz -lpthread
else
    CFLAGS  = -Wall -Wextra -O2 -std=gnu11 -fPIC -I$(HAJIMU_INCLUDE)
    CFLAGS += -shared
    LDFLAGS = -lz -lpthread
endif

.PHONY: all clean install uninstall help build-all build-linux build-windows

all: $(OUT)
	@echo "  ビルド完了: $(OUT)"

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# =============================================================================
# クロスコンパイル (macOS ホストから全プラットフォーム向け .hjp を生成)
# =============================================================================
# 成果物は dist/ に配置:
#   dist/hajimu_web-macos.hjp
#   dist/hajimu_web-linux-x64.hjp
#   dist/hajimu_web-windows-x64.hjp

build-all: $(DIST)/$(PLUGIN_NAME)-macos.hjp \
           $(DIST)/$(PLUGIN_NAME)-linux-x64.hjp \
           $(DIST)/$(PLUGIN_NAME)-windows-x64.hjp
	@echo ""
	@echo "=== 全プラットフォームビルド完了 ==="
	@ls -lh $(DIST)/$(PLUGIN_NAME)-*.hjp

$(DIST):
	mkdir -p $(DIST)

# macOS (ネイティブ)
$(DIST)/$(PLUGIN_NAME)-macos.hjp: $(SRC) | $(DIST)
	$(CC) -shared -dynamiclib -fPIC -O2 -std=gnu11 \
	  -D_DARWIN_C_SOURCE \
	  -I$(HAJIMU_INCLUDE) \
	  $< -o $@ \
	  -lz -lpthread
	@echo "  → $@"

# Linux x86_64 (musl 静的リンク)
# zlib は vendor/zlib/ をソースから組み込む (musl sysroot に zlib がないため)
$(DIST)/$(PLUGIN_NAME)-linux-x64.hjp: $(SRC) $(ZLIB_SRC) | $(DIST)
	$(LINUX_CC) -shared -fPIC -O2 -std=gnu11 \
	  -D_GNU_SOURCE \
	  -I$(HAJIMU_INCLUDE) -Ivendor/zlib \
	  $< $(ZLIB_SRC) -o $@ \
	  -lpthread -lm
	@echo "  → $@"

# Windows x86_64 (mingw-w64)
# zlib は vendor/zlib/ をソースから組み込む
$(DIST)/$(PLUGIN_NAME)-windows-x64.hjp: $(SRC) $(ZLIB_SRC) | $(DIST)
	$(WIN_CC) -shared -O2 -std=gnu11 \
	  -D_WIN32_WINNT=0x0601 -DWIN32_LEAN_AND_MEAN \
	  -I$(HAJIMU_INCLUDE) -Ivendor/zlib \
	  $< $(ZLIB_SRC) -o $@ \
	  -lws2_32 -lwinmm -lpthread -static-libgcc
	@echo "  → $@"

build-linux: $(DIST)/$(PLUGIN_NAME)-linux-x64.hjp
build-windows: $(DIST)/$(PLUGIN_NAME)-windows-x64.hjp

clean:
ifeq ($(OS),Windows_NT)
	-del /F /Q $(OUT) 2>NUL
else
	rm -f $(OUT)
endif
	@echo "  クリーン完了"

install: $(OUT)
ifeq ($(OS),Windows_NT)
	if not exist "$(INSTALL_DIR)\$(PLUGIN_NAME)" mkdir "$(INSTALL_DIR)\$(PLUGIN_NAME)"
	copy /Y $(OUT) "$(INSTALL_DIR)\$(PLUGIN_NAME)"
	copy /Y hajimu.json "$(INSTALL_DIR)\$(PLUGIN_NAME)"
else
	@mkdir -p $(INSTALL_DIR)/$(PLUGIN_NAME)
	cp $(OUT) $(INSTALL_DIR)/$(PLUGIN_NAME)/
	cp hajimu.json $(INSTALL_DIR)/$(PLUGIN_NAME)/
endif
	@echo "  インストール完了: $(INSTALL_DIR)/$(PLUGIN_NAME)/"

uninstall:
ifeq ($(OS),Windows_NT)
	-rmdir /S /Q "$(INSTALL_DIR)\$(PLUGIN_NAME)" 2>NUL
else
	rm -rf $(INSTALL_DIR)/$(PLUGIN_NAME)
endif
	@echo "  アンインストール完了"

help:
	@echo "  hajimu_web — はじむ用 HTTP ウェブサーバープラグイン"
	@echo "  macOS:   (OpenSSL/curl は標準で利用可能)"
	@echo "  Linux:   sudo apt install zlib1g-dev"
	@echo "  Windows: MSYS2 MinGW64 ターミナルで実行してください"
	@echo "    pacman -S mingw-w64-x86_64-gcc"
	@echo ""
