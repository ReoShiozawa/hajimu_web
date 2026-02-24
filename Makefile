# =============================================================================
# hajimu_web — はじむ用 HTTP ウェブサーバープラグイン
# クロスプラットフォーム Makefile (macOS / Linux / Windows MinGW)
# =============================================================================

PLUGIN_NAME = hajimu_web
SRC         = src/hajimu_web.c
OUT         = $(PLUGIN_NAME).hjp
CC         ?= gcc

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
    CFLAGS  = -Wall -Wextra -O2 -std=c11 -D_WIN32_WINNT=0x0601 -DWIN32_LEAN_AND_MEAN
    CFLAGS += -I$(HAJIMU_INCLUDE)
    CFLAGS += -shared
    LDFLAGS = -lws2_32 -lwinmm -static-libgcc
else ifeq ($(DETECTED_OS),Darwin)
    CFLAGS  = -Wall -Wextra -O2 -std=c11 -fPIC -I$(HAJIMU_INCLUDE)
    CFLAGS += -shared -dynamiclib
    LDFLAGS = -lz -lpthread
else
    CFLAGS  = -Wall -Wextra -O2 -std=c11 -fPIC -I$(HAJIMU_INCLUDE)
    CFLAGS += -shared
    LDFLAGS = -lz -lpthread
endif

.PHONY: all clean install uninstall help

all: $(OUT)
	@echo "  ビルド完了: $(OUT)"

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

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
