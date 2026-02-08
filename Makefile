# ==============================================================================
# hajimu_web — はじむ用 HTTP ウェブサーバープラグイン ビルドファイル
#
# 使い方:
#   make               ビルド（hajimu_web.hjp を生成）
#   make clean          ビルド成果物を削除
#   make install        ~/.hajimu/plugins/ にインストール
#   make uninstall      インストール済みプラグインを削除
#   make test           テストサーバーを起動
#
# クロスプラットフォーム対応（macOS / Linux / Windows MinGW）
# ==============================================================================

# プラグイン名
PLUGIN_NAME = hajimu_web

# ソースファイル
SRC = src/hajimu_web.c

# はじむインクルードパス
# 環境変数 HAJIMU_INCLUDE で指定可能。未設定時は相対パスから検索
HAJIMU_INCLUDE ?= $(shell \
	if [ -d "../../jp/include" ]; then echo "../../jp/include"; \
	elif [ -d "../jp/include" ]; then echo "../jp/include"; \
	elif [ -d "/usr/local/include/hajimu" ]; then echo "/usr/local/include/hajimu"; \
	else echo "include"; fi)

# コンパイラ
CC ?= gcc

# 共通フラグ
CFLAGS = -Wall -Wextra -O2 -I$(HAJIMU_INCLUDE)

# ==============================================================================
# プラットフォーム判定
# ==============================================================================

UNAME := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME),Darwin)
    # macOS
    SHARED_FLAGS = -shared -dynamiclib -fPIC
    OUT = $(PLUGIN_NAME).hjp
    INSTALL_DIR = $(HOME)/.hajimu/plugins
else ifeq ($(UNAME),Linux)
    # Linux
    SHARED_FLAGS = -shared -fPIC
    OUT = $(PLUGIN_NAME).hjp
    INSTALL_DIR = $(HOME)/.hajimu/plugins
else
    # Windows (MinGW)
    SHARED_FLAGS = -shared
    OUT = $(PLUGIN_NAME).hjp
    CFLAGS += -lws2_32
    INSTALL_DIR = $(USERPROFILE)\.hajimu\plugins
endif

# ==============================================================================
# ターゲット
# ==============================================================================

.PHONY: all clean install uninstall test help

all: $(OUT)
	@echo ""
	@echo "  ✅ ビルド成功: $(OUT)"
	@echo ""
	@echo "  インストール:   make install"
	@echo "  テスト:        make test"
	@echo ""

$(OUT): $(SRC)
	$(CC) $(SHARED_FLAGS) $(CFLAGS) -o $@ $<

clean:
	rm -f $(OUT)
	@echo "  🧹 クリーン完了"

install: $(OUT)
	@mkdir -p $(INSTALL_DIR)/$(PLUGIN_NAME)
	cp $(OUT) $(INSTALL_DIR)/$(PLUGIN_NAME)/
	cp hajimu.json $(INSTALL_DIR)/$(PLUGIN_NAME)/
	@echo ""
	@echo "  📦 インストール完了: $(INSTALL_DIR)/$(PLUGIN_NAME)/"
	@echo ""

uninstall:
	rm -rf $(INSTALL_DIR)/$(PLUGIN_NAME)
	@echo "  🗑  アンインストール完了"

# テストサーバー起動（はじむで examples/hello_server.jp を実行）
NIHONGO ?= $(shell \
	if [ -x "../../jp/nihongo" ]; then echo "../../jp/nihongo"; \
	elif command -v nihongo >/dev/null 2>&1; then echo "nihongo"; \
	else echo "./nihongo"; fi)

test: $(OUT)
	@echo "  🚀 テストサーバーを起動..."
	$(NIHONGO) examples/hello_server.jp

help:
	@echo ""
	@echo "  hajimu_web — はじむ用 HTTP ウェブサーバープラグイン"
	@echo ""
	@echo "  ターゲット:"
	@echo "    make             ビルド ($(OUT))"
	@echo "    make clean       クリーン"
	@echo "    make install     ~/.hajimu/plugins/ にインストール"
	@echo "    make uninstall   アンインストール"
	@echo "    make test        テストサーバー起動"
	@echo "    make help        このヘルプ"
	@echo ""
	@echo "  環境変数:"
	@echo "    HAJIMU_INCLUDE   はじむヘッダーパス (デフォルト: 自動検出)"
	@echo "    CC               コンパイラ (デフォルト: gcc)"
	@echo "    NIHONGO          はじむ実行パス (デフォルト: 自動検出)"
	@echo ""
