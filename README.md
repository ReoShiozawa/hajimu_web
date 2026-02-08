# hajimu_web

**はじむ言語初の外部パッケージ** — HTTP ウェブサーバープラグイン

Python の Flask / Node.js の Express のような、シンプルな API で HTTP サーバーを構築できるプラグインです。

## ✨ 特徴

- 🌐 HTTP/1.1 サーバー（GET / POST / PUT / DELETE / OPTIONS）
- 🔀 パスルーティング（静的パス + パスパラメータ `:param`）
- 📁 静的ファイル配信（MIME 自動判別）
- 📋 JSON レスポンスヘルパー
- 🔒 CORS ヘッダー対応
- ⚡ C 実装による高速動作
- 🖥️ クロスプラットフォーム（macOS / Linux / Windows）

## 📦 インストール

### 方法1: ソースからビルド

```bash
git clone https://github.com/ReoShiozawa/hajimu-web.git
cd hajimu-web
make
make install
```

### 方法2: .hjp ファイルを直接配置

`hajimu_web.hjp` と `hajimu.json` を以下のいずれかに配置:

```
プロジェクト/hajimu_packages/hajimu_web/
~/.hajimu/plugins/hajimu_web/
```

## 🚀 クイックスタート

### Hello World サーバー

```
取り込む "hajimu_web" として ウェブ

ウェブ.サーバー作成(8080)
ウェブ.GET("/", "<h1>こんにちは、はじむ！</h1>")
ウェブ.起動()
```

```bash
nihongo hello.jp
# → http://localhost:8080/ にアクセス
```

### JSON API サーバー

```
取り込む "hajimu_web" として ウェブ

ウェブ.サーバー作成(3000)
ウェブ.CORS有効()

ウェブ.JSON応答("/api/status", 200, "{\"状態\": \"正常\"}")
ウェブ.JSON応答("/api/users", 200, "[{\"名前\": \"太郎\"}, {\"名前\": \"花子\"}]")

ウェブ.起動()
```

### 静的ファイルサーバー

```
取り込む "hajimu_web" として ウェブ

ウェブ.サーバー作成(8000)
ウェブ.静的ファイル("public")
ウェブ.起動()
```

## 📖 API リファレンス

### サーバー管理

| 関数 | 説明 | 引数 |
|------|------|------|
| `サーバー作成(ポート)` | サーバーを初期化 | ポート番号（1〜65535） |
| `起動()` | サーバーを起動（ブロッキング） | なし |
| `停止()` | サーバーを停止 | なし |
| `ポート取得()` | 設定されたポート番号を返す | なし |
| `実行中()` | サーバーが実行中か判定 | なし |

### ルーティング

| 関数 | 説明 | 引数 |
|------|------|------|
| `GET(パス, 本文)` | GET ルートを登録 | パス, レスポンス本文 |
| `POST(パス, 本文)` | POST ルートを登録 | パス, レスポンス本文 |
| `ルート追加(メソッド, パス, ステータス, コンテンツタイプ, 本文)` | 汎用ルート登録 | 5引数 |
| `JSON応答(パス, ステータス, JSON文字列)` | JSON レスポンスルート登録 | パス, ステータス, JSON |
| `ルート一覧()` | 登録されたルート一覧 | なし |

### 設定

| 関数 | 説明 | 引数 |
|------|------|------|
| `静的ファイル(ディレクトリ)` | 静的ファイル配信ディレクトリ設定 | ディレクトリパス |
| `CORS有効()` | CORS ヘッダーを有効化 | なし |

## 📂 パスパラメータ

ルートパスに `:パラメータ名` を使用してパスパラメータを定義できます:

```
// "/api/users/42" にマッチ → params["id"] = "42"
ウェブ.ルート追加("GET", "/api/users/:id", 200, "application/json", "{\"id\": \"42\"}")
```

## 🔧 ビルド

### 必要なもの

- C コンパイラ (gcc / clang)
- はじむヘッダー（`hajimu_plugin.h`）
- POSIX 互換環境（Windows では MinGW）

### コマンド

```bash
make              # ビルド
make clean        # クリーン
make install      # ~/.hajimu/plugins/ にインストール
make uninstall    # アンインストール
make test         # テストサーバー起動
```

### 環境変数

| 変数 | デフォルト | 説明 |
|------|-----------|------|
| `HAJIMU_INCLUDE` | 自動検出 | はじむヘッダーのパス |
| `CC` | `gcc` | C コンパイラ |
| `NIHONGO` | 自動検出 | はじむ実行ファイルパス |

## 📁 ディレクトリ構成

```
jp-web/
├── hajimu.json           # パッケージマニフェスト
├── Makefile              # ビルドファイル
├── README.md             # このファイル
├── src/
│   └── hajimu_web.c      # プラグイン本体
└── examples/
    ├── hello_server.jp   # Hello World サーバー
    ├── api_server.jp     # JSON API サーバー
    ├── static_server.jp  # 静的ファイルサーバー
    └── public/
        └── index.html    # 静的ファイルサンプル
```

## 🏗️ アーキテクチャ

```
はじむコード (.jp)
     │  取り込む "hajimu_web" として ウェブ
     │  ウェブ.サーバー作成(8080)
     │  ウェブ.GET("/", ...)
     │  ウェブ.起動()
     ▼
hajimu_web.hjp (C 共有ライブラリ)
     │  ┌─────────────────────┐
     │  │  HTTP パーサー       │
     │  │  ルーティングエンジン │
     │  │  レスポンスビルダー   │
     │  │  静的ファイル配信     │
     │  │  POSIX ソケット      │
     │  └─────────────────────┘
     ▼
OS ソケット API (TCP/IP)
```

## 🤝 プラグイン開発の参考として

このパッケージは、はじむの外部パッケージ開発の**リファレンス実装**として設計されています。
独自のプラグインを開発する際の参考にしてください:

1. `hajimu.json` — パッケージマニフェストの書き方
2. `src/hajimu_web.c` — プラグイン関数の実装パターン
3. `Makefile` — クロスプラットフォームビルド
4. `examples/` — はじむでの使用例

## 📄 ライセンス

MIT License

## 🔗 関連リンク

- [はじむ言語](https://github.com/ReoShiozawa/hajimu)
- [はじむドキュメント](https://reoshiozawa.github.io/hajimu-document/)
- [プラグイン開発ガイド](https://reoshiozawa.github.io/hajimu-document/pages/plugins.html)
