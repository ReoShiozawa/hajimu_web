/**
 * hajimu_web — はじむ用 HTTP ウェブサーバープラグイン
 * 
 * Python の Flask / Node.js の Express に相当するシンプルな HTTP サーバー。
 * 統一拡張子 .hjp（Hajimu Plugin）でクロスプラットフォーム対応。
 * 
 * === 機能 ===
 *   - HTTP/1.1 サーバー（GET / POST / PUT / DELETE）
 *   - パスルーティング（静的パス + パスパラメータ :param）
 *   - 静的ファイル配信
 *   - JSON レスポンスヘルパー
 *   - リクエストヘッダー / ボディ / クエリパラメータ解析
 *   - CORS ヘッダー対応
 * 
 * === アーキテクチャ ===
 *   ┌─────────────────────────────────────────────┐
 *   │  はじむコード (.jp)                          │
 *   │  ─────────────────                          │
 *   │  取り込む "hajimu_web" として ウェブ          │
 *   │  ウェブ.サーバー作成(8080)                    │
 *   │  ウェブ.GET("/", ハンドラ)                    │
 *   │  ウェブ.起動()                               │
 *   └──────────┬──────────────────────────────────┘
 *              │ .hjp プラグインAPI
 *   ┌──────────▼──────────────────────────────────┐
 *   │  hajimu_web.c (このファイル)                 │
 *   │  ─────────────────                          │
 *   │  ソケット → HTTP パーサー → ルーター          │
 *   │  → レスポンスビルダー → 送信                  │
 *   └─────────────────────────────────────────────┘
 * 
 * === はじむでの使用例 ===
 *   取り込む "hajimu_web" として ウェブ
 *   
 *   ウェブ.サーバー作成(8080)
 *   
 *   ウェブ.GET("/", 関数(リクエスト):
 *       戻す {"状態": 200, "本文": "こんにちは、世界！"}
 *   終わり)
 *   
 *   ウェブ.GET("/api/users", 関数(リクエスト):
 *       戻す ウェブ.JSON応答([{"名前": "太郎"}, {"名前": "花子"}])
 *   終わり)
 *   
 *   ウェブ.起動()
 * 
 * コンパイル:
 *   macOS:  make
 *   Linux:  make
 *   Win:    make (MinGW)
 */

#include "hajimu_plugin.h"

#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>

// =============================================================================
// プラットフォーム抽象化
// =============================================================================

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef SOCKET socket_t;
  #define INVALID_SOCK INVALID_SOCKET
  #define close_socket closesocket
  #define sock_errno WSAGetLastError()
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  typedef int socket_t;
  #define INVALID_SOCK (-1)
  #define close_socket close
  #define sock_errno errno
#endif

// =============================================================================
// 定数
// =============================================================================

#define HW_MAX_ROUTES       128
#define HW_MAX_HEADERS      64
#define HW_MAX_PATH         2048
#define HW_MAX_HEADER_VALUE 4096
#define HW_MAX_BODY         (1024 * 1024)  // 1MB
#define HW_READ_BUF         8192
#define HW_MAX_PARAMS       32
#define HW_MAX_QUERY_PARAMS 32
#define HW_STATIC_BUF       (64 * 1024)    // 64KB

// HTTP メソッド
typedef enum {
    METHOD_GET = 0,
    METHOD_POST,
    METHOD_PUT,
    METHOD_DELETE,
    METHOD_OPTIONS,
    METHOD_HEAD,
    METHOD_UNKNOWN,
} HttpMethod;

// =============================================================================
// データ構造
// =============================================================================

// キー・バリューペア
typedef struct {
    char key[256];
    char value[HW_MAX_HEADER_VALUE];
} KVPair;

// パースされた HTTP リクエスト
typedef struct {
    HttpMethod method;
    char path[HW_MAX_PATH];
    char raw_query[HW_MAX_PATH];
    char http_version[16];
    KVPair headers[HW_MAX_HEADERS];
    int header_count;
    char *body;
    int body_length;
    // パスパラメータ
    KVPair params[HW_MAX_PARAMS];
    int param_count;
    // クエリパラメータ
    KVPair query[HW_MAX_QUERY_PARAMS];
    int query_count;
    // クライアント情報
    char client_ip[64];
} HttpRequest;

// ルート登録情報
// NOTE: はじむのコールバック関数を保持するため Value を使う。
//       ただし現段階のプラグインAPIではコールバック呼出不可のため、
//       静的レスポンス方式と C 関数ハンドラの2種類をサポートする。
typedef struct {
    HttpMethod method;
    char pattern[HW_MAX_PATH];  // パスパターン（例: "/api/users/:id"）
    // --- 静的レスポンス ---
    int  has_static_response;
    int  static_status;
    char static_content_type[128];
    char static_body[HW_MAX_BODY];
    // --- C 関数ハンドラ ---
    Value (*c_handler)(const HttpRequest *req);
} Route;

// サーバー状態
typedef struct {
    socket_t listen_fd;
    int port;
    int running;
    Route routes[HW_MAX_ROUTES];
    int route_count;
    char static_dir[HW_MAX_PATH];   // 静的ファイルディレクトリ
    int  cors_enabled;              // CORS ヘッダーを付与するか
} WebServer;

// グローバルサーバーインスタンス（1プロセス1サーバー）
static WebServer g_server = {0};
static volatile int g_shutdown = 0;

// =============================================================================
// ユーティリティ
// =============================================================================

static const char *method_to_string(HttpMethod m) {
    switch (m) {
        case METHOD_GET:     return "GET";
        case METHOD_POST:    return "POST";
        case METHOD_PUT:     return "PUT";
        case METHOD_DELETE:  return "DELETE";
        case METHOD_OPTIONS: return "OPTIONS";
        case METHOD_HEAD:    return "HEAD";
        default:             return "UNKNOWN";
    }
}

static HttpMethod string_to_method(const char *s) {
    if (strcmp(s, "GET")     == 0) return METHOD_GET;
    if (strcmp(s, "POST")    == 0) return METHOD_POST;
    if (strcmp(s, "PUT")     == 0) return METHOD_PUT;
    if (strcmp(s, "DELETE")  == 0) return METHOD_DELETE;
    if (strcmp(s, "OPTIONS") == 0) return METHOD_OPTIONS;
    if (strcmp(s, "HEAD")    == 0) return METHOD_HEAD;
    return METHOD_UNKNOWN;
}

/**
 * URL デコード: %XX → 文字
 */
static void url_decode(const char *src, char *dst, int dst_size) {
    int di = 0;
    for (int i = 0; src[i] && di < dst_size - 1; i++) {
        if (src[i] == '%' && src[i+1] && src[i+2]) {
            char hex[3] = {src[i+1], src[i+2], '\0'};
            dst[di++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (src[i] == '+') {
            dst[di++] = ' ';
        } else {
            dst[di++] = src[i];
        }
    }
    dst[di] = '\0';
}

/**
 * クエリ文字列をパース: "key1=val1&key2=val2" → KVPair[]
 */
static int parse_query_string(const char *qs, KVPair *out, int max) {
    if (!qs || !*qs) return 0;
    int count = 0;
    char buf[HW_MAX_PATH];
    snprintf(buf, sizeof(buf), "%s", qs);
    
    char *pair = strtok(buf, "&");
    while (pair && count < max) {
        char *eq = strchr(pair, '=');
        if (eq) {
            *eq = '\0';
            url_decode(pair, out[count].key, sizeof(out[count].key));
            url_decode(eq + 1, out[count].value, sizeof(out[count].value));
        } else {
            url_decode(pair, out[count].key, sizeof(out[count].key));
            out[count].value[0] = '\0';
        }
        count++;
        pair = strtok(NULL, "&");
    }
    return count;
}

/**
 * MIME タイプを拡張子から取得
 */
static const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    ext++;
    if (strcasecmp(ext, "html") == 0 || strcasecmp(ext, "htm") == 0)
        return "text/html; charset=utf-8";
    if (strcasecmp(ext, "css") == 0)  return "text/css; charset=utf-8";
    if (strcasecmp(ext, "js") == 0)   return "application/javascript; charset=utf-8";
    if (strcasecmp(ext, "json") == 0) return "application/json; charset=utf-8";
    if (strcasecmp(ext, "png") == 0)  return "image/png";
    if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0)
        return "image/jpeg";
    if (strcasecmp(ext, "gif") == 0)  return "image/gif";
    if (strcasecmp(ext, "svg") == 0)  return "image/svg+xml";
    if (strcasecmp(ext, "ico") == 0)  return "image/x-icon";
    if (strcasecmp(ext, "txt") == 0)  return "text/plain; charset=utf-8";
    if (strcasecmp(ext, "xml") == 0)  return "application/xml";
    if (strcasecmp(ext, "pdf") == 0)  return "application/pdf";
    if (strcasecmp(ext, "woff") == 0) return "font/woff";
    if (strcasecmp(ext, "woff2") == 0) return "font/woff2";
    return "application/octet-stream";
}

/**
 * 現在時刻を HTTP-date 形式で取得
 */
static void get_http_date(char *buf, int buf_size) {
    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);
    strftime(buf, buf_size, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}

// =============================================================================
// HTTP パーサー
// =============================================================================

/**
 * 受信したバイト列を HttpRequest にパースする。
 * リクエスト行 + ヘッダー + ボディ（Content-Length 対応）
 */
static int parse_http_request(const char *raw, int raw_len, HttpRequest *req) {
    memset(req, 0, sizeof(*req));
    
    // リクエスト行を取得
    const char *line_end = strstr(raw, "\r\n");
    if (!line_end) return -1;
    
    char request_line[HW_MAX_PATH];
    int line_len = (int)(line_end - raw);
    if (line_len >= (int)sizeof(request_line)) return -1;
    memcpy(request_line, raw, line_len);
    request_line[line_len] = '\0';
    
    // "METHOD /path HTTP/1.1" をパース
    char method_str[16] = {0};
    char full_path[HW_MAX_PATH] = {0};
    if (sscanf(request_line, "%15s %2047s %15s", method_str, full_path, req->http_version) != 3) {
        return -1;
    }
    req->method = string_to_method(method_str);
    
    // パスとクエリを分離
    char *qmark = strchr(full_path, '?');
    if (qmark) {
        *qmark = '\0';
        snprintf(req->raw_query, sizeof(req->raw_query), "%s", qmark + 1);
        req->query_count = parse_query_string(req->raw_query, req->query, HW_MAX_QUERY_PARAMS);
    }
    url_decode(full_path, req->path, sizeof(req->path));
    
    // ヘッダーをパース
    const char *hp = line_end + 2;
    while (hp < raw + raw_len) {
        const char *he = strstr(hp, "\r\n");
        if (!he) break;
        if (he == hp) {
            // 空行 → ボディ開始
            hp = he + 2;
            break;
        }
        if (req->header_count < HW_MAX_HEADERS) {
            int hlen = (int)(he - hp);
            char hbuf[HW_MAX_HEADER_VALUE];
            if (hlen < (int)sizeof(hbuf)) {
                memcpy(hbuf, hp, hlen);
                hbuf[hlen] = '\0';
                char *colon = strchr(hbuf, ':');
                if (colon) {
                    *colon = '\0';
                    char *val = colon + 1;
                    while (*val == ' ') val++;
                    snprintf(req->headers[req->header_count].key, 256, "%s", hbuf);
                    snprintf(req->headers[req->header_count].value, 
                             HW_MAX_HEADER_VALUE, "%s", val);
                    req->header_count++;
                }
            }
        }
        hp = he + 2;
    }
    
    // ボディ（Content-Length ベース）
    int content_length = 0;
    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].key, "Content-Length") == 0) {
            content_length = atoi(req->headers[i].value);
            break;
        }
    }
    if (content_length > 0 && content_length < HW_MAX_BODY) {
        int remaining = raw_len - (int)(hp - raw);
        int to_copy = content_length < remaining ? content_length : remaining;
        req->body = (char *)malloc(to_copy + 1);
        if (req->body) {
            memcpy(req->body, hp, to_copy);
            req->body[to_copy] = '\0';
            req->body_length = to_copy;
        }
    }
    
    return 0;
}

// =============================================================================
// ルーティング
// =============================================================================

/**
 * パスパターンマッチング
 * "/api/users/:id" は "/api/users/42" にマッチし、params["id"] = "42" が設定される
 */
static int match_route(const char *pattern, const char *path,
                       KVPair *params, int *param_count) {
    *param_count = 0;
    
    // 完全一致の高速パス
    if (strcmp(pattern, path) == 0) return 1;
    
    // パラメータ付きパターンマッチング
    const char *pp = pattern;
    const char *rp = path;
    
    while (*pp && *rp) {
        if (*pp == ':') {
            // パラメータ名を取得
            pp++;
            char param_name[256] = {0};
            int ni = 0;
            while (*pp && *pp != '/' && ni < 255) {
                param_name[ni++] = *pp++;
            }
            param_name[ni] = '\0';
            
            // パス値を取得
            char param_val[HW_MAX_HEADER_VALUE] = {0};
            int vi = 0;
            while (*rp && *rp != '/' && vi < HW_MAX_HEADER_VALUE - 1) {
                param_val[vi++] = *rp++;
            }
            param_val[vi] = '\0';
            
            if (*param_count < HW_MAX_PARAMS) {
                snprintf(params[*param_count].key, 256, "%s", param_name);
                snprintf(params[*param_count].value, HW_MAX_HEADER_VALUE, "%s", param_val);
                (*param_count)++;
            }
        } else {
            if (*pp != *rp) return 0;
            pp++;
            rp++;
        }
    }
    
    return (*pp == '\0' && *rp == '\0');
}

/**
 * ルートを検索してマッチしたものを返す
 */
static Route *find_route(HttpMethod method, const char *path, HttpRequest *req) {
    for (int i = 0; i < g_server.route_count; i++) {
        Route *r = &g_server.routes[i];
        if (r->method != method) continue;
        
        KVPair params[HW_MAX_PARAMS];
        int param_count = 0;
        
        if (match_route(r->pattern, path, params, &param_count)) {
            // パラメータをリクエストにコピー
            for (int j = 0; j < param_count && req->param_count < HW_MAX_PARAMS; j++) {
                req->params[req->param_count] = params[j];
                req->param_count++;
            }
            return r;
        }
    }
    return NULL;
}

// =============================================================================
// レスポンス送信
// =============================================================================

static const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        default:  return "OK";
    }
}

/**
 * HTTP レスポンスを送信する
 */
static void send_response(socket_t fd, int status_code,
                          const char *content_type,
                          const char *body, int body_len) {
    char date[64];
    get_http_date(date, sizeof(date));
    
    char header[2048];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Date: %s\r\n"
        "Server: hajimu_web/1.0.0\r\n"
        "Connection: close\r\n",
        status_code, status_text(status_code),
        content_type, body_len, date);
    
    if (g_server.cors_enabled) {
        hlen += snprintf(header + hlen, sizeof(header) - hlen,
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n");
    }
    
    hlen += snprintf(header + hlen, sizeof(header) - hlen, "\r\n");
    
    send(fd, header, hlen, 0);
    if (body && body_len > 0) {
        send(fd, body, body_len, 0);
    }
}

/**
 * 静的ファイルを配信
 */
static int serve_static_file(socket_t fd, const char *path) {
    if (g_server.static_dir[0] == '\0') return 0;
    
    // パストラバーサル防止
    if (strstr(path, "..") != NULL) {
        send_response(fd, 403, "text/plain", "Forbidden", 9);
        return 1;
    }
    
    char filepath[HW_MAX_PATH];
    const char *req_path = path;
    if (strcmp(req_path, "/") == 0) req_path = "/index.html";
    snprintf(filepath, sizeof(filepath), "%s%s", g_server.static_dir, req_path);
    
    FILE *f = fopen(filepath, "rb");
    if (!f) return 0;
    
    // ファイルサイズ取得
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    const char *mime = get_mime_type(filepath);
    
    // ヘッダー送信
    char date[64];
    get_http_date(date, sizeof(date));
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Date: %s\r\n"
        "Server: hajimu_web/1.0.0\r\n"
        "Connection: close\r\n",
        mime, file_size, date);
    
    if (g_server.cors_enabled) {
        hlen += snprintf(header + hlen, sizeof(header) - hlen,
            "Access-Control-Allow-Origin: *\r\n");
    }
    hlen += snprintf(header + hlen, sizeof(header) - hlen, "\r\n");
    send(fd, header, hlen, 0);
    
    // ボディをチャンク送信
    char buf[HW_STATIC_BUF];
    size_t nread;
    while ((nread = fread(buf, 1, sizeof(buf), f)) > 0) {
        send(fd, buf, (int)nread, 0);
    }
    fclose(f);
    return 1;
}

// =============================================================================
// リクエスト → Value 変換（はじむ側に渡す辞書を構築）
// =============================================================================

/**
 * HttpRequest を辞書型 Value に変換する。
 * はじむ側でリクエスト情報にアクセスするための構造体。
 * 将来コールバック対応時に使用される。
 */
__attribute__((unused))
static Value request_to_value(const HttpRequest *req) {
    // 辞書型はプラグインAPIでは直接作成できないため、
    // 配列でキー・バリューのペアを返す
    // [メソッド, パス, クエリ文字列, ボディ, ヘッダー配列, パラメータ配列]
    Value arr = hajimu_array();
    
    // [0] メソッド
    hajimu_array_push(&arr, hajimu_string(method_to_string(req->method)));
    // [1] パス
    hajimu_array_push(&arr, hajimu_string(req->path));
    // [2] クエリ文字列
    hajimu_array_push(&arr, hajimu_string(req->raw_query));
    // [3] ボディ
    hajimu_array_push(&arr, hajimu_string(req->body ? req->body : ""));
    // [4] クライアントIP
    hajimu_array_push(&arr, hajimu_string(req->client_ip));
    
    // [5] ヘッダー配列 [[キー, 値], ...]
    Value headers = hajimu_array();
    for (int i = 0; i < req->header_count; i++) {
        Value pair = hajimu_array();
        hajimu_array_push(&pair, hajimu_string(req->headers[i].key));
        hajimu_array_push(&pair, hajimu_string(req->headers[i].value));
        hajimu_array_push(&headers, pair);
    }
    hajimu_array_push(&arr, headers);
    
    // [6] パスパラメータ配列 [[キー, 値], ...]
    Value params = hajimu_array();
    for (int i = 0; i < req->param_count; i++) {
        Value pair = hajimu_array();
        hajimu_array_push(&pair, hajimu_string(req->params[i].key));
        hajimu_array_push(&pair, hajimu_string(req->params[i].value));
        hajimu_array_push(&params, pair);
    }
    hajimu_array_push(&arr, params);
    
    // [7] クエリパラメータ配列 [[キー, 値], ...]
    Value query_params = hajimu_array();
    for (int i = 0; i < req->query_count; i++) {
        Value pair = hajimu_array();
        hajimu_array_push(&pair, hajimu_string(req->query[i].key));
        hajimu_array_push(&pair, hajimu_string(req->query[i].value));
        hajimu_array_push(&query_params, pair);
    }
    hajimu_array_push(&arr, query_params);
    
    return arr;
}

// =============================================================================
// リクエスト処理
// =============================================================================

static void handle_client(socket_t client_fd, struct sockaddr_in *addr) {
    // クライアントIP取得
    char client_ip[64] = {0};
    inet_ntop(AF_INET, &addr->sin_addr, client_ip, sizeof(client_ip));
    
    // データ受信
    char buf[HW_READ_BUF];
    int total = 0;
    char *raw = (char *)malloc(HW_READ_BUF);
    if (!raw) { close_socket(client_fd); return; }
    int capacity = HW_READ_BUF;
    
    while (1) {
        int n = (int)recv(client_fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        
        // バッファ拡張
        if (total + n >= capacity) {
            capacity *= 2;
            char *tmp = (char *)realloc(raw, capacity);
            if (!tmp) { free(raw); close_socket(client_fd); return; }
            raw = tmp;
        }
        memcpy(raw + total, buf, n);
        total += n;
        
        // ヘッダー終端 "\r\n\r\n" が見つかったか
        if (total >= 4) {
            char *header_end = strstr(raw, "\r\n\r\n");
            if (header_end) {
                // Content-Length があればボディも待つ
                char *cl = strcasestr(raw, "Content-Length:");
                if (cl) {
                    int body_expected = atoi(cl + 15);
                    int header_size = (int)(header_end - raw) + 4;
                    int body_received = total - header_size;
                    if (body_received >= body_expected) break;
                } else {
                    break;
                }
            }
        }
        
        if (total > HW_MAX_BODY) break;
    }
    
    if (total == 0) {
        free(raw);
        close_socket(client_fd);
        return;
    }
    raw[total] = '\0';
    
    // パース
    HttpRequest req;
    if (parse_http_request(raw, total, &req) != 0) {
        send_response(client_fd, 400, "text/plain; charset=utf-8", 
                     "Bad Request", 11);
        free(raw);
        close_socket(client_fd);
        return;
    }
    snprintf(req.client_ip, sizeof(req.client_ip), "%s", client_ip);
    
    // ログ出力
    printf("[hajimu_web] %s %s %s\n", 
           method_to_string(req.method), req.path, client_ip);
    
    // OPTIONS → CORS プリフライト応答
    if (req.method == METHOD_OPTIONS && g_server.cors_enabled) {
        send_response(client_fd, 204, "text/plain", "", 0);
        if (req.body) free(req.body);
        free(raw);
        close_socket(client_fd);
        return;
    }
    
    // ルート検索
    Route *route = find_route(req.method, req.path, &req);
    
    if (route) {
        if (route->has_static_response) {
            // 静的レスポンス（ルート登録時に設定されたもの）
            send_response(client_fd, route->static_status,
                         route->static_content_type,
                         route->static_body, (int)strlen(route->static_body));
        } else if (route->c_handler) {
            // C関数ハンドラ
            Value result = route->c_handler(&req);
            if (result.type == VALUE_STRING) {
                send_response(client_fd, 200, "text/html; charset=utf-8",
                             result.string.data, result.string.length);
            } else {
                send_response(client_fd, 200, "text/plain; charset=utf-8",
                             "OK", 2);
            }
        } else {
            send_response(client_fd, 200, "text/plain; charset=utf-8",
                         "OK", 2);
        }
    } else if (req.method == METHOD_GET && serve_static_file(client_fd, req.path)) {
        // 静的ファイルが見つかった → serve_static_file 内で送信済み
    } else {
        const char *not_found = "{\"エラー\": \"ページが見つかりません\"}";
        send_response(client_fd, 404, "application/json; charset=utf-8",
                     not_found, (int)strlen(not_found));
    }
    
    if (req.body) free(req.body);
    free(raw);
    close_socket(client_fd);
}

// =============================================================================
// シグナルハンドラ
// =============================================================================

static void signal_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
    if (g_server.listen_fd != INVALID_SOCK) {
        close_socket(g_server.listen_fd);
        g_server.listen_fd = INVALID_SOCK;
    }
}

// =============================================================================
// プラグイン関数: はじむから呼び出される関数群
// =============================================================================

/**
 * サーバー作成(ポート)
 * ポート番号を指定してサーバーを初期化する
 */
static Value fn_server_create(int argc, Value *argv) {
    (void)argc;
    if (argv[0].type != VALUE_NUMBER) {
        fprintf(stderr, "[hajimu_web] エラー: ポート番号は数値で指定してください\n");
        return hajimu_bool(false);
    }
    
    int port = (int)argv[0].number;
    if (port < 1 || port > 65535) {
        fprintf(stderr, "[hajimu_web] エラー: ポート番号は1〜65535の範囲で指定してください\n");
        return hajimu_bool(false);
    }
    
    memset(&g_server, 0, sizeof(g_server));
    g_server.listen_fd = INVALID_SOCK;
    g_server.port = port;
    g_server.running = 0;
    g_server.route_count = 0;
    g_server.static_dir[0] = '\0';
    g_server.cors_enabled = 0;
    g_shutdown = 0;
    
    return hajimu_bool(true);
}

/**
 * ルート追加の内部関数
 */
static Value add_route(HttpMethod method, const char *pattern,
                       int status, const char *content_type, const char *body) {
    if (g_server.route_count >= HW_MAX_ROUTES) {
        fprintf(stderr, "[hajimu_web] エラー: ルートの最大数に達しました\n");
        return hajimu_bool(false);
    }
    
    Route *r = &g_server.routes[g_server.route_count++];
    r->method = method;
    snprintf(r->pattern, sizeof(r->pattern), "%s", pattern);
    r->has_static_response = 1;
    r->static_status = status;
    snprintf(r->static_content_type, sizeof(r->static_content_type), "%s", content_type);
    snprintf(r->static_body, sizeof(r->static_body), "%s", body);
    r->c_handler = NULL;
    
    return hajimu_bool(true);
}

/**
 * ルート追加(メソッド, パス, ステータス, コンテンツタイプ, 本文)
 * 
 * 汎用的なルート登録関数
 * 例: ルート追加("GET", "/", 200, "text/html", "<h1>Hello</h1>")
 */
static Value fn_route_add(int argc, Value *argv) {
    if (argc < 5) {
        fprintf(stderr, "[hajimu_web] エラー: ルート追加には5つの引数が必要です\n");
        return hajimu_bool(false);
    }
    if (argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_NUMBER || argv[3].type != VALUE_STRING ||
        argv[4].type != VALUE_STRING) {
        fprintf(stderr, "[hajimu_web] エラー: ルート追加(メソッド, パス, ステータス, コンテンツタイプ, 本文)\n");
        return hajimu_bool(false);
    }
    
    HttpMethod method = string_to_method(argv[0].string.data);
    return add_route(method, argv[1].string.data, (int)argv[2].number,
                     argv[3].string.data, argv[4].string.data);
}

/**
 * GET(パス, 本文)
 * GET ルートを簡易登録（HTML レスポンス）
 */
static Value fn_get(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        fprintf(stderr, "[hajimu_web] エラー: GET(パス, 本文)\n");
        return hajimu_bool(false);
    }
    return add_route(METHOD_GET, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

/**
 * POST(パス, 本文)
 * POST ルートを簡易登録
 */
static Value fn_post(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING) {
        fprintf(stderr, "[hajimu_web] エラー: POST(パス, 本文)\n");
        return hajimu_bool(false);
    }
    return add_route(METHOD_POST, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

/**
 * JSON応答(ステータス, JSON文字列)
 * JSON レスポンスルートを登録 or JSON文字列としてレスポンスを構築
 */
static Value fn_json_route(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING || argv[1].type != VALUE_NUMBER ||
        argv[2].type != VALUE_STRING) {
        fprintf(stderr, "[hajimu_web] エラー: JSON応答(パス, ステータス, JSON文字列)\n");
        return hajimu_bool(false);
    }
    return add_route(METHOD_GET, argv[0].string.data, (int)argv[1].number,
                     "application/json; charset=utf-8", argv[2].string.data);
}

/**
 * 静的ファイル(ディレクトリ)
 * 静的ファイル配信ディレクトリを設定
 */
static Value fn_static_dir(int argc, Value *argv) {
    (void)argc;
    if (argv[0].type != VALUE_STRING) {
        fprintf(stderr, "[hajimu_web] エラー: 静的ファイル(ディレクトリパス)\n");
        return hajimu_bool(false);
    }
    snprintf(g_server.static_dir, sizeof(g_server.static_dir), "%s", argv[0].string.data);
    // 末尾のスラッシュを除去
    int len = (int)strlen(g_server.static_dir);
    if (len > 0 && g_server.static_dir[len - 1] == '/') {
        g_server.static_dir[len - 1] = '\0';
    }
    printf("[hajimu_web] 静的ファイルディレクトリ: %s\n", g_server.static_dir);
    return hajimu_bool(true);
}

/**
 * CORS有効()
 * CORS ヘッダーを有効にする
 */
static Value fn_cors_enable(int argc, Value *argv) {
    (void)argc; (void)argv;
    g_server.cors_enabled = 1;
    return hajimu_bool(true);
}

/**
 * ルート一覧()
 * 登録されたルートの一覧を配列で返す
 */
static Value fn_route_list(int argc, Value *argv) {
    (void)argc; (void)argv;
    Value arr = hajimu_array();
    for (int i = 0; i < g_server.route_count; i++) {
        Route *r = &g_server.routes[i];
        char desc[HW_MAX_PATH];
        snprintf(desc, sizeof(desc), "%s %s", 
                 method_to_string(r->method), r->pattern);
        hajimu_array_push(&arr, hajimu_string(desc));
    }
    return arr;
}

/**
 * 起動()
 * サーバーを起動し、リクエストの受付を開始する（ブロッキング）
 */
static Value fn_server_start(int argc, Value *argv) {
    (void)argc; (void)argv;
    
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[hajimu_web] エラー: WinSock 初期化失敗\n");
        return hajimu_bool(false);
    }
#endif
    
    // ソケット作成
    g_server.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server.listen_fd == INVALID_SOCK) {
        fprintf(stderr, "[hajimu_web] エラー: ソケットを作成できません\n");
        return hajimu_bool(false);
    }
    
    // SO_REUSEADDR
    int opt = 1;
    setsockopt(g_server.listen_fd, SOL_SOCKET, SO_REUSEADDR, 
               (const char *)&opt, sizeof(opt));
    
    // バインド
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)g_server.port);
    
    if (bind(g_server.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[hajimu_web] エラー: ポート %d にバインドできません（%s）\n",
                g_server.port, strerror(errno));
        close_socket(g_server.listen_fd);
        return hajimu_bool(false);
    }
    
    // リッスン
    if (listen(g_server.listen_fd, 128) < 0) {
        fprintf(stderr, "[hajimu_web] エラー: リッスンに失敗しました\n");
        close_socket(g_server.listen_fd);
        return hajimu_bool(false);
    }
    
    // シグナルハンドラ（Ctrl+C で停止）
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    
    g_server.running = 1;
    
    printf("\n");
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║   🌐 hajimu_web サーバー起動             ║\n");
    printf("  ║                                          ║\n");
    printf("  ║   http://localhost:%-5d                  ║\n", g_server.port);
    printf("  ║                                          ║\n");
    printf("  ║   ルート: %d 件登録済み                   ║\n", g_server.route_count);
    if (g_server.static_dir[0]) {
    printf("  ║   静的:  %s                              \n", g_server.static_dir);
    }
    printf("  ║   Ctrl+C で停止                          ║\n");
    printf("  ╚══════════════════════════════════════════╝\n");
    printf("\n");
    
    // メインループ
    while (!g_shutdown) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        socket_t client_fd = accept(g_server.listen_fd, 
                                     (struct sockaddr *)&client_addr, &client_len);
        if (client_fd == INVALID_SOCK) {
            if (g_shutdown) break;
            continue;
        }
        
        handle_client(client_fd, &client_addr);
    }
    
    // クリーンアップ
    if (g_server.listen_fd != INVALID_SOCK) {
        close_socket(g_server.listen_fd);
        g_server.listen_fd = INVALID_SOCK;
    }
    g_server.running = 0;
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    printf("\n[hajimu_web] サーバーを停止しました\n");
    return hajimu_bool(true);
}

/**
 * 停止()
 * サーバーを停止する
 */
static Value fn_server_stop(int argc, Value *argv) {
    (void)argc; (void)argv;
    g_shutdown = 1;
    if (g_server.listen_fd != INVALID_SOCK) {
        close_socket(g_server.listen_fd);
        g_server.listen_fd = INVALID_SOCK;
    }
    return hajimu_bool(true);
}

/**
 * ポート取得()
 * 現在のサーバーポートを返す
 */
static Value fn_get_port(int argc, Value *argv) {
    (void)argc; (void)argv;
    return hajimu_number(g_server.port);
}

/**
 * 実行中()
 * サーバーが実行中かどうかを返す
 */
static Value fn_is_running(int argc, Value *argv) {
    (void)argc; (void)argv;
    return hajimu_bool(g_server.running && !g_shutdown);
}

// =============================================================================
// 関数テーブル
// =============================================================================

static HajimuPluginFunc functions[] = {
    // サーバー管理
    {"サーバー作成",  fn_server_create,   1, 1},
    {"起動",         fn_server_start,     0, 0},
    {"停止",         fn_server_stop,      0, 0},
    {"ポート取得",    fn_get_port,        0, 0},
    {"実行中",       fn_is_running,       0, 0},
    
    // ルーティング
    {"ルート追加",    fn_route_add,       5, 5},
    {"GET",          fn_get,             2, 2},
    {"POST",         fn_post,            2, 2},
    {"JSON応答",     fn_json_route,      3, 3},
    {"ルート一覧",    fn_route_list,      0, 0},
    
    // 設定
    {"静的ファイル",   fn_static_dir,     1, 1},
    {"CORS有効",     fn_cors_enable,     0, 0},
};

// =============================================================================
// プラグイン初期化
// =============================================================================

HAJIMU_PLUGIN_EXPORT HajimuPluginInfo *hajimu_plugin_init(void) {
    static HajimuPluginInfo info = {
        .name           = "hajimu_web",
        .version        = "1.0.0",
        .author         = "はじむ開発チーム",
        .description    = "HTTP ウェブサーバープラグイン — Flask/Express ライクな API",
        .functions      = functions,
        .function_count = sizeof(functions) / sizeof(functions[0]),
    };
    return &info;
}
