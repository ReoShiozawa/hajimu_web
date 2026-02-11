/**
 * hajimu_web — はじむ用 HTTP ウェブサーバープラグイン v5.0
 *
 * Python の Flask / Node.js の Express に相当する本格的な HTTP サーバー。
 * 統一拡張子 .hjp（Hajimu Plugin）でクロスプラットフォーム対応。
 *
 * === v5.0 新機能 ===
 *   - Keep-Alive 持続接続ループ（実際のソケット再利用）
 *   - マルチスレッド化（スレッドプール + コールバックミューテックス）
 *   - 動的リダイレクト（コールバック内 res.redirect()）
 *   - JSON解析 VALUE_DICT 統一（オブジェクト → 辞書型）
 *   - headers VALUE_DICT 統一（全フィールド辞書アクセス可）
 *   - パス限定ミドルウェア（app.use('/api', fn) 対応）
 *   - Chunked Transfer Encoding（res.write() / res.end()）
 *   - Range リクエスト（206 Partial Content / 動画シーク）
 *   - コンテンツネゴシエーション（req.accepts()）
 *   - エラーミドルウェアチェーン（複数エラーハンドラ）
 *   - オプショナルパラメータ（:id? 構文）
 *   - Trust Proxy（X-Forwarded-For / X-Forwarded-Proto）
 *   - 複数静的ファイルディレクトリ / ディレクトリ一覧
 *   - コールバック内テンプレート描画
 *   - res.append() / res.location() / res.download()
 *
 * === v4.0 機能 ===
 *   - ユーザー定義ミドルウェア（はじむ関数ミドルウェア）
 *   - レスポンスAPI強化（JSON送信 / ファイル送信 / テキスト送信 / HTML送信）
 *   - セッション管理（インメモリセッションストア + Cookie）
 *   - gzip 圧縮（zlib / Accept-Encoding 自動判定）
 *   - ファイルアップロード（multipart/form-data パース）
 *   - HTTPS/TLS（OpenSSL 条件コンパイル）
 *   - SSE（Server-Sent Events / pthread）
 *   - エラーハンドリングコールバック（動的エラーハンドラ関数）
 *   - リクエストバリデーション
 *   - ルーターマウント
 *
 * === v3.0 機能 ===
 *   - コールバック関数ハンドラ（はじむ関数をルートハンドラとして使用可能）
 *   - Cookie 設定 / 削除（Set-Cookie ヘッダー）
 *   - レスポンスヘッダー / ステータスコード / Content-Type 動的設定
 *   - JSON パーサー / ジェネレーター（解析・生成ユーティリティ）
 *   - レートリミッタミドルウェア（IP単位のレート制限）
 *
 * === v2.0 機能 ===
 *   - ミドルウェア / フィルタ機能（前後フック、チェーン実行、ロガー内蔵）
 *   - リクエストボディ自動解析（JSON / フォーム / テキスト自動判定）
 *   - 高度なルーティング（ワイルドカード, ルートグループ, 全メソッド対応）
 *   - テンプレートエンジン（変数展開 {{変数}}, 条件 {{#もし}}, ループ {{#各}}）
 *   - 静的ファイル配信強化（MIME 50種+, キャッシュヘッダー, ETag, 304対応）
 *   - エラーハンドリング強化（カスタムエラーページ, ステータス別ハンドラ）
 *   - レスポンスヘルパー（リダイレクト, CORS設定, カスタムヘッダー）
 *
 * コンパイル:
 *   macOS:  make
 *   Linux:  make
 *   Win:    make (MinGW)
 */

#include "hajimu_plugin.h"

/* hajimu_plugin_set_runtime デフォルト実装 */
HAJIMU_PLUGIN_EXPORT void hajimu_plugin_set_runtime(HajimuRuntime *rt) {
    __hajimu_runtime = rt;
}

#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>
#include <zlib.h>

/* ================================================================= */
/* プラットフォーム抽象化                                              */
/* ================================================================= */

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
  #include <dirent.h>
  typedef int socket_t;
  #define INVALID_SOCK (-1)
  #define close_socket close
  #define sock_errno errno
#endif

/* ================================================================= */
/* 定数                                                               */
/* ================================================================= */

#define HW_MAX_ROUTES           256
#define HW_MAX_HEADERS          64
#define HW_MAX_PATH             2048
#define HW_MAX_HEADER_VALUE     4096
#define HW_MAX_BODY             (4 * 1024 * 1024)
#define HW_READ_BUF             8192
#define HW_MAX_PARAMS           32
#define HW_MAX_QUERY_PARAMS     32
#define HW_STATIC_BUF           (64 * 1024)
#define HW_MAX_MIDDLEWARES      32
#define HW_MAX_ERROR_HANDLERS   16
#define HW_MAX_GROUPS           32
#define HW_MAX_RESP_HEADERS     32
#define HW_MAX_TEMPLATE_VARS    64
#define HW_TEMPLATE_BUF         (256 * 1024)
#define HW_MAX_SESSIONS         256
#define HW_SESSION_ID_LEN       64
#define HW_SESSION_MAX_VARS     32
#define HW_MAX_UPLOADS          16
#define HW_UPLOAD_MAX_SIZE      (16 * 1024 * 1024)
#define HW_MAX_SSE_CLIENTS      64
#define HW_MAX_THREADS          64
#define HW_MAX_STATIC_DIRS      8
#define HW_MAX_ERROR_CALLBACKS  8

/* HTTP メソッド */
typedef enum {
    METHOD_GET = 0,
    METHOD_POST,
    METHOD_PUT,
    METHOD_DELETE,
    METHOD_PATCH,
    METHOD_OPTIONS,
    METHOD_HEAD,
    METHOD_ALL,
    METHOD_UNKNOWN,
} HttpMethod;

/* ================================================================= */
/* データ構造                                                         */
/* ================================================================= */

typedef struct {
    char key[256];
    char value[HW_MAX_HEADER_VALUE];
} KVPair;

typedef enum {
    BODY_NONE = 0,
    BODY_TEXT,
    BODY_JSON,
    BODY_FORM,
} BodyType;

typedef struct {
    BodyType type;
    char    *raw;
    int      raw_length;
    KVPair   fields[HW_MAX_QUERY_PARAMS];
    int      field_count;
} ParsedBody;

typedef struct {
    char field_name[256];
    char filename[256];
    char content_type[128];
    char *data;
    int  data_len;
} UploadedFile;

typedef struct {
    HttpMethod method;
    char       path[HW_MAX_PATH];
    char       raw_query[HW_MAX_PATH];
    char       http_version[16];
    KVPair     headers[HW_MAX_HEADERS];
    int        header_count;
    char      *body;
    int        body_length;
    ParsedBody parsed_body;
    KVPair     params[HW_MAX_PARAMS];
    int        param_count;
    KVPair     query[HW_MAX_QUERY_PARAMS];
    int        query_count;
    char       client_ip[64];
    KVPair     cookies[HW_MAX_QUERY_PARAMS];
    int        cookie_count;
    UploadedFile  uploads[HW_MAX_UPLOADS];
    int           upload_count;
    char          session_id[HW_SESSION_ID_LEN];
} HttpRequest;

typedef struct {
    int    status_code;
    char   content_type[256];
    KVPair headers[HW_MAX_RESP_HEADERS];
    int    header_count;
    char  *body;
    int    body_length;
    int    sent;
} HttpResponse;

typedef enum {
    MW_LOGGER = 0,
    MW_CORS,
    MW_SECURITY,
    MW_JSON_PARSE,
    MW_FORM_PARSE,
    MW_STATIC_CACHE,
    MW_RATE_LIMIT,
    MW_USER_CALLBACK,
    MW_COMPRESSION,
    MW_SESSION,
    MW_CUSTOM,
} MiddlewareType;

typedef struct {
    MiddlewareType type;
    char   name[64];
    int    enabled;
    int  (*before)(HttpRequest *req, HttpResponse *resp);
    void (*after)(HttpRequest *req, HttpResponse *resp);
    Value  callback_func;      /* MW_USER_CALLBACK 用 */
    char   path[HW_MAX_PATH];  /* パス限定ミドルウェア (v5.0) */
    int    has_path;           /* パス指定あり */
} Middleware;

typedef struct {
    HttpMethod method;
    char       pattern[HW_MAX_PATH];
    int        has_static_response;
    int        static_status;
    char       static_content_type[128];
    char      *static_body;
    int        static_body_len;
    Value    (*c_handler)(const HttpRequest *req);
    int        is_wildcard;
    int        has_callback;       /* はじむ関数コールバック */
    Value      callback_func;      /* VALUE_FUNCTION */
} Route;

typedef struct {
    int   status_code;
    char  content_type[128];
    char *body;
    int   body_len;
} ErrorHandler;

typedef struct {
    char prefix[HW_MAX_PATH];
    int  active;
} RouteGroup;

typedef struct {
    char key[256];
    char value[HW_MAX_HEADER_VALUE];
} TemplateVar;

typedef struct {
    char   id[HW_SESSION_ID_LEN];
    KVPair vars[HW_SESSION_MAX_VARS];
    int    var_count;
    time_t created;
    time_t last_access;
    int    active;
} Session;

typedef struct {
    socket_t fd;
    int      active;
    char     path[HW_MAX_PATH];
} SSEClient;

typedef struct {
    socket_t      listen_fd;
    int           port;
    int           running;
    Route         routes[HW_MAX_ROUTES];
    int           route_count;
    Middleware    middlewares[HW_MAX_MIDDLEWARES];
    int           middleware_count;
    ErrorHandler  error_handlers[HW_MAX_ERROR_HANDLERS];
    int           error_handler_count;
    RouteGroup    groups[HW_MAX_GROUPS];
    int           group_count;
    int           active_group;
    char          template_dir[HW_MAX_PATH];
    TemplateVar   template_globals[HW_MAX_TEMPLATE_VARS];
    int           template_global_count;
    char          static_dir[HW_MAX_PATH];
    int           static_cache_seconds;
    int           static_etag;
    int           cors_enabled;
    char          cors_origin[512];
    char          cors_methods[256];
    char          cors_headers[256];
    long long     total_requests;
    long long     error_count;
    /* リクエスト処理中のレスポンスコンテキスト */
    HttpResponse *current_resp;
    socket_t      current_fd;
    /* レートリミッタ設定 */
    int           rate_limit_max;     /* ウィンドウあたり最大リクエスト数 */
    int           rate_limit_window;  /* 秒 */
    struct {
        char ip[64];
        int  count;
        time_t window_start;
    } rate_table[256];
    int           rate_table_count;
    /* セッション管理 */
    Session       sessions[HW_MAX_SESSIONS];
    int           session_count;
    int           session_timeout;       /* 秒 (default 1800) */
    int           session_enabled;
    char          current_session_id[HW_SESSION_ID_LEN];
    /* エラーハンドラコールバック (v5.0: 配列) */
    Value         error_callbacks[HW_MAX_ERROR_CALLBACKS];
    int           error_callback_count;
    /* SSE */
    SSEClient     sse_clients[HW_MAX_SSE_CLIENTS];
    int           sse_client_count;
    pthread_mutex_t sse_mutex;
    /* Keep-Alive */
    int           keep_alive_enabled;
    int           keep_alive_timeout;    /* 秒 */
    int           keep_alive_max_requests;
    /* 圧縮 */
    int           compression_enabled;
    int           compression_min_size;  /* バイト (default 1024) */
    /* HTTPS */
    int           tls_enabled;
    char          tls_cert_path[HW_MAX_PATH];
    char          tls_key_path[HW_MAX_PATH];
    /* アップロード */
    char          upload_dir[HW_MAX_PATH];
    int           upload_max_size;
    /* 現在のリクエスト参照 */
    HttpRequest  *current_req;
    /* v5.0: スレッドプール */
    int           max_threads;
    int           active_threads;
    pthread_mutex_t thread_mutex;
    /* v5.0: コールバック保護 */
    pthread_mutex_t callback_mutex;
    /* v5.0: Trust Proxy */
    int           trust_proxy;
    /* v5.0: 複数静的ファイルディレクトリ */
    char          static_dirs_extra[HW_MAX_STATIC_DIRS][HW_MAX_PATH];
    int           static_dir_extra_count;
    /* v5.0: ディレクトリ一覧 */
    int           directory_listing;
    /* v5.0: チャンク転送状態 */
    int           chunked_started;
} WebServer;

static WebServer g_server = {0};
static volatile int g_shutdown = 0;

/* v5.0: スレッドプール用構造体 */
typedef struct {
    socket_t fd;
    struct sockaddr_in addr;
} ClientThreadArg;

static void handle_client(socket_t client_fd, struct sockaddr_in *addr);

static void *client_thread_func(void *arg) {
    ClientThreadArg *ca = (ClientThreadArg *)arg;
    handle_client(ca->fd, &ca->addr);
    free(ca);
    pthread_mutex_lock(&g_server.thread_mutex);
    g_server.active_threads--;
    pthread_mutex_unlock(&g_server.thread_mutex);
    return NULL;
}


/* ================================================================= */
/* ユーティリティ                                                     */
/* ================================================================= */

static const char *method_to_string(HttpMethod m) {
    switch (m) {
        case METHOD_GET:     return "GET";
        case METHOD_POST:    return "POST";
        case METHOD_PUT:     return "PUT";
        case METHOD_DELETE:  return "DELETE";
        case METHOD_PATCH:   return "PATCH";
        case METHOD_OPTIONS: return "OPTIONS";
        case METHOD_HEAD:    return "HEAD";
        case METHOD_ALL:     return "ALL";
        default:             return "UNKNOWN";
    }
}

static HttpMethod string_to_method(const char *s) {
    if (strcmp(s, "GET")     == 0) return METHOD_GET;
    if (strcmp(s, "POST")    == 0) return METHOD_POST;
    if (strcmp(s, "PUT")     == 0) return METHOD_PUT;
    if (strcmp(s, "DELETE")  == 0) return METHOD_DELETE;
    if (strcmp(s, "PATCH")   == 0) return METHOD_PATCH;
    if (strcmp(s, "OPTIONS") == 0) return METHOD_OPTIONS;
    if (strcmp(s, "HEAD")    == 0) return METHOD_HEAD;
    if (strcmp(s, "ALL") == 0 || strcmp(s, "*") == 0) return METHOD_ALL;
    return METHOD_UNKNOWN;
}

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

static int parse_query_string(const char *qs, KVPair *out, int max) {
    if (!qs || !*qs) return 0;
    int count = 0;
    char buf[HW_MAX_PATH];
    snprintf(buf, sizeof(buf), "%s", qs);
    char *saveptr = NULL;
    char *pair = strtok_r(buf, "&", &saveptr);
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
        pair = strtok_r(NULL, "&", &saveptr);
    }
    return count;
}

static int parse_cookies(const char *cookie_str, KVPair *out, int max) {
    if (!cookie_str || !*cookie_str) return 0;
    int count = 0;
    char buf[HW_MAX_HEADER_VALUE];
    snprintf(buf, sizeof(buf), "%s", cookie_str);
    char *saveptr = NULL;
    char *pair = strtok_r(buf, ";", &saveptr);
    while (pair && count < max) {
        while (*pair == ' ') pair++;
        char *eq = strchr(pair, '=');
        if (eq) {
            *eq = '\0';
            snprintf(out[count].key, sizeof(out[count].key), "%s", pair);
            snprintf(out[count].value, sizeof(out[count].value), "%s", eq + 1);
            count++;
        }
        pair = strtok_r(NULL, ";", &saveptr);
    }
    return count;
}

static const char *get_header(const HttpRequest *req, const char *name) {
    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].key, name) == 0)
            return req->headers[i].value;
    }
    return NULL;
}

/* ================================================================= */
/* MIME タイプ（50種+対応）                                            */
/* ================================================================= */

typedef struct { const char *ext; const char *mime; } MimeEntry;

static const MimeEntry MIME_TABLE[] = {
    {"html",  "text/html; charset=utf-8"},
    {"htm",   "text/html; charset=utf-8"},
    {"css",   "text/css; charset=utf-8"},
    {"js",    "application/javascript; charset=utf-8"},
    {"mjs",   "application/javascript; charset=utf-8"},
    {"json",  "application/json; charset=utf-8"},
    {"xml",   "application/xml; charset=utf-8"},
    {"txt",   "text/plain; charset=utf-8"},
    {"csv",   "text/csv; charset=utf-8"},
    {"md",    "text/markdown; charset=utf-8"},
    {"yaml",  "text/yaml; charset=utf-8"},
    {"yml",   "text/yaml; charset=utf-8"},
    {"ics",   "text/calendar"},
    {"png",   "image/png"},
    {"jpg",   "image/jpeg"},
    {"jpeg",  "image/jpeg"},
    {"gif",   "image/gif"},
    {"svg",   "image/svg+xml"},
    {"ico",   "image/x-icon"},
    {"webp",  "image/webp"},
    {"avif",  "image/avif"},
    {"bmp",   "image/bmp"},
    {"tiff",  "image/tiff"},
    {"tif",   "image/tiff"},
    {"woff",  "font/woff"},
    {"woff2", "font/woff2"},
    {"ttf",   "font/ttf"},
    {"otf",   "font/otf"},
    {"eot",   "application/vnd.ms-fontobject"},
    {"pdf",   "application/pdf"},
    {"doc",   "application/msword"},
    {"docx",  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"xls",   "application/vnd.ms-excel"},
    {"xlsx",  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"ppt",   "application/vnd.ms-powerpoint"},
    {"pptx",  "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"zip",   "application/zip"},
    {"gz",    "application/gzip"},
    {"tar",   "application/x-tar"},
    {"7z",    "application/x-7z-compressed"},
    {"rar",   "application/x-rar-compressed"},
    {"mp3",   "audio/mpeg"},
    {"mp4",   "video/mp4"},
    {"webm",  "video/webm"},
    {"ogg",   "audio/ogg"},
    {"wav",   "audio/wav"},
    {"avi",   "video/x-msvideo"},
    {"mkv",   "video/x-matroska"},
    {"flac",  "audio/flac"},
    {"wasm",  "application/wasm"},
    {"map",   "application/json"},
    {"swf",   "application/x-shockwave-flash"},
    {"bin",   "application/octet-stream"},
    {NULL, NULL}
};

static const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    ext++;
    for (int i = 0; MIME_TABLE[i].ext; i++) {
        if (strcasecmp(ext, MIME_TABLE[i].ext) == 0)
            return MIME_TABLE[i].mime;
    }
    return "application/octet-stream";
}

static void get_http_date(char *buf, int buf_size) {
    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);
    strftime(buf, buf_size, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}

static void generate_etag(const char *filepath, long file_size,
                          char *etag, int etag_size) {
    struct stat st;
    if (stat(filepath, &st) == 0) {
        snprintf(etag, etag_size, "\"%lx-%lx\"",
                 (unsigned long)st.st_mtime, (unsigned long)file_size);
    } else {
        snprintf(etag, etag_size, "\"%lx\"", (unsigned long)file_size);
    }
}

/* ================================================================= */
/* HTTP パーサー                                                      */
/* ================================================================= */

static int parse_http_request(const char *raw, int raw_len, HttpRequest *req) {
    memset(req, 0, sizeof(*req));

    const char *line_end = strstr(raw, "\r\n");
    if (!line_end) return -1;

    char request_line[HW_MAX_PATH];
    int line_len = (int)(line_end - raw);
    if (line_len >= (int)sizeof(request_line)) return -1;
    memcpy(request_line, raw, line_len);
    request_line[line_len] = '\0';

    char method_str[16] = {0};
    char full_path[HW_MAX_PATH] = {0};
    if (sscanf(request_line, "%15s %2047s %15s",
               method_str, full_path, req->http_version) != 3)
        return -1;

    req->method = string_to_method(method_str);

    char *qmark = strchr(full_path, '?');
    if (qmark) {
        *qmark = '\0';
        snprintf(req->raw_query, sizeof(req->raw_query), "%s", qmark + 1);
        req->query_count = parse_query_string(
            req->raw_query, req->query, HW_MAX_QUERY_PARAMS);
    }
    url_decode(full_path, req->path, sizeof(req->path));

    /* ヘッダー解析 */
    const char *hp = line_end + 2;
    while (hp < raw + raw_len) {
        const char *he = strstr(hp, "\r\n");
        if (!he) break;
        if (he == hp) { hp = he + 2; break; }
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
                    snprintf(req->headers[req->header_count].key,
                             256, "%s", hbuf);
                    snprintf(req->headers[req->header_count].value,
                             HW_MAX_HEADER_VALUE, "%s", val);
                    req->header_count++;
                }
            }
        }
        hp = he + 2;
    }

    /* ボディ取得 */
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

    /* Cookie 解析 */
    const char *cookie_hdr = get_header(req, "Cookie");
    if (cookie_hdr) {
        req->cookie_count = parse_cookies(
            cookie_hdr, req->cookies, HW_MAX_QUERY_PARAMS);
    }
    return 0;
}

/* ================================================================= */
/* リクエストボディ自動解析                                            */
/* ================================================================= */

static void auto_parse_body(HttpRequest *req) {
    req->parsed_body.type = BODY_NONE;
    req->parsed_body.raw = req->body;
    req->parsed_body.raw_length = req->body_length;
    req->parsed_body.field_count = 0;

    if (!req->body || req->body_length == 0) return;

    const char *ct = get_header(req, "Content-Type");
    if (!ct) {
        /* Content-Type 未指定の場合、先頭文字で推測 */
        if (req->body[0] == '{' || req->body[0] == '[')
            req->parsed_body.type = BODY_JSON;
        else
            req->parsed_body.type = BODY_TEXT;
        return;
    }

    if (strstr(ct, "application/json") || strstr(ct, "text/json")) {
        req->parsed_body.type = BODY_JSON;
    } else if (strstr(ct, "application/x-www-form-urlencoded")) {
        req->parsed_body.type = BODY_FORM;
        req->parsed_body.field_count = parse_query_string(
            req->body, req->parsed_body.fields, HW_MAX_QUERY_PARAMS);
    } else {
        req->parsed_body.type = BODY_TEXT;
    }
}



/* ================================================================= */
/* セッション管理                                                      */
/* ================================================================= */

static void generate_session_id(char *id, int size) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static int seeded = 0;
    if (!seeded) { srand((unsigned)time(NULL) ^ (unsigned)getpid()); seeded = 1; }
    for (int i = 0; i < size - 1; i++)
        id[i] = charset[rand() % (sizeof(charset) - 1)];
    id[size - 1] = '\0';
}

static Session *find_session(const char *id) {
    if (!id || !id[0]) return NULL;
    for (int i = 0; i < g_server.session_count; i++) {
        if (g_server.sessions[i].active &&
            strcmp(g_server.sessions[i].id, id) == 0) {
            g_server.sessions[i].last_access = time(NULL);
            return &g_server.sessions[i];
        }
    }
    return NULL;
}

static Session *create_session(void) {
    time_t now = time(NULL);
    int timeout = g_server.session_timeout > 0
                  ? g_server.session_timeout : 1800;
    /* 期限切れセッションを回収 */
    for (int i = 0; i < g_server.session_count; i++) {
        if (g_server.sessions[i].active &&
            (now - g_server.sessions[i].last_access) > timeout)
            g_server.sessions[i].active = 0;
    }
    /* 空きスロット検索 */
    Session *s = NULL;
    for (int i = 0; i < g_server.session_count; i++) {
        if (!g_server.sessions[i].active) { s = &g_server.sessions[i]; break; }
    }
    if (!s && g_server.session_count < HW_MAX_SESSIONS)
        s = &g_server.sessions[g_server.session_count++];
    if (!s) return NULL;
    memset(s, 0, sizeof(*s));
    generate_session_id(s->id, HW_SESSION_ID_LEN);
    s->created = now;
    s->last_access = now;
    s->active = 1;
    return s;
}

static const char *session_get_var(Session *s, const char *key) {
    if (!s) return NULL;
    for (int i = 0; i < s->var_count; i++)
        if (strcmp(s->vars[i].key, key) == 0) return s->vars[i].value;
    return NULL;
}

static int session_set_var(Session *s, const char *key, const char *val) {
    if (!s) return 0;
    for (int i = 0; i < s->var_count; i++) {
        if (strcmp(s->vars[i].key, key) == 0) {
            snprintf(s->vars[i].value, HW_MAX_HEADER_VALUE, "%s", val);
            return 1;
        }
    }
    if (s->var_count >= HW_SESSION_MAX_VARS) return 0;
    snprintf(s->vars[s->var_count].key, 256, "%s", key);
    snprintf(s->vars[s->var_count].value, HW_MAX_HEADER_VALUE, "%s", val);
    s->var_count++;
    return 1;
}

static int session_delete_var(Session *s, const char *key) {
    if (!s) return 0;
    for (int i = 0; i < s->var_count; i++) {
        if (strcmp(s->vars[i].key, key) == 0) {
            for (int j = i; j < s->var_count - 1; j++)
                s->vars[j] = s->vars[j + 1];
            s->var_count--;
            return 1;
        }
    }
    return 0;
}

/* ================================================================= */
/* マルチパート解析（ファイルアップロード）                              */
/* ================================================================= */

static void parse_multipart_body(HttpRequest *req) {
    const char *ct = get_header(req, "Content-Type");
    if (!ct || !strstr(ct, "multipart/form-data")) return;

    const char *bstr = strstr(ct, "boundary=");
    if (!bstr) return;
    bstr += 9;

    char boundary[256];
    snprintf(boundary, sizeof(boundary), "--%s", bstr);
    char *bp = boundary + strlen(boundary) - 1;
    while (bp > boundary && (*bp == ' ' || *bp == ';' || *bp == '\r' || *bp == '\n'))
        *bp-- = '\0';
    int blen = (int)strlen(boundary);

    const char *p   = req->body;
    const char *end = req->body + req->body_length;

    while (p < end && req->upload_count < HW_MAX_UPLOADS) {
        const char *bs = strstr(p, boundary);
        if (!bs) break;
        bs += blen;
        if (*bs == '-' && *(bs+1) == '-') break;       /* 終端 */
        if (*bs == '\r') bs++;
        if (*bs == '\n') bs++;

        const char *hend = strstr(bs, "\r\n\r\n");
        if (!hend) break;

        char ph[4096];
        int hsize = (int)(hend - bs);
        if (hsize >= (int)sizeof(ph)) { p = hend + 4; continue; }
        memcpy(ph, bs, hsize);
        ph[hsize] = '\0';

        UploadedFile *uf = &req->uploads[req->upload_count];
        memset(uf, 0, sizeof(*uf));

        char *disp = strstr(ph, "Content-Disposition:");
        if (disp) {
            char *ns = strstr(disp, "name=\"");
            if (ns) {
                ns += 6;
                char *ne = strchr(ns, '"');
                if (ne) { int n = (int)(ne-ns); if(n>255)n=255;
                    memcpy(uf->field_name, ns, n); uf->field_name[n]='\0'; }
            }
            char *fs = strstr(disp, "filename=\"");
            if (fs) {
                fs += 10;
                char *fe = strchr(fs, '"');
                if (fe) { int n = (int)(fe-fs); if(n>255)n=255;
                    memcpy(uf->filename, fs, n); uf->filename[n]='\0'; }
            }
        }
        char *cts = strstr(ph, "Content-Type:");
        if (cts) {
            cts += 13; while (*cts == ' ') cts++;
            char *cte = strstr(cts, "\r\n");
            if (!cte) cte = ph + hsize;
            int n = (int)(cte-cts); if(n>127)n=127;
            memcpy(uf->content_type, cts, n); uf->content_type[n]='\0';
        }

        const char *ds = hend + 4;
        const char *de = strstr(ds, boundary);
        if (!de) break;
        if (de >= ds + 2 && *(de-1)=='\n' && *(de-2)=='\r') de -= 2;
        int dlen = (int)(de - ds);
        uf->data = (char *)malloc(dlen + 1);
        if (uf->data) {
            memcpy(uf->data, ds, dlen);
            uf->data[dlen] = '\0';
            uf->data_len = dlen;
        }
        req->upload_count++;
        p = de;
    }
}

/* ================================================================= */
/* gzip 圧縮                                                          */
/* ================================================================= */

static int gzip_compress(const char *input, int input_len,
                         char **output, int *output_len) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return 0;
    int max_out = deflateBound(&strm, input_len);
    *output = (char *)malloc(max_out);
    if (!*output) { deflateEnd(&strm); return 0; }
    strm.next_in  = (Bytef *)input;
    strm.avail_in = input_len;
    strm.next_out = (Bytef *)*output;
    strm.avail_out = max_out;
    if (deflate(&strm, Z_FINISH) != Z_STREAM_END) {
        free(*output); *output = NULL; deflateEnd(&strm); return 0;
    }
    *output_len = (int)strm.total_out;
    deflateEnd(&strm);
    return 1;
}

static int should_compress(const HttpRequest *req, const HttpResponse *resp) {
    if (!g_server.compression_enabled) return 0;
    int min_sz = g_server.compression_min_size > 0
                 ? g_server.compression_min_size : 1024;
    if (!resp->body || resp->body_length < min_sz) return 0;
    const char *ae = get_header(req, "Accept-Encoding");
    if (!ae || !strstr(ae, "gzip")) return 0;
    if (strstr(resp->content_type, "text/") ||
        strstr(resp->content_type, "application/json") ||
        strstr(resp->content_type, "application/javascript") ||
        strstr(resp->content_type, "application/xml"))
        return 1;
    return 0;
}

/* ================================================================= */
/* SSE（Server-Sent Events）                                          */
/* ================================================================= */

typedef struct {
    socket_t fd;
    Value callback_func;
    char path[HW_MAX_PATH];
} SSEThreadArg;

static void *sse_client_thread(void *arg) {
    SSEThreadArg *sa = (SSEThreadArg *)arg;
    int slot = -1;

    pthread_mutex_lock(&g_server.sse_mutex);
    for (int i = 0; i < HW_MAX_SSE_CLIENTS; i++) {
        if (!g_server.sse_clients[i].active) {
            g_server.sse_clients[i].fd = sa->fd;
            g_server.sse_clients[i].active = 1;
            snprintf(g_server.sse_clients[i].path, HW_MAX_PATH, "%s", sa->path);
            slot = i;
            break;
        }
    }
    pthread_mutex_unlock(&g_server.sse_mutex);

    if (slot < 0) { close_socket(sa->fd); free(sa); return NULL; }

    const char *hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n";
    send(sa->fd, hdr, (int)strlen(hdr), 0);

    if (hajimu_runtime_available() &&
        (sa->callback_func.type == VALUE_FUNCTION ||
         sa->callback_func.type == VALUE_BUILTIN)) {
        Value ev = hajimu_string("connected");
        hajimu_call(&sa->callback_func, 1, &ev);
    }

    char buf[1];
    while (!g_shutdown && g_server.sse_clients[slot].active) {
        struct timeval tv = {2, 0};
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sa->fd, &fds);
        int sel = select(sa->fd + 1, &fds, NULL, NULL, &tv);
        if (sel > 0) {
            int n = (int)recv(sa->fd, buf, 1, 0);
            if (n <= 0) break;
        }
    }

    pthread_mutex_lock(&g_server.sse_mutex);
    g_server.sse_clients[slot].active = 0;
    pthread_mutex_unlock(&g_server.sse_mutex);
    close_socket(sa->fd);
    free(sa);
    return NULL;
}

static void sse_send_to_path(const char *path, const char *event,
                              const char *data) {
    char msg[HW_MAX_HEADER_VALUE];
    int mlen;
    if (event && event[0])
        mlen = snprintf(msg, sizeof(msg), "event: %s\ndata: %s\n\n", event, data);
    else
        mlen = snprintf(msg, sizeof(msg), "data: %s\n\n", data);

    pthread_mutex_lock(&g_server.sse_mutex);
    for (int i = 0; i < HW_MAX_SSE_CLIENTS; i++) {
        if (g_server.sse_clients[i].active) {
            if (!path || !path[0] ||
                strcmp(g_server.sse_clients[i].path, path) == 0) {
                int n = (int)send(g_server.sse_clients[i].fd, msg, mlen, 0);
                if (n <= 0) g_server.sse_clients[i].active = 0;
            }
        }
    }
    pthread_mutex_unlock(&g_server.sse_mutex);
}

/* ================================================================= */
/* ルーティング                                                       */
/* ================================================================= */

static int match_route(const Route *route, const char *path,
                       KVPair *params, int *param_count) {
    *param_count = 0;
    const char *pattern = route->pattern;

    /* ワイルドカードルート */
    if (route->is_wildcard) {
        int plen = (int)strlen(pattern);
        if (plen >= 2 && pattern[plen-1] == '*' && pattern[plen-2] == '/') {
            if (strncmp(pattern, path, plen - 1) == 0) return 1;
            if (strncmp(pattern, path, plen - 2) == 0 &&
                (int)strlen(path) == plen - 2) return 1;
        }
        return 0;
    }

    /* 完全一致 */
    if (strcmp(pattern, path) == 0) return 1;

    /* パラメータ付きルート :param / :param? (v5.0 オプショナル対応) */
    const char *pp = pattern;
    const char *rp = path;
    while (*pp && *rp) {
        if (*pp == ':') {
            pp++;
            char param_name[256] = {0};
            int ni = 0;
            while (*pp && *pp != '/' && *pp != '?' && ni < 255)
                param_name[ni++] = *pp++;
            param_name[ni] = '\0';
            int optional = (*pp == '?');
            if (optional) pp++;

            char param_val[HW_MAX_HEADER_VALUE] = {0};
            int vi = 0;
            while (*rp && *rp != '/' && vi < HW_MAX_HEADER_VALUE - 1)
                param_val[vi++] = *rp++;
            param_val[vi] = '\0';

            if (*param_count < HW_MAX_PARAMS) {
                snprintf(params[*param_count].key, 256, "%s", param_name);
                snprintf(params[*param_count].value,
                         HW_MAX_HEADER_VALUE, "%s", param_val);
                (*param_count)++;
            }
        } else {
            if (*pp != *rp) return 0;
            pp++;
            rp++;
        }
    }
    /* 残りパターンがオプショナルパラメータのみなら一致 */
    while (*pp == '/' || *pp == ':') {
        if (*pp == '/') pp++;
        if (*pp == ':') {
            pp++;
            while (*pp && *pp != '/' && *pp != '?') pp++;
            if (*pp == '?') { pp++; continue; }
            else return 0; /* 非オプショナル未充足 */
        }
    }
    return (*pp == '\0' && *rp == '\0');
}

static Route *find_route(HttpMethod method, const char *path,
                         HttpRequest *req) {
    /* パス 0: 通常ルート、パス 1: ワイルドカード */
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < g_server.route_count; i++) {
            Route *r = &g_server.routes[i];
            if (r->method != method && r->method != METHOD_ALL) continue;
            if (pass == 0 && r->is_wildcard) continue;
            if (pass == 1 && !r->is_wildcard) continue;

            KVPair params[HW_MAX_PARAMS];
            int param_count = 0;
            if (match_route(r, path, params, &param_count)) {
                for (int j = 0;
                     j < param_count && req->param_count < HW_MAX_PARAMS;
                     j++) {
                    req->params[req->param_count] = params[j];
                    req->param_count++;
                }
                return r;
            }
        }
    }
    return NULL;
}

/* ================================================================= */
/* レスポンスビルダー                                                  */
/* ================================================================= */

static void response_init(HttpResponse *resp) {
    memset(resp, 0, sizeof(*resp));
    resp->status_code = 200;
    snprintf(resp->content_type, sizeof(resp->content_type),
             "text/html; charset=utf-8");
}

static void response_set_header(HttpResponse *resp,
                                const char *key, const char *value) {
    if (resp->header_count >= HW_MAX_RESP_HEADERS) return;
    snprintf(resp->headers[resp->header_count].key, 256, "%s", key);
    snprintf(resp->headers[resp->header_count].value,
             HW_MAX_HEADER_VALUE, "%s", value);
    resp->header_count++;
}

static void response_set_body(HttpResponse *resp,
                              const char *body, int length) {
    if (resp->body) free(resp->body);
    resp->body = (char *)malloc(length + 1);
    if (resp->body) {
        memcpy(resp->body, body, length);
        resp->body[length] = '\0';
        resp->body_length = length;
    }
}

static const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 422: return "Unprocessable Entity";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default:  return "OK";
    }
}

static void send_response_obj(socket_t fd, HttpResponse *resp) {
    if (resp->sent) return;
    resp->sent = 1;

    char date[64];
    get_http_date(date, sizeof(date));

    char header[4096];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Date: %s\r\n"
        "Server: hajimu_web/5.0.0\r\n"
        "Connection: %s\r\n",
        resp->status_code, status_text(resp->status_code),
        resp->content_type, resp->body_length, date,
        g_server.keep_alive_enabled ? "keep-alive" : "close");

    for (int i = 0; i < resp->header_count; i++) {
        hlen += snprintf(header + hlen, sizeof(header) - hlen,
            "%s: %s\r\n", resp->headers[i].key, resp->headers[i].value);
    }
    hlen += snprintf(header + hlen, sizeof(header) - hlen, "\r\n");

    send(fd, header, hlen, 0);
    if (resp->body && resp->body_length > 0)
        send(fd, resp->body, resp->body_length, 0);
}

static void send_response(socket_t fd, int status_code,
                          const char *content_type,
                          const char *body, int body_len) {
    HttpResponse resp;
    response_init(&resp);
    resp.status_code = status_code;
    snprintf(resp.content_type, sizeof(resp.content_type),
             "%s", content_type);
    response_set_body(&resp, body, body_len);

    if (g_server.cors_enabled) {
        response_set_header(&resp, "Access-Control-Allow-Origin",
            g_server.cors_origin[0] ? g_server.cors_origin : "*");
        response_set_header(&resp, "Access-Control-Allow-Methods",
            g_server.cors_methods[0] ? g_server.cors_methods
            : "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        response_set_header(&resp, "Access-Control-Allow-Headers",
            g_server.cors_headers[0] ? g_server.cors_headers
            : "Content-Type, Authorization, X-Requested-With");
    }

    send_response_obj(fd, &resp);
    if (resp.body) free(resp.body);
}

/* ================================================================= */
/* エラーハンドリング                                                  */
/* ================================================================= */

static void default_error_page(int status_code, char *buf, int buf_size) {
    const char *emoji = "?";
    switch (status_code) {
        case 400: emoji = "X"; break;
        case 401: emoji = "L"; break;
        case 403: emoji = "!"; break;
        case 404: emoji = "?"; break;
        case 405: emoji = "#"; break;
        case 408: emoji = "T"; break;
        case 413: emoji = "B"; break;
        case 429: emoji = "S"; break;
        case 500: emoji = "E"; break;
        case 502: emoji = "G"; break;
        case 503: emoji = "M"; break;
        default:  emoji = "X"; break;
    }
    snprintf(buf, buf_size,
        "<!DOCTYPE html>\n"
        "<html lang=\"ja\">\n"
        "<head><meta charset=\"utf-8\"><title>%d %s</title>\n"
        "<style>body{font-family:sans-serif;text-align:center;"
        "padding:50px;background:#f8f9fa;}"
        "h1{font-size:72px;margin:0;}h2{color:#333;margin:10px 0;}"
        "p{color:#666;font-size:18px;}"
        ".container{max-width:600px;margin:0 auto;}"
        "a{color:#007bff;text-decoration:none;}"
        "a:hover{text-decoration:underline;}"
        ".code{font-size:120px;color:#dee2e6;font-weight:bold;"
        "margin:20px 0;}</style></head>\n"
        "<body><div class=\"container\">\n"
        "<div class=\"code\">%d</div>\n"
        "<h1>%s</h1>\n"
        "<h2>%s</h2>\n"
        "<p>hajimu_web server</p>\n"
        "<p><a href=\"/\">top page</a></p>\n"
        "</div></body></html>\n",
        status_code, status_text(status_code),
        status_code, emoji, status_text(status_code));
}

/* 前方宣言 */
static Value request_to_value(const HttpRequest *req);

static void send_error(socket_t fd, int status_code, const char *message) {
    /* コールバックエラーハンドラ (v5.0: 配列チェーン) */
    if (g_server.error_callback_count > 0 && hajimu_runtime_available()) {
        Value args[3];
        args[0] = hajimu_number(status_code);
        args[1] = hajimu_string(message ? message : status_text(status_code));
        args[2] = g_server.current_req
                  ? request_to_value(g_server.current_req)
                  : hajimu_null();
        for (int ei = 0; ei < g_server.error_callback_count; ei++) {
            pthread_mutex_lock(&g_server.callback_mutex);
            Value result = hajimu_call(&g_server.error_callbacks[ei], 3, args);
            pthread_mutex_unlock(&g_server.callback_mutex);
            if (result.type == VALUE_STRING) {
                send_response(fd, status_code,
                    "text/html; charset=utf-8",
                    result.string.data, result.string.length);
                __sync_fetch_and_add(&g_server.error_count, 1);
                return;
            }
            /* 文字列以外 → 次のハンドラへ (next() 相当) */
        }
    }

    /* カスタムエラーハンドラを検索 */
    for (int i = 0; i < g_server.error_handler_count; i++) {
        ErrorHandler *eh = &g_server.error_handlers[i];
        if (eh->status_code == status_code || eh->status_code == 0) {
            send_response(fd, status_code,
                          eh->content_type, eh->body, eh->body_len);
            __sync_fetch_and_add(&g_server.error_count, 1);
            return;
        }
    }

    if (message) {
        /* JSON 形式のエラーレスポンス */
        char json_buf[1024];
        int json_len = snprintf(json_buf, sizeof(json_buf),
            "{\"error\":{\"code\":%d,\"message\":\"%s\",\"status\":\"%s\"}}",
            status_code, message, status_text(status_code));
        send_response(fd, status_code,
                      "application/json; charset=utf-8",
                      json_buf, json_len);
    } else {
        /* HTML 形式のデフォルトエラーページ */
        char html_buf[4096];
        default_error_page(status_code, html_buf, sizeof(html_buf));
        send_response(fd, status_code,
                      "text/html; charset=utf-8",
                      html_buf, (int)strlen(html_buf));
    }
    __sync_fetch_and_add(&g_server.error_count, 1);
}

/* ================================================================= */
/* テンプレートエンジン                                                */
/* ================================================================= */

static const char *template_get_var(const TemplateVar *vars, int count,
                                    const char *key) {
    for (int i = 0; i < count; i++) {
        if (strcmp(vars[i].key, key) == 0) return vars[i].value;
    }
    for (int i = 0; i < g_server.template_global_count; i++) {
        if (strcmp(g_server.template_globals[i].key, key) == 0)
            return g_server.template_globals[i].value;
    }
    return NULL;
}

/*
 * テンプレート文字列を展開する
 *   {{var}}                     -> HTML エスケープ付き変数展開
 *   {{!var}}                    -> エスケープなし変数展開
 *   {{#moshi var}}...{{/moshi}} -> 条件分岐
 *   {{#moshi !var}}...{{/moshi}}-> 否定条件
 *   {{#kaku var}}...{{genzai}}...{{/kaku}} -> ループ (カンマ区切り)
 *   {{-- comment --}}           -> コメント (出力なし)
 */
static int template_render(const char *tmpl, const TemplateVar *vars,
                           int var_count, char *output, int output_size) {
    int oi = 0, ti = 0;
    int tmpl_len = (int)strlen(tmpl);

    while (ti < tmpl_len && oi < output_size - 1) {
        if (ti < tmpl_len - 1 &&
            tmpl[ti] == '{' && tmpl[ti + 1] == '{') {

            const char *end = strstr(tmpl + ti + 2, "}}");
            if (!end) { output[oi++] = tmpl[ti++]; continue; }

            int tag_len = (int)(end - (tmpl + ti + 2));
            char tag[1024];
            if (tag_len >= (int)sizeof(tag)) tag_len = (int)sizeof(tag) - 1;
            memcpy(tag, tmpl + ti + 2, tag_len);
            tag[tag_len] = '\0';

            /* trim */
            char *tp = tag;
            while (*tp == ' ') tp++;
            char *te = tp + strlen(tp) - 1;
            while (te > tp && *te == ' ') *te-- = '\0';

            if (tp[0] == '-' && tp[1] == '-') {
                /* comment: skip */
            } else if (tp[0] == '#') {
                char *directive = tp + 1;
                while (*directive == ' ') directive++;

                /* Check for "moshi" (condition) or "kaku" (loop)
                 * Also supports Japanese: もし / 各 */
                int is_moshi = (strncmp(directive, "moshi", 5) == 0) ||
                    (strncmp(directive, "\xe3\x82\x82\xe3\x81\x97", 6) == 0);
                int is_kaku = (strncmp(directive, "kaku", 4) == 0) ||
                    (strncmp(directive, "\xe5\x90\x84", 3) == 0);

                if (is_moshi) {
                    /* advance past keyword */
                    char *cond = directive;
                    if (strncmp(cond, "moshi", 5) == 0) cond += 5;
                    else cond += 6; /* もし = 6 bytes */
                    while (*cond == ' ') cond++;

                    int negate = 0;
                    if (*cond == '!') {
                        negate = 1; cond++;
                        while (*cond == ' ') cond++;
                    }

                    const char *val = template_get_var(vars, var_count, cond);
                    int truthy = (val && val[0] &&
                                  strcmp(val, "0") != 0);
                    if (negate) truthy = !truthy;

                    /* find closing tag */
                    const char *close1 = strstr(end + 2, "{{/moshi}}");
                    const char *close2 = strstr(end + 2,
                        "{{/\xe3\x82\x82\xe3\x81\x97}}");
                    const char *close_pos = NULL;
                    int close_tag_len = 0;
                    if (close1 && (!close2 || close1 <= close2)) {
                        close_pos = close1; close_tag_len = 10;
                    } else if (close2) {
                        close_pos = close2; close_tag_len = 12;
                    }

                    if (!close_pos) {
                        ti = (int)(end - tmpl) + 2;
                        continue;
                    }

                    if (truthy) {
                        int block_len = (int)(close_pos - (end + 2));
                        char *block = (char *)malloc(block_len + 1);
                        memcpy(block, end + 2, block_len);
                        block[block_len] = '\0';
                        oi += template_render(block, vars, var_count,
                                              output + oi, output_size - oi);
                        free(block);
                    }
                    ti = (int)(close_pos - tmpl) + close_tag_len;
                    continue;

                } else if (is_kaku) {
                    char *arr_name = directive;
                    if (strncmp(arr_name, "kaku", 4) == 0) arr_name += 4;
                    else arr_name += 3; /* 各 = 3 bytes */
                    while (*arr_name == ' ') arr_name++;

                    const char *close1 = strstr(end + 2, "{{/kaku}}");
                    const char *close2 = strstr(end + 2,
                        "{{/\xe5\x90\x84}}");
                    const char *close_pos = NULL;
                    int close_tag_len = 0;
                    if (close1 && (!close2 || close1 <= close2)) {
                        close_pos = close1; close_tag_len = 9;
                    } else if (close2) {
                        close_pos = close2; close_tag_len = 9;
                    }

                    if (!close_pos) {
                        ti = (int)(end - tmpl) + 2;
                        continue;
                    }

                    int block_len = (int)(close_pos - (end + 2));
                    char *block = (char *)malloc(block_len + 1);
                    memcpy(block, end + 2, block_len);
                    block[block_len] = '\0';

                    const char *arr_val = template_get_var(
                        vars, var_count, arr_name);
                    if (arr_val) {
                        char arr_buf[HW_MAX_HEADER_VALUE];
                        snprintf(arr_buf, sizeof(arr_buf), "%s", arr_val);
                        char *saveptr = NULL;
                        char *item = strtok_r(arr_buf, ",", &saveptr);
                        while (item) {
                            while (*item == ' ') item++;
                            TemplateVar loop_vars[HW_MAX_TEMPLATE_VARS];
                            int lc = var_count < HW_MAX_TEMPLATE_VARS - 1
                                     ? var_count : HW_MAX_TEMPLATE_VARS - 1;
                            for (int vi = 0; vi < lc; vi++)
                                loop_vars[vi] = vars[vi];
                            snprintf(loop_vars[lc].key, 256, "genzai");
                            snprintf(loop_vars[lc].value,
                                     HW_MAX_HEADER_VALUE, "%s", item);
                            lc++;
                            /* also add Japanese alias */
                            if (lc < HW_MAX_TEMPLATE_VARS) {
                                snprintf(loop_vars[lc].key, 256,
                                    "\xe7\x8f\xbe\xe5\x9c\xa8\xe5\x80\xa4");
                                snprintf(loop_vars[lc].value,
                                         HW_MAX_HEADER_VALUE, "%s", item);
                                lc++;
                            }
                            oi += template_render(block, loop_vars, lc,
                                output + oi, output_size - oi);
                            item = strtok_r(NULL, ",", &saveptr);
                        }
                    }
                    free(block);
                    ti = (int)(close_pos - tmpl) + close_tag_len;
                    continue;
                }

            } else if (tp[0] == '/') {
                /* closing tag, skip */
            } else {
                /* variable expansion */
                int raw_output = 0;
                char *var_name = tp;
                if (*var_name == '!') {
                    raw_output = 1; var_name++;
                    while (*var_name == ' ') var_name++;
                }
                const char *val = template_get_var(vars, var_count, var_name);
                if (val) {
                    if (raw_output) {
                        int vlen = (int)strlen(val);
                        if (oi + vlen < output_size - 1) {
                            memcpy(output + oi, val, vlen);
                            oi += vlen;
                        }
                    } else {
                        for (int vi = 0; val[vi] && oi < output_size - 6; vi++) {
                            switch (val[vi]) {
                                case '<':
                                    memcpy(output+oi, "&lt;", 4); oi += 4;
                                    break;
                                case '>':
                                    memcpy(output+oi, "&gt;", 4); oi += 4;
                                    break;
                                case '&':
                                    memcpy(output+oi, "&amp;", 5); oi += 5;
                                    break;
                                case '"':
                                    memcpy(output+oi, "&quot;", 6); oi += 6;
                                    break;
                                default:
                                    output[oi++] = val[vi];
                                    break;
                            }
                        }
                    }
                }
            }
            ti = (int)(end - tmpl) + 2;
        } else {
            output[oi++] = tmpl[ti++];
        }
    }
    output[oi] = '\0';
    return oi;
}

static char *render_template_file(const char *filename,
                                  const TemplateVar *vars, int var_count) {
    char filepath[HW_MAX_PATH];
    if (g_server.template_dir[0])
        snprintf(filepath, sizeof(filepath), "%s/%s",
                 g_server.template_dir, filename);
    else
        snprintf(filepath, sizeof(filepath), "%s", filename);

    FILE *f = fopen(filepath, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > HW_TEMPLATE_BUF) { fclose(f); return NULL; }

    char *tmpl = (char *)malloc(fsize + 1);
    if (!tmpl) { fclose(f); return NULL; }
    fread(tmpl, 1, fsize, f);
    tmpl[fsize] = '\0';
    fclose(f);

    char *output = (char *)malloc(HW_TEMPLATE_BUF);
    if (!output) { free(tmpl); return NULL; }
    template_render(tmpl, vars, var_count, output, HW_TEMPLATE_BUF);
    free(tmpl);
    return output;
}

/* ================================================================= */
/* 静的ファイル配信（強化版）                                          */
/* ================================================================= */

static int try_static_directory(socket_t fd, const HttpRequest *req,
                                const char *static_dir) {
    char filepath[HW_MAX_PATH];
    const char *req_path = req->path;
    if (strcmp(req_path, "/") == 0) req_path = "/index.html";
    snprintf(filepath, sizeof(filepath), "%s%s", static_dir, req_path);

    struct stat st;
    if (stat(filepath, &st) == 0 && S_ISDIR(st.st_mode)) {
        char idx_path[HW_MAX_PATH];
        snprintf(idx_path, sizeof(idx_path), "%s/index.html", filepath);
        if (stat(idx_path, &st) == 0) {
            snprintf(filepath, sizeof(filepath), "%s", idx_path);
        } else if (g_server.directory_listing) {
            /* v5.0: ディレクトリ一覧 */
#ifndef _WIN32
            DIR *d = opendir(filepath);
            if (!d) return 0;
            char html[HW_TEMPLATE_BUF];
            int hi = snprintf(html, sizeof(html),
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
                "<title>%s</title><style>body{font-family:sans-serif;"
                "padding:20px}a{color:#007bff;text-decoration:none}"
                "a:hover{text-decoration:underline}li{margin:4px 0}"
                "</style></head><body><h2>%s</h2><ul>",
                req->path, req->path);
            if (strcmp(req->path, "/") != 0)
                hi += snprintf(html + hi, sizeof(html) - hi,
                    "<li><a href=\"..\">../</a></li>");
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char full[HW_MAX_PATH];
                snprintf(full, sizeof(full), "%s/%s", filepath, ent->d_name);
                struct stat est;
                int is_dir = (stat(full, &est) == 0 && S_ISDIR(est.st_mode));
                hi += snprintf(html + hi, sizeof(html) - hi,
                    "<li><a href=\"%s%s%s\">%s%s</a></li>",
                    req->path,
                    (req->path[strlen(req->path)-1] == '/') ? "" : "/",
                    ent->d_name, ent->d_name, is_dir ? "/" : "");
            }
            closedir(d);
            hi += snprintf(html + hi, sizeof(html) - hi,
                "</ul><hr><p>hajimu_web/5.0.0</p></body></html>");
            send_response(fd, 200, "text/html; charset=utf-8", html, hi);
            return 1;
#endif
        } else {
            return 0;
        }
    }

    FILE *f = fopen(filepath, "rb");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    const char *mime = get_mime_type(filepath);

    /* ETag / 304 判定 */
    char etag[128] = {0};
    if (g_server.static_etag) {
        generate_etag(filepath, file_size, etag, sizeof(etag));
        const char *if_none_match = get_header(req, "If-None-Match");
        if (if_none_match && strcmp(if_none_match, etag) == 0) {
            fclose(f);
            send_response(fd, 304, mime, "", 0);
            return 1;
        }
    }

    /* v5.0: Range リクエスト対応 */
    const char *range_hdr = get_header(req, "Range");
    long range_start = 0, range_end = file_size - 1;
    int is_range = 0;
    if (range_hdr && strncmp(range_hdr, "bytes=", 6) == 0) {
        const char *rp = range_hdr + 6;
        if (*rp == '-') {
            long suffix = strtol(rp + 1, NULL, 10);
            if (suffix > 0 && suffix <= file_size) {
                range_start = file_size - suffix;
                is_range = 1;
            }
        } else {
            char *dash = NULL;
            range_start = strtol(rp, &dash, 10);
            if (dash && *dash == '-') {
                if (*(dash+1) && *(dash+1) != ',')
                    range_end = strtol(dash+1, NULL, 10);
                if (range_start >= 0 && range_start < file_size &&
                    range_end >= range_start && range_end < file_size)
                    is_range = 1;
            }
        }
    }

    char date[64];
    get_http_date(date, sizeof(date));

    char header[2048];
    int hlen;
    if (is_range) {
        long content_len = range_end - range_start + 1;
        hlen = snprintf(header, sizeof(header),
            "HTTP/1.1 206 Partial Content\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n"
            "Content-Range: bytes %ld-%ld/%ld\r\n"
            "Accept-Ranges: bytes\r\n"
            "Date: %s\r\n"
            "Server: hajimu_web/5.0.0\r\n"
            "Connection: %s\r\n",
            mime, content_len, range_start, range_end, file_size,
            date, g_server.keep_alive_enabled ? "keep-alive" : "close");
    } else {
        hlen = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n"
            "Accept-Ranges: bytes\r\n"
            "Date: %s\r\n"
            "Server: hajimu_web/5.0.0\r\n"
            "Connection: %s\r\n",
            mime, file_size, date,
            g_server.keep_alive_enabled ? "keep-alive" : "close");
    }

    if (g_server.static_cache_seconds > 0) {
        hlen += snprintf(header + hlen, sizeof(header) - hlen,
            "Cache-Control: public, max-age=%d\r\n",
            g_server.static_cache_seconds);
    }
    if (etag[0]) {
        hlen += snprintf(header + hlen, sizeof(header) - hlen,
            "ETag: %s\r\n", etag);
    }
    if (g_server.cors_enabled) {
        hlen += snprintf(header + hlen, sizeof(header) - hlen,
            "Access-Control-Allow-Origin: %s\r\n",
            g_server.cors_origin[0] ? g_server.cors_origin : "*");
    }
    for (int i = 0; i < g_server.middleware_count; i++) {
        if (g_server.middlewares[i].type == MW_SECURITY &&
            g_server.middlewares[i].enabled) {
            hlen += snprintf(header + hlen, sizeof(header) - hlen,
                "X-Content-Type-Options: nosniff\r\n"
                "X-Frame-Options: DENY\r\n"
                "X-XSS-Protection: 1; mode=block\r\n");
            break;
        }
    }
    hlen += snprintf(header + hlen, sizeof(header) - hlen, "\r\n");
    send(fd, header, hlen, 0);

    if (is_range) {
        fseek(f, range_start, SEEK_SET);
        long remaining = range_end - range_start + 1;
        char buf[HW_STATIC_BUF];
        while (remaining > 0) {
            size_t to_read = remaining < (long)sizeof(buf)
                           ? (size_t)remaining : sizeof(buf);
            size_t nread = fread(buf, 1, to_read, f);
            if (nread == 0) break;
            send(fd, buf, (int)nread, 0);
            remaining -= (long)nread;
        }
    } else {
        char buf[HW_STATIC_BUF];
        size_t nread;
        while ((nread = fread(buf, 1, sizeof(buf), f)) > 0)
            send(fd, buf, (int)nread, 0);
    }
    fclose(f);
    return 1;
}

static int serve_static_file(socket_t fd, const HttpRequest *req) {
    if (g_server.static_dir[0] == '\0' &&
        g_server.static_dir_extra_count == 0) return 0;
    /* ディレクトリトラバーサル防止 */
    if (strstr(req->path, "..") != NULL) {
        send_error(fd, 403, NULL);
        return 1;
    }
    /* プライマリディレクトリ */
    if (g_server.static_dir[0] && try_static_directory(fd, req, g_server.static_dir))
        return 1;
    /* v5.0: 追加ディレクトリ */
    for (int i = 0; i < g_server.static_dir_extra_count; i++) {
        if (try_static_directory(fd, req, g_server.static_dirs_extra[i]))
            return 1;
    }
    return 0;
}

/* ================================================================= */
/* ミドルウェアチェーン実行                                            */
/* ================================================================= */

static int middleware_logger_before(HttpRequest *req, HttpResponse *resp) {
    (void)resp;
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", lt);
    printf("[%s] %s %s %s\n", time_str,
           method_to_string(req->method), req->path, req->client_ip);
    return 0;
}

static int middleware_cors_before(HttpRequest *req, HttpResponse *resp) {
    (void)req;
    response_set_header(resp, "Access-Control-Allow-Origin",
        g_server.cors_origin[0] ? g_server.cors_origin : "*");
    response_set_header(resp, "Access-Control-Allow-Methods",
        g_server.cors_methods[0] ? g_server.cors_methods
        : "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    response_set_header(resp, "Access-Control-Allow-Headers",
        g_server.cors_headers[0] ? g_server.cors_headers
        : "Content-Type, Authorization, X-Requested-With");
    response_set_header(resp, "Access-Control-Max-Age", "86400");
    return 0;
}

static int middleware_security_before(HttpRequest *req, HttpResponse *resp) {
    (void)req;
    response_set_header(resp, "X-Content-Type-Options", "nosniff");
    response_set_header(resp, "X-Frame-Options", "DENY");
    response_set_header(resp, "X-XSS-Protection", "1; mode=block");
    response_set_header(resp, "Referrer-Policy",
                        "strict-origin-when-cross-origin");
    return 0;
}

static int middleware_rate_limit_before(HttpRequest *req, HttpResponse *resp) {
    if (g_server.rate_limit_max <= 0) return 0;
    time_t now = time(NULL);
    int found = -1;
    for (int i = 0; i < g_server.rate_table_count; i++) {
        if (strcmp(g_server.rate_table[i].ip, req->client_ip) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0) {
        if (g_server.rate_table_count < 256) {
            found = g_server.rate_table_count++;
            snprintf(g_server.rate_table[found].ip,
                     sizeof(g_server.rate_table[found].ip),
                     "%s", req->client_ip);
            g_server.rate_table[found].count = 0;
            g_server.rate_table[found].window_start = now;
        } else {
            return 0; /* テーブル満杯 */
        }
    }
    /* ウィンドウリセット */
    int window = g_server.rate_limit_window > 0
                 ? g_server.rate_limit_window : 60;
    if (now - g_server.rate_table[found].window_start >= window) {
        g_server.rate_table[found].count = 0;
        g_server.rate_table[found].window_start = now;
    }
    g_server.rate_table[found].count++;
    if (g_server.rate_table[found].count > g_server.rate_limit_max) {
        resp->status_code = 429;
        snprintf(resp->content_type, sizeof(resp->content_type),
                 "application/json; charset=utf-8");
        char body[256];
        int blen = snprintf(body, sizeof(body),
            "{\"error\":{\"code\":429,\"message\":\"リクエスト数が制限を超えました\"}}");
        response_set_body(resp, body, blen);
        char retry[32];
        snprintf(retry, sizeof(retry), "%d",
                 (int)(window - (now - g_server.rate_table[found].window_start)));
        response_set_header(resp, "Retry-After", retry);
        return 1; /* 中断 → レスポンス送信 */
    }
    /* X-RateLimit ヘッダー */
    char rl_buf[32];
    snprintf(rl_buf, sizeof(rl_buf), "%d", g_server.rate_limit_max);
    response_set_header(resp, "X-RateLimit-Limit", rl_buf);
    snprintf(rl_buf, sizeof(rl_buf), "%d",
             g_server.rate_limit_max - g_server.rate_table[found].count);
    response_set_header(resp, "X-RateLimit-Remaining", rl_buf);
    return 0;
}

static int run_middlewares_before(HttpRequest *req, HttpResponse *resp) {
    for (int i = 0; i < g_server.middleware_count; i++) {
        Middleware *mw = &g_server.middlewares[i];
        if (!mw->enabled) continue;
        int result = 0;
        switch (mw->type) {
            case MW_LOGGER:     result = middleware_logger_before(req, resp); break;
            case MW_CORS:       result = middleware_cors_before(req, resp); break;
            case MW_SECURITY:   result = middleware_security_before(req, resp); break;
            case MW_RATE_LIMIT: result = middleware_rate_limit_before(req, resp); break;
            case MW_USER_CALLBACK:
                if (hajimu_runtime_available() &&
                    (mw->callback_func.type == VALUE_FUNCTION ||
                     mw->callback_func.type == VALUE_BUILTIN)) {
                    /* v5.0: パス限定チェック */
                    if (mw->has_path &&
                        strncmp(req->path, mw->path, strlen(mw->path)) != 0)
                        break; /* パス不一致 → スキップ */
                    Value req_val = request_to_value(req);
                    pthread_mutex_lock(&g_server.callback_mutex);
                    g_server.current_resp = resp;
                    g_server.current_req = req;
                    Value rv = hajimu_call(&mw->callback_func, 1, &req_val);
                    pthread_mutex_unlock(&g_server.callback_mutex);
                    if (rv.type == VALUE_BOOL && !rv.boolean) result = 1;
                }
                break;
            case MW_COMPRESSION: break; /* after フック側で処理 */
            case MW_SESSION:     break; /* handle_client 側で処理 */
            case MW_CUSTOM:     if (mw->before) result = mw->before(req, resp); break;
            default: break;
        }
        if (result != 0) return 1; /* 中断 */
    }
    return 0;
}

static void run_middlewares_after(HttpRequest *req, HttpResponse *resp) {
    /* after フックは逆順（オニオンモデル） */
    for (int i = g_server.middleware_count - 1; i >= 0; i--) {
        Middleware *mw = &g_server.middlewares[i];
        if (!mw->enabled) continue;
        if (mw->type == MW_CUSTOM && mw->after)
            mw->after(req, resp);
    }
}

/* ================================================================= */
/* リクエスト -> Value 変換                                            */
/* ================================================================= */

static Value request_to_value(const HttpRequest *req) {
    Value arr = hajimu_array();

    /* [0] method */
    hajimu_array_push(&arr, hajimu_string(method_to_string(req->method)));
    /* [1] path */
    hajimu_array_push(&arr, hajimu_string(req->path));
    /* [2] raw_query */
    hajimu_array_push(&arr, hajimu_string(req->raw_query));
    /* [3] body */
    hajimu_array_push(&arr, hajimu_string(req->body ? req->body : ""));
    /* [4] client_ip */
    hajimu_array_push(&arr, hajimu_string(req->client_ip));

    /* [5] headers {key: value, ...} — 辞書型 (v5.0) */
    Value headers;
    memset(&headers, 0, sizeof(headers));
    headers.type = VALUE_DICT;
    if (req->header_count > 0) {
        headers.dict.keys = (char **)calloc(req->header_count, sizeof(char *));
        headers.dict.values = (Value *)calloc(req->header_count, sizeof(Value));
        headers.dict.length = req->header_count;
        headers.dict.capacity = req->header_count;
        for (int i = 0; i < req->header_count; i++) {
            headers.dict.keys[i] = strdup(req->headers[i].key);
            headers.dict.values[i] = hajimu_string(req->headers[i].value);
        }
    }
    hajimu_array_push(&arr, headers);

    /* [6] params {key: value, ...} — 辞書型 */
    Value params;
    memset(&params, 0, sizeof(params));
    params.type = VALUE_DICT;
    if (req->param_count > 0) {
        params.dict.keys = (char **)calloc(req->param_count, sizeof(char *));
        params.dict.values = (Value *)calloc(req->param_count, sizeof(Value));
        params.dict.length = req->param_count;
        params.dict.capacity = req->param_count;
        for (int i = 0; i < req->param_count; i++) {
            params.dict.keys[i] = strdup(req->params[i].key);
            params.dict.values[i] = hajimu_string(req->params[i].value);
        }
    }
    hajimu_array_push(&arr, params);

    /* [7] query {key: value, ...} — 辞書型 */
    Value query_params;
    memset(&query_params, 0, sizeof(query_params));
    query_params.type = VALUE_DICT;
    if (req->query_count > 0) {
        query_params.dict.keys = (char **)calloc(req->query_count, sizeof(char *));
        query_params.dict.values = (Value *)calloc(req->query_count, sizeof(Value));
        query_params.dict.length = req->query_count;
        query_params.dict.capacity = req->query_count;
        for (int i = 0; i < req->query_count; i++) {
            query_params.dict.keys[i] = strdup(req->query[i].key);
            query_params.dict.values[i] = hajimu_string(req->query[i].value);
        }
    }
    hajimu_array_push(&arr, query_params);

    /* [8] body_type */
    const char *body_type_str = "none";
    switch (req->parsed_body.type) {
        case BODY_JSON: body_type_str = "json"; break;
        case BODY_FORM: body_type_str = "form"; break;
        case BODY_TEXT: body_type_str = "text"; break;
        default: break;
    }
    hajimu_array_push(&arr, hajimu_string(body_type_str));

    /* [9] form_fields {key: value, ...} — 辞書型 */
    Value form_fields;
    memset(&form_fields, 0, sizeof(form_fields));
    form_fields.type = VALUE_DICT;
    if (req->parsed_body.field_count > 0) {
        int fc = req->parsed_body.field_count;
        form_fields.dict.keys = (char **)calloc(fc, sizeof(char *));
        form_fields.dict.values = (Value *)calloc(fc, sizeof(Value));
        form_fields.dict.length = fc;
        form_fields.dict.capacity = fc;
        for (int i = 0; i < fc; i++) {
            form_fields.dict.keys[i] = strdup(req->parsed_body.fields[i].key);
            form_fields.dict.values[i] = hajimu_string(req->parsed_body.fields[i].value);
        }
    }
    hajimu_array_push(&arr, form_fields);

    /* [10] cookies {key: value, ...} — 辞書型 */
    Value cookies;
    memset(&cookies, 0, sizeof(cookies));
    cookies.type = VALUE_DICT;
    if (req->cookie_count > 0) {
        cookies.dict.keys = (char **)calloc(req->cookie_count, sizeof(char *));
        cookies.dict.values = (Value *)calloc(req->cookie_count, sizeof(Value));
        cookies.dict.length = req->cookie_count;
        cookies.dict.capacity = req->cookie_count;
        for (int i = 0; i < req->cookie_count; i++) {
            cookies.dict.keys[i] = strdup(req->cookies[i].key);
            cookies.dict.values[i] = hajimu_string(req->cookies[i].value);
        }
    }
    hajimu_array_push(&arr, cookies);

    /* [11] uploads [[field, filename, content_type, data_len], ...] */
    Value uploads = hajimu_array();
    for (int i = 0; i < req->upload_count; i++) {
        Value uf = hajimu_array();
        hajimu_array_push(&uf, hajimu_string(req->uploads[i].field_name));
        hajimu_array_push(&uf, hajimu_string(req->uploads[i].filename));
        hajimu_array_push(&uf, hajimu_string(req->uploads[i].content_type));
        hajimu_array_push(&uf, hajimu_number(req->uploads[i].data_len));
        if (req->uploads[i].data)
            hajimu_array_push(&uf, hajimu_string(req->uploads[i].data));
        else
            hajimu_array_push(&uf, hajimu_string(""));
        hajimu_array_push(&uploads, uf);
    }
    hajimu_array_push(&arr, uploads);

    /* [12] session_id */
    hajimu_array_push(&arr, hajimu_string(req->session_id));

    /* [13] hostname (v5.0) */
    const char *host_hdr = get_header(req, "Host");
    char hostname[256] = {0};
    if (host_hdr) {
        snprintf(hostname, sizeof(hostname), "%s", host_hdr);
        char *colon = strchr(hostname, ':');
        if (colon) *colon = '\0';
    }
    hajimu_array_push(&arr, hajimu_string(hostname));

    /* [14] protocol (v5.0) */
    const char *proto = "http";
    if (g_server.trust_proxy) {
        const char *fp = get_header(req, "X-Forwarded-Proto");
        if (fp) proto = fp;
    }
    if (g_server.tls_enabled) proto = "https";
    hajimu_array_push(&arr, hajimu_string(proto));

    /* [15] secure (v5.0) */
    hajimu_array_push(&arr, hajimu_bool(strcmp(proto, "https") == 0));

    return arr;
}

/* ================================================================= */
/* リクエスト処理（メインハンドラ）                                     */
/* ================================================================= */

static void handle_client(socket_t client_fd, struct sockaddr_in *addr) {
    int ka_request_count = 0;
    int ka_max = g_server.keep_alive_max_requests > 0
              ? g_server.keep_alive_max_requests : 100;

  ka_loop: ;
    char client_ip[64] = {0};
    inet_ntop(AF_INET, &addr->sin_addr, client_ip, sizeof(client_ip));

    char buf[HW_READ_BUF];
    int total = 0;
    char *raw = (char *)malloc(HW_READ_BUF);
    if (!raw) { close_socket(client_fd); return; }
    int capacity = HW_READ_BUF;

    /* 受信タイムアウト 5秒 */
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&tv, sizeof(tv));

    while (1) {
        int n = (int)recv(client_fd, buf, sizeof(buf), 0);
        if (n <= 0) break;

        if (total + n >= capacity) {
            capacity *= 2;
            if (capacity > HW_MAX_BODY + HW_READ_BUF) {
                send_error(client_fd, 413, "Request too large");
                free(raw);
                close_socket(client_fd);
                return;
            }
            char *tmp = (char *)realloc(raw, capacity);
            if (!tmp) { free(raw); close_socket(client_fd); return; }
            raw = tmp;
        }
        memcpy(raw + total, buf, n);
        total += n;

        if (total >= 4) {
            char *header_end = strstr(raw, "\r\n\r\n");
            if (header_end) {
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
        if (total > HW_MAX_BODY) {
            send_error(client_fd, 413, "Request too large");
            free(raw);
            close_socket(client_fd);
            return;
        }
    }

    if (total == 0) { free(raw); close_socket(client_fd); return; }
    raw[total] = '\0';

    HttpRequest req;
    if (parse_http_request(raw, total, &req) != 0) {
        send_error(client_fd, 400, "Bad request");
        free(raw);
        close_socket(client_fd);
        return;
    }
    /* v5.0: Trust Proxy — X-Forwarded-For */
    if (g_server.trust_proxy) {
        const char *xff = get_header(&req, "X-Forwarded-For");
        if (xff) {
            char xff_buf[256];
            snprintf(xff_buf, sizeof(xff_buf), "%s", xff);
            char *comma = strchr(xff_buf, ',');
            if (comma) *comma = '\0';
            char *xp = xff_buf; while (*xp == ' ') xp++;
            snprintf(client_ip, sizeof(client_ip), "%s", xp);
        }
    }
    snprintf(req.client_ip, sizeof(req.client_ip), "%s", client_ip);

    /* ボディ自動解析 */
    auto_parse_body(&req);
    parse_multipart_body(&req);
    __sync_fetch_and_add(&g_server.total_requests, 1);

    /* セッション処理 */
    if (g_server.session_enabled) {
        const char *sid_cookie = NULL;
        for (int ci = 0; ci < req.cookie_count; ci++) {
            if (strcmp(req.cookies[ci].key, "hajimu_sid") == 0) {
                sid_cookie = req.cookies[ci].value;
                break;
            }
        }
        Session *sess = sid_cookie ? find_session(sid_cookie) : NULL;
        if (!sess) sess = create_session();
        if (sess) {
            snprintf(req.session_id, HW_SESSION_ID_LEN, "%s", sess->id);
            snprintf(g_server.current_session_id, HW_SESSION_ID_LEN,
                     "%s", sess->id);
        }
    }

    /* ミドルウェア before */
    HttpResponse resp;
    response_init(&resp);

    if (run_middlewares_before(&req, &resp) != 0) {
        if (!resp.sent) send_response_obj(client_fd, &resp);
        if (resp.body) free(resp.body);
        if (req.body)  free(req.body);
        free(raw);
        close_socket(client_fd);
        return;
    }

    /* OPTIONS (CORS preflight) */
    if (req.method == METHOD_OPTIONS && g_server.cors_enabled) {
        resp.status_code = 204;
        snprintf(resp.content_type, sizeof(resp.content_type), "text/plain");
        send_response_obj(client_fd, &resp);
        if (resp.body) free(resp.body);
        if (req.body)  free(req.body);
        free(raw);
        close_socket(client_fd);
        return;
    }

    /* ルート検索 */
    Route *route = find_route(req.method, req.path, &req);

    /* レスポンスコンテキストをグローバルに設定 */
    g_server.current_resp = &resp;
    g_server.current_fd   = client_fd;
    g_server.current_req  = &req;

    if (route) {
        /* SSE ルートチェック */
        if (route->has_callback && route->is_wildcard == 2) {
            /* SSE 接続 — 別スレッドで処理 */
            SSEThreadArg *sa = (SSEThreadArg *)malloc(sizeof(SSEThreadArg));
            if (sa) {
                sa->fd = client_fd;
                sa->callback_func = route->callback_func;
                snprintf(sa->path, HW_MAX_PATH, "%s", req.path);
                pthread_t tid;
                pthread_create(&tid, NULL, sse_client_thread, sa);
                pthread_detach(tid);
                /* SSE の場合 client_fd は閉じない */
                if (req.body) free(req.body);
                free(raw);
                return;
            }
        } else if (route->has_callback && hajimu_runtime_available()) {
            /* === コールバック関数ハンドラ (v5.0: mutex保護) === */
            Value req_val = request_to_value(&req);
            pthread_mutex_lock(&g_server.callback_mutex);
            g_server.current_resp = &resp;
            g_server.current_req  = &req;
            g_server.current_fd   = client_fd;
            Value result  = hajimu_call(&route->callback_func, 1, &req_val);

            /* レスポンスがまだ送信されていない場合 */
            if (!resp.sent) {
                if (result.type == VALUE_STRING) {
                    /* 文字列を返した場合: Content-Type 未設定なら自動判定 */
                    if (resp.status_code == 200 && resp.body == NULL) {
                        const char *s = result.string.data;
                        if (s[0] == '{' || s[0] == '[') {
                            snprintf(resp.content_type, sizeof(resp.content_type),
                                     "application/json; charset=utf-8");
                        }
                    }
                    if (resp.body == NULL) {
                        response_set_body(&resp, result.string.data,
                                          result.string.length);
                    }
                } else if (result.type == VALUE_NUMBER) {
                    /* 数値を返した場合: ステータスコードとして使用 */
                    resp.status_code = (int)result.number;
                    if (resp.body == NULL) {
                        const char *st = status_text(resp.status_code);
                        response_set_body(&resp, st, (int)strlen(st));
                    }
                } else if (result.type == VALUE_ARRAY) {
                    /* 配列を返した場合: [ステータス, Content-Type, ボディ] */
                    if (result.array.length >= 1 &&
                        result.array.elements[0].type == VALUE_NUMBER)
                        resp.status_code = (int)result.array.elements[0].number;
                    if (result.array.length >= 2 &&
                        result.array.elements[1].type == VALUE_STRING)
                        snprintf(resp.content_type, sizeof(resp.content_type),
                                 "%s", result.array.elements[1].string.data);
                    if (result.array.length >= 3 &&
                        result.array.elements[2].type == VALUE_STRING)
                        response_set_body(&resp,
                            result.array.elements[2].string.data,
                            result.array.elements[2].string.length);
                }
                if (resp.body == NULL) {
                    response_set_body(&resp, "OK", 2);
                }
                pthread_mutex_unlock(&g_server.callback_mutex);
                /* gzip 圧縮 */
                if (should_compress(&req, &resp)) {
                    char *gz = NULL; int gz_len = 0;
                    if (gzip_compress(resp.body, resp.body_length,
                                     &gz, &gz_len)) {
                        response_set_body(&resp, gz, gz_len);
                        response_set_header(&resp, "Content-Encoding", "gzip");
                        free(gz);
                    }
                }
                /* セッションCookieセット */
                if (g_server.session_enabled && req.session_id[0]) {
                    char sc[256];
                    int stimeout = g_server.session_timeout > 0
                                   ? g_server.session_timeout : 1800;
                    snprintf(sc, sizeof(sc),
                        "hajimu_sid=%s; Path=/; HttpOnly; Max-Age=%d",
                        req.session_id, stimeout);
                    response_set_header(&resp, "Set-Cookie", sc);
                }
                run_middlewares_after(&req, &resp);
                send_response_obj(client_fd, &resp);
            }
        } else if (route->has_static_response) {
            resp.status_code = route->static_status;
            snprintf(resp.content_type, sizeof(resp.content_type),
                     "%s", route->static_content_type);
            response_set_body(&resp, route->static_body,
                              route->static_body_len);
            run_middlewares_after(&req, &resp);
            send_response_obj(client_fd, &resp);
        } else if (route->c_handler) {
            Value result = route->c_handler(&req);
            if (result.type == VALUE_STRING) {
                resp.status_code = 200;
                snprintf(resp.content_type, sizeof(resp.content_type),
                         "text/html; charset=utf-8");
                response_set_body(&resp, result.string.data,
                                  result.string.length);
            } else {
                resp.status_code = 200;
                snprintf(resp.content_type, sizeof(resp.content_type),
                         "text/plain; charset=utf-8");
                response_set_body(&resp, "OK", 2);
            }
            run_middlewares_after(&req, &resp);
            send_response_obj(client_fd, &resp);
        } else {
            resp.status_code = 200;
            snprintf(resp.content_type, sizeof(resp.content_type),
                     "text/plain; charset=utf-8");
            response_set_body(&resp, "OK", 2);
            run_middlewares_after(&req, &resp);
            send_response_obj(client_fd, &resp);
        }
    } else if (req.method == METHOD_GET &&
               serve_static_file(client_fd, &req)) {
        /* served by static file handler */
    } else {
        /* 405 vs 404 判定 */
        int path_exists = 0;
        for (int i = 0; i < g_server.route_count; i++) {
            KVPair dp[HW_MAX_PARAMS];
            int dc = 0;
            if (match_route(&g_server.routes[i], req.path, dp, &dc)) {
                path_exists = 1;
                break;
            }
        }
        if (path_exists)
            send_error(client_fd, 405, "Method not allowed");
        else
            send_error(client_fd, 404, NULL);
    }

    /* アップロードデータ解放 */
    for (int ui = 0; ui < req.upload_count; ui++)
        if (req.uploads[ui].data) free(req.uploads[ui].data);
    if (resp.body) free(resp.body);
    if (req.body)  free(req.body);
    free(raw);

    /* v5.0: Keep-Alive ループ判定 */
    if (g_server.keep_alive_enabled && !g_shutdown) {
        const char *conn_hdr = get_header(&req, "Connection");
        ka_request_count++;
        if (ka_request_count < ka_max &&
            (conn_hdr == NULL || strcasecmp(conn_hdr, "close") != 0)) {
            goto ka_loop;
        }
    }
    close_socket(client_fd);
}

/* ================================================================= */
/* シグナルハンドラ                                                    */
/* ================================================================= */

static void signal_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
    if (g_server.listen_fd != INVALID_SOCK) {
        close_socket(g_server.listen_fd);
        g_server.listen_fd = INVALID_SOCK;
    }
}

/* ================================================================= */
/* プラグイン関数                                                      */
/* ================================================================= */

/* --- サーバー管理 --- */

static Value fn_server_create(int argc, Value *argv) {
    (void)argc;
    if (argv[0].type != VALUE_NUMBER) {
        fprintf(stderr,
            "[hajimu_web] error: port must be a number\n");
        return hajimu_bool(false);
    }
    int port = (int)argv[0].number;
    if (port < 1 || port > 65535) {
        fprintf(stderr,
            "[hajimu_web] error: port must be 1-65535\n");
        return hajimu_bool(false);
    }
    memset(&g_server, 0, sizeof(g_server));
    g_server.listen_fd = INVALID_SOCK;
    g_server.port = port;
    g_server.active_group = -1;
    g_server.upload_max_size = HW_UPLOAD_MAX_SIZE;
    g_server.max_threads = 0;  /* デフォルト同期モード（ランタイム非スレッドセーフ） */
    pthread_mutex_init(&g_server.sse_mutex, NULL);
    pthread_mutex_init(&g_server.thread_mutex, NULL);
    /* v5.0: recursive mutex for callback protection */
    {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&g_server.callback_mutex, &attr);
        pthread_mutexattr_destroy(&attr);
    }
    g_shutdown = 0;
    return hajimu_bool(true);
}

/* --- ミドルウェア --- */

static Value fn_middleware(int argc, Value *argv) {
    (void)argc;
    if (argv[0].type != VALUE_STRING) {
        fprintf(stderr, "[hajimu_web] エラー: ミドルウェア名が必要です\n");
        return hajimu_bool(false);
    }
    if (g_server.middleware_count >= HW_MAX_MIDDLEWARES)
        return hajimu_bool(false);

    const char *name = argv[0].string.data;
    Middleware *mw = &g_server.middlewares[g_server.middleware_count];
    memset(mw, 0, sizeof(*mw));
    mw->enabled = 1;
    snprintf(mw->name, sizeof(mw->name), "%s", name);

    if (strcmp(name, "logger") == 0) {
        mw->type = MW_LOGGER;
    } else if (strcmp(name, "CORS") == 0 || strcmp(name, "cors") == 0) {
        mw->type = MW_CORS;
        g_server.cors_enabled = 1;
    } else if (strcmp(name, "security") == 0) {
        mw->type = MW_SECURITY;
    } else if (strcmp(name, "json") == 0) {
        mw->type = MW_JSON_PARSE;
    } else if (strcmp(name, "form") == 0) {
        mw->type = MW_FORM_PARSE;
    } else if (strcmp(name, "cache") == 0) {
        mw->type = MW_STATIC_CACHE;
        if (g_server.static_cache_seconds == 0)
            g_server.static_cache_seconds = 3600;
        g_server.static_etag = 1;
    } else if (strcmp(name, "rate_limit") == 0 ||
               strcmp(name, "rate-limit") == 0 ||
               strcmp(name, "ratelimit") == 0) {
        mw->type = MW_RATE_LIMIT;
        if (g_server.rate_limit_max == 0) {
            g_server.rate_limit_max = 100;   /* デフォルト: 100リクエスト/分 */
            g_server.rate_limit_window = 60;
        }
    } else if (strcmp(name, "compression") == 0 ||
               strcmp(name, "gzip") == 0) {
        mw->type = MW_COMPRESSION;
        g_server.compression_enabled = 1;
        if (g_server.compression_min_size == 0)
            g_server.compression_min_size = 1024;
    } else if (strcmp(name, "session") == 0) {
        mw->type = MW_SESSION;
        g_server.session_enabled = 1;
        if (g_server.session_timeout == 0)
            g_server.session_timeout = 1800;
    } else {
        fprintf(stderr,
            "[hajimu_web] warning: unknown middleware '%s'\n", name);
        return hajimu_bool(false);
    }

    g_server.middleware_count++;
    printf("[hajimu_web] ミドルウェア追加: %s\n", name);
    return hajimu_bool(true);
}

static Value fn_middleware_list(int argc, Value *argv) {
    (void)argc; (void)argv;
    Value arr = hajimu_array();
    for (int i = 0; i < g_server.middleware_count; i++)
        hajimu_array_push(&arr, hajimu_string(g_server.middlewares[i].name));
    return arr;
}

/* --- ルーティング --- */

static Value add_route(HttpMethod method, const char *raw_pattern,
                       int status, const char *content_type,
                       const char *body) {
    if (g_server.route_count >= HW_MAX_ROUTES)
        return hajimu_bool(false);

    Route *r = &g_server.routes[g_server.route_count++];
    memset(r, 0, sizeof(*r));
    r->method = method;

    if (g_server.active_group >= 0) {
        snprintf(r->pattern, sizeof(r->pattern), "%s%s",
                 g_server.groups[g_server.active_group].prefix,
                 raw_pattern);
    } else {
        snprintf(r->pattern, sizeof(r->pattern), "%s", raw_pattern);
    }

    int plen = (int)strlen(r->pattern);
    if (plen >= 2 && r->pattern[plen-1] == '*' && r->pattern[plen-2] == '/')
        r->is_wildcard = 1;

    r->has_static_response = 1;
    r->static_status = status;
    snprintf(r->static_content_type, sizeof(r->static_content_type),
             "%s", content_type);
    int body_len = (int)strlen(body);
    r->static_body = (char *)malloc(body_len + 1);
    if (r->static_body) {
        memcpy(r->static_body, body, body_len + 1);
        r->static_body_len = body_len;
    }
    r->c_handler = NULL;
    return hajimu_bool(true);
}

/* コールバック付きルートを追加 */
static Value add_callback_route(HttpMethod method, const char *raw_pattern,
                                Value *callback) {
    if (g_server.route_count >= HW_MAX_ROUTES)
        return hajimu_bool(false);

    Route *r = &g_server.routes[g_server.route_count++];
    memset(r, 0, sizeof(*r));
    r->method = method;

    if (g_server.active_group >= 0) {
        snprintf(r->pattern, sizeof(r->pattern), "%s%s",
                 g_server.groups[g_server.active_group].prefix,
                 raw_pattern);
    } else {
        snprintf(r->pattern, sizeof(r->pattern), "%s", raw_pattern);
    }

    int plen = (int)strlen(r->pattern);
    if (plen >= 2 && r->pattern[plen-1] == '*' && r->pattern[plen-2] == '/')
        r->is_wildcard = 1;

    r->has_static_response = 0;
    r->has_callback = 1;
    r->callback_func = *callback;
    r->c_handler = NULL;
    return hajimu_bool(true);
}

static Value fn_route_add(int argc, Value *argv) {
    if (argc < 5) return hajimu_bool(false);
    if (argv[0].type != VALUE_STRING || argv[1].type != VALUE_STRING ||
        argv[2].type != VALUE_NUMBER || argv[3].type != VALUE_STRING ||
        argv[4].type != VALUE_STRING)
        return hajimu_bool(false);
    return add_route(string_to_method(argv[0].string.data),
                     argv[1].string.data, (int)argv[2].number,
                     argv[3].string.data, argv[4].string.data);
}

static Value fn_get(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    if (argv[1].type == VALUE_FUNCTION || argv[1].type == VALUE_BUILTIN)
        return add_callback_route(METHOD_GET, argv[0].string.data, &argv[1]);
    if (argv[1].type != VALUE_STRING) return hajimu_bool(false);
    return add_route(METHOD_GET, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_post(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    if (argv[1].type == VALUE_FUNCTION || argv[1].type == VALUE_BUILTIN)
        return add_callback_route(METHOD_POST, argv[0].string.data, &argv[1]);
    if (argc >= 4 && argv[1].type == VALUE_NUMBER)
        return add_route(METHOD_POST, argv[0].string.data,
                         (int)argv[1].number, argv[2].string.data,
                         argv[3].string.data);
    if (argv[1].type != VALUE_STRING) return hajimu_bool(false);
    return add_route(METHOD_POST, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_put(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    if (argv[1].type == VALUE_FUNCTION || argv[1].type == VALUE_BUILTIN)
        return add_callback_route(METHOD_PUT, argv[0].string.data, &argv[1]);
    if (argv[1].type != VALUE_STRING) return hajimu_bool(false);
    return add_route(METHOD_PUT, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    if (argv[1].type == VALUE_FUNCTION || argv[1].type == VALUE_BUILTIN)
        return add_callback_route(METHOD_DELETE, argv[0].string.data, &argv[1]);
    if (argv[1].type != VALUE_STRING) return hajimu_bool(false);
    return add_route(METHOD_DELETE, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_patch(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    if (argv[1].type == VALUE_FUNCTION || argv[1].type == VALUE_BUILTIN)
        return add_callback_route(METHOD_PATCH, argv[0].string.data, &argv[1]);
    if (argv[1].type != VALUE_STRING) return hajimu_bool(false);
    return add_route(METHOD_PATCH, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_all_methods(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    if (argv[1].type == VALUE_FUNCTION || argv[1].type == VALUE_BUILTIN)
        return add_callback_route(METHOD_ALL, argv[0].string.data, &argv[1]);
    if (argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    return add_route(METHOD_ALL, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_json_route(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_NUMBER || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);
    return add_route(METHOD_GET, argv[0].string.data,
                     (int)argv[1].number,
                     "application/json; charset=utf-8",
                     argv[2].string.data);
}

static Value fn_json_post(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_NUMBER || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);
    return add_route(METHOD_POST, argv[0].string.data,
                     (int)argv[1].number,
                     "application/json; charset=utf-8",
                     argv[2].string.data);
}

/* --- ルートグループ --- */

static Value fn_group(int argc, Value *argv) {
    (void)argc;
    if (argv[0].type != VALUE_STRING) return hajimu_bool(false);
    if (g_server.group_count >= HW_MAX_GROUPS) return hajimu_bool(false);
    int idx = g_server.group_count++;
    snprintf(g_server.groups[idx].prefix,
             sizeof(g_server.groups[idx].prefix),
             "%s", argv[0].string.data);
    g_server.groups[idx].active = 1;
    g_server.active_group = idx;
    printf("[hajimu_web] ルートグループ: %s\n", argv[0].string.data);
    return hajimu_bool(true);
}

static Value fn_group_end(int argc, Value *argv) {
    (void)argc; (void)argv;
    if (g_server.active_group >= 0)
        g_server.groups[g_server.active_group].active = 0;
    g_server.active_group = -1;
    return hajimu_bool(true);
}

/* --- エラーハンドラ --- */

static Value fn_error_page(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_NUMBER ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);
    if (g_server.error_handler_count >= HW_MAX_ERROR_HANDLERS)
        return hajimu_bool(false);

    ErrorHandler *eh =
        &g_server.error_handlers[g_server.error_handler_count++];
    eh->status_code = (int)argv[0].number;
    snprintf(eh->content_type, sizeof(eh->content_type),
             "%s", argv[1].string.data);
    int body_len = argv[2].string.length;
    eh->body = (char *)malloc(body_len + 1);
    if (eh->body) {
        memcpy(eh->body, argv[2].string.data, body_len + 1);
        eh->body_len = body_len;
    }
    return hajimu_bool(true);
}

static Value fn_json_error_page(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_NUMBER ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    if (g_server.error_handler_count >= HW_MAX_ERROR_HANDLERS)
        return hajimu_bool(false);

    ErrorHandler *eh =
        &g_server.error_handlers[g_server.error_handler_count++];
    eh->status_code = (int)argv[0].number;
    snprintf(eh->content_type, sizeof(eh->content_type),
             "application/json; charset=utf-8");
    int body_len = argv[1].string.length;
    eh->body = (char *)malloc(body_len + 1);
    if (eh->body) {
        memcpy(eh->body, argv[1].string.data, body_len + 1);
        eh->body_len = body_len;
    }
    return hajimu_bool(true);
}

/* --- テンプレート --- */

static Value fn_template_dir(int argc, Value *argv) {
    (void)argc;
    if (argv[0].type != VALUE_STRING) return hajimu_bool(false);
    snprintf(g_server.template_dir, sizeof(g_server.template_dir),
             "%s", argv[0].string.data);
    int len = (int)strlen(g_server.template_dir);
    if (len > 0 && g_server.template_dir[len - 1] == '/')
        g_server.template_dir[len - 1] = '\0';
    printf("[hajimu_web] テンプレートディレクトリ: %s\n", g_server.template_dir);
    return hajimu_bool(true);
}

static Value fn_template_var(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    if (g_server.template_global_count >= HW_MAX_TEMPLATE_VARS)
        return hajimu_bool(false);

    /* 既存キーの更新 */
    for (int i = 0; i < g_server.template_global_count; i++) {
        if (strcmp(g_server.template_globals[i].key,
                   argv[0].string.data) == 0) {
            snprintf(g_server.template_globals[i].value,
                     HW_MAX_HEADER_VALUE, "%s", argv[1].string.data);
            return hajimu_bool(true);
        }
    }

    int idx = g_server.template_global_count++;
    snprintf(g_server.template_globals[idx].key, 256,
             "%s", argv[0].string.data);
    snprintf(g_server.template_globals[idx].value, HW_MAX_HEADER_VALUE,
             "%s", argv[1].string.data);
    return hajimu_bool(true);
}

static Value fn_template_render(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_string("");

    TemplateVar vars[HW_MAX_TEMPLATE_VARS];
    int var_count = 0;
    for (int i = 1; i + 1 < argc && var_count < HW_MAX_TEMPLATE_VARS;
         i += 2) {
        if (argv[i].type == VALUE_STRING &&
            argv[i + 1].type == VALUE_STRING) {
            snprintf(vars[var_count].key, 256,
                     "%s", argv[i].string.data);
            snprintf(vars[var_count].value, HW_MAX_HEADER_VALUE,
                     "%s", argv[i + 1].string.data);
            var_count++;
        }
    }

    char *output = render_template_file(
        argv[0].string.data, vars, var_count);
    if (!output) {
        fprintf(stderr,
            "[hajimu_web] error: cannot load template '%s'\n",
            argv[0].string.data);
        return hajimu_string("");
    }
    Value result = hajimu_string(output);
    free(output);
    return result;
}

static Value fn_template_string(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_string("");

    TemplateVar vars[HW_MAX_TEMPLATE_VARS];
    int var_count = 0;
    for (int i = 1; i + 1 < argc && var_count < HW_MAX_TEMPLATE_VARS;
         i += 2) {
        if (argv[i].type == VALUE_STRING &&
            argv[i + 1].type == VALUE_STRING) {
            snprintf(vars[var_count].key, 256,
                     "%s", argv[i].string.data);
            snprintf(vars[var_count].value, HW_MAX_HEADER_VALUE,
                     "%s", argv[i + 1].string.data);
            var_count++;
        }
    }

    char output[HW_TEMPLATE_BUF];
    template_render(argv[0].string.data, vars, var_count,
                    output, sizeof(output));
    return hajimu_string(output);
}

static Value fn_template_get(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);

    Value rendered = fn_template_render(argc - 1, argv + 1);
    if (rendered.type == VALUE_STRING && rendered.string.length > 0) {
        return add_route(METHOD_GET, argv[0].string.data, 200,
                         "text/html; charset=utf-8",
                         rendered.string.data);
    }
    return hajimu_bool(false);
}

/* --- 設定 --- */

static Value fn_static_dir(int argc, Value *argv) {
    (void)argc;
    if (argv[0].type != VALUE_STRING) return hajimu_bool(false);
    snprintf(g_server.static_dir, sizeof(g_server.static_dir),
             "%s", argv[0].string.data);
    int len = (int)strlen(g_server.static_dir);
    if (len > 0 && g_server.static_dir[len - 1] == '/')
        g_server.static_dir[len - 1] = '\0';
    printf("[hajimu_web] 静的ファイルディレクトリ: %s\n", g_server.static_dir);
    return hajimu_bool(true);
}

static Value fn_static_cache(int argc, Value *argv) {
    (void)argc;
    if (argv[0].type != VALUE_NUMBER) return hajimu_bool(false);
    g_server.static_cache_seconds = (int)argv[0].number;
    g_server.static_etag = 1;
    return hajimu_bool(true);
}

static Value fn_cors_enable(int argc, Value *argv) {
    (void)argc; (void)argv;
    g_server.cors_enabled = 1;
    return hajimu_bool(true);
}

static Value fn_cors_config(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    g_server.cors_enabled = 1;
    snprintf(g_server.cors_origin, sizeof(g_server.cors_origin),
             "%s", argv[0].string.data);
    if (argc >= 2 && argv[1].type == VALUE_STRING)
        snprintf(g_server.cors_methods, sizeof(g_server.cors_methods),
                 "%s", argv[1].string.data);
    if (argc >= 3 && argv[2].type == VALUE_STRING)
        snprintf(g_server.cors_headers, sizeof(g_server.cors_headers),
                 "%s", argv[2].string.data);
    return hajimu_bool(true);
}

/* レートリミッタ設定(最大リクエスト数, ウィンドウ秒) */
static Value fn_rate_limit_config(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_NUMBER)
        return hajimu_bool(false);
    g_server.rate_limit_max = (int)argv[0].number;
    if (argc >= 2 && argv[1].type == VALUE_NUMBER)
        g_server.rate_limit_window = (int)argv[1].number;
    else
        g_server.rate_limit_window = 60;
    return hajimu_bool(true);
}

/* --- レスポンスヘルパー --- */

static Value fn_redirect(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);

    int status = 302;
    if (argc >= 3 && argv[2].type == VALUE_NUMBER)
        status = (int)argv[2].number;

    char body[1024];
    snprintf(body, sizeof(body),
        "<!DOCTYPE html><html><head>"
        "<meta http-equiv=\"refresh\" content=\"0;url=%s\">"
        "</head><body><p>Redirecting... "
        "<a href=\"%s\">%s</a></p></body></html>",
        argv[1].string.data, argv[1].string.data, argv[1].string.data);

    if (g_server.route_count >= HW_MAX_ROUTES) return hajimu_bool(false);
    Route *r = &g_server.routes[g_server.route_count++];
    memset(r, 0, sizeof(*r));
    r->method = METHOD_GET;
    snprintf(r->pattern, sizeof(r->pattern), "%s", argv[0].string.data);
    r->has_static_response = 1;
    r->static_status = status;
    snprintf(r->static_content_type, sizeof(r->static_content_type),
             "text/html; charset=utf-8");
    int body_len = (int)strlen(body);
    r->static_body = (char *)malloc(body_len + 1);
    if (r->static_body) {
        memcpy(r->static_body, body, body_len + 1);
        r->static_body_len = body_len;
    }
    return hajimu_bool(true);
}

/* --- #2 Cookie 設定 --- */

/* Cookie設定(名前, 値)  または  Cookie設定(名前, 値, オプション文字列) */
static Value fn_set_cookie(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);

    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);

    char cookie[HW_MAX_HEADER_VALUE];
    if (argc >= 3 && argv[2].type == VALUE_STRING) {
        /* オプション付き: Cookie設定("token", "abc123", "Path=/; HttpOnly; Secure; Max-Age=3600") */
        snprintf(cookie, sizeof(cookie), "%s=%s; %s",
                 argv[0].string.data, argv[1].string.data,
                 argv[2].string.data);
    } else {
        snprintf(cookie, sizeof(cookie), "%s=%s; Path=/; HttpOnly",
                 argv[0].string.data, argv[1].string.data);
    }
    response_set_header(resp, "Set-Cookie", cookie);
    return hajimu_bool(true);
}

/* Cookie削除(名前) */
static Value fn_delete_cookie(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);

    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);

    char cookie[HW_MAX_HEADER_VALUE];
    snprintf(cookie, sizeof(cookie),
             "%s=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0",
             argv[0].string.data);
    response_set_header(resp, "Set-Cookie", cookie);
    return hajimu_bool(true);
}

/* --- #3 レスポンスヘッダー設定 --- */

/* ヘッダー設定(キー, 値) */
static Value fn_set_header(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);

    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);

    response_set_header(resp, argv[0].string.data, argv[1].string.data);
    return hajimu_bool(true);
}

/* --- #4 ステータスコード動的設定 --- */

/* ステータス設定(コード) */
static Value fn_set_status(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_NUMBER)
        return hajimu_bool(false);

    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);

    resp->status_code = (int)argv[0].number;
    return hajimu_bool(true);
}

/* --- #5 Content-Type 動的設定 --- */

/* コンテンツタイプ設定(タイプ) */
static Value fn_set_content_type(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);

    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);

    snprintf(resp->content_type, sizeof(resp->content_type),
             "%s", argv[0].string.data);
    return hajimu_bool(true);
}

/* --- #6 JSON ユーティリティ --- */

/* JSON解析 — 簡易 JSON パーサー（文字列 → はじむ配列/文字列） */
static Value parse_json_value(const char **p);

static void skip_ws(const char **p) {
    while (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r') (*p)++;
}

static Value parse_json_string(const char **p) {
    if (**p != '"') return hajimu_string("");
    (*p)++; /* skip " */
    char buf[HW_MAX_HEADER_VALUE];
    int bi = 0;
    while (**p && **p != '"' && bi < HW_MAX_HEADER_VALUE - 2) {
        if (**p == '\\') {
            (*p)++;
            switch (**p) {
                case '"':  buf[bi++] = '"'; break;
                case '\\': buf[bi++] = '\\'; break;
                case '/':  buf[bi++] = '/'; break;
                case 'n':  buf[bi++] = '\n'; break;
                case 't':  buf[bi++] = '\t'; break;
                case 'r':  buf[bi++] = '\r'; break;
                default:   buf[bi++] = **p; break;
            }
        } else {
            buf[bi++] = **p;
        }
        (*p)++;
    }
    if (**p == '"') (*p)++; /* skip closing " */
    buf[bi] = '\0';
    return hajimu_string(buf);
}

static Value parse_json_value(const char **p) {
    skip_ws(p);
    if (**p == '"') {
        return parse_json_string(p);
    } else if (**p == '{') {
        /* オブジェクト → VALUE_DICT (v5.0) */
        (*p)++;
        skip_ws(p);
        /* まずキー・値を一時配列に収集 */
        char *tmp_keys[256];
        Value tmp_vals[256];
        int tmp_count = 0;
        if (**p != '}') {
            while (**p && tmp_count < 256) {
                skip_ws(p);
                Value key = parse_json_string(p);
                skip_ws(p);
                if (**p == ':') (*p)++;
                Value val = parse_json_value(p);
                tmp_keys[tmp_count] = key.string.data
                    ? strdup(key.string.data) : strdup("");
                tmp_vals[tmp_count] = val;
                tmp_count++;
                skip_ws(p);
                if (**p == ',') (*p)++;
                else break;
            }
        }
        skip_ws(p);
        if (**p == '}') (*p)++;
        /* VALUE_DICT 構築 */
        Value dict;
        memset(&dict, 0, sizeof(dict));
        dict.type = VALUE_DICT;
        if (tmp_count > 0) {
            dict.dict.keys = (char **)calloc(tmp_count, sizeof(char *));
            dict.dict.values = (Value *)calloc(tmp_count, sizeof(Value));
            dict.dict.length = tmp_count;
            dict.dict.capacity = tmp_count;
            for (int i = 0; i < tmp_count; i++) {
                dict.dict.keys[i] = tmp_keys[i];
                dict.dict.values[i] = tmp_vals[i];
            }
        }
        return dict;
    } else if (**p == '[') {
        (*p)++;
        Value arr = hajimu_array();
        skip_ws(p);
        if (**p == ']') { (*p)++; return arr; }
        while (**p) {
            Value val = parse_json_value(p);
            hajimu_array_push(&arr, val);
            skip_ws(p);
            if (**p == ',') (*p)++;
            else break;
        }
        skip_ws(p);
        if (**p == ']') (*p)++;
        return arr;
    } else if (**p == 't') {
        if (strncmp(*p, "true", 4) == 0) { *p += 4; return hajimu_bool(true); }
        return hajimu_null();
    } else if (**p == 'f') {
        if (strncmp(*p, "false", 5) == 0) { *p += 5; return hajimu_bool(false); }
        return hajimu_null();
    } else if (**p == 'n') {
        if (strncmp(*p, "null", 4) == 0) { *p += 4; return hajimu_null(); }
        return hajimu_null();
    } else if (**p == '-' || (**p >= '0' && **p <= '9')) {
        char *end = NULL;
        double num = strtod(*p, &end);
        if (end != *p) { *p = end; return hajimu_number(num); }
        return hajimu_null();
    }
    return hajimu_null();
}

/* JSON解析(文字列) → はじむ値 */
static Value fn_json_parse(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_null();
    const char *p = argv[0].string.data;
    return parse_json_value(&p);
}

/* JSON生成 — はじむ値 → JSON 文字列 */
static int value_to_json(Value *val, char *buf, int buf_size);

static int value_to_json(Value *val, char *buf, int buf_size) {
    int written = 0;
    if (!val || buf_size <= 0) return 0;

    switch (val->type) {
        case VALUE_NULL:
            written = snprintf(buf, buf_size, "null");
            break;
        case VALUE_BOOL:
            written = snprintf(buf, buf_size, "%s",
                               val->boolean ? "true" : "false");
            break;
        case VALUE_NUMBER: {
            double n = val->number;
            if (n == (int)n)
                written = snprintf(buf, buf_size, "%d", (int)n);
            else
                written = snprintf(buf, buf_size, "%g", n);
            break;
        }
        case VALUE_STRING: {
            written = snprintf(buf, buf_size, "\"");
            for (int i = 0; i < val->string.length && written < buf_size - 2; i++) {
                char c = val->string.data[i];
                switch (c) {
                    case '"':  written += snprintf(buf+written, buf_size-written, "\\\""); break;
                    case '\\': written += snprintf(buf+written, buf_size-written, "\\\\"); break;
                    case '\n': written += snprintf(buf+written, buf_size-written, "\\n"); break;
                    case '\t': written += snprintf(buf+written, buf_size-written, "\\t"); break;
                    case '\r': written += snprintf(buf+written, buf_size-written, "\\r"); break;
                    default:   buf[written++] = c; break;
                }
            }
            written += snprintf(buf+written, buf_size-written, "\"");
            break;
        }
        case VALUE_ARRAY: {
            /* 配列の各要素が2要素配列なら → JSON object として出力 */
            int is_kv = 1;
            if (val->array.length > 0) {
                for (int i = 0; i < val->array.length; i++) {
                    Value *elem = &val->array.elements[i];
                    if (elem->type != VALUE_ARRAY || elem->array.length != 2 ||
                        elem->array.elements[0].type != VALUE_STRING) {
                        is_kv = 0;
                        break;
                    }
                }
            } else {
                is_kv = 0;
            }

            if (is_kv) {
                buf[written++] = '{';
                for (int i = 0; i < val->array.length && written < buf_size - 2; i++) {
                    if (i > 0) buf[written++] = ',';
                    Value *pair = &val->array.elements[i];
                    written += value_to_json(&pair->array.elements[0],
                                             buf+written, buf_size-written);
                    buf[written++] = ':';
                    written += value_to_json(&pair->array.elements[1],
                                             buf+written, buf_size-written);
                }
                buf[written++] = '}';
            } else {
                buf[written++] = '[';
                for (int i = 0; i < val->array.length && written < buf_size - 2; i++) {
                    if (i > 0) buf[written++] = ',';
                    written += value_to_json(&val->array.elements[i],
                                             buf+written, buf_size-written);
                }
                buf[written++] = ']';
            }
            buf[written] = '\0';
            break;
        }
        case VALUE_DICT: {
            buf[written++] = '{';
            for (int i = 0; i < val->dict.length && written < buf_size - 2; i++) {
                if (i > 0) buf[written++] = ',';
                /* キー */
                Value key_val = hajimu_string(val->dict.keys[i]);
                written += value_to_json(&key_val, buf+written, buf_size-written);
                buf[written++] = ':';
                /* 値 */
                written += value_to_json(&val->dict.values[i],
                                         buf+written, buf_size-written);
            }
            buf[written++] = '}';
            buf[written] = '\0';
            break;
        }
        default:
            written = snprintf(buf, buf_size, "null");
            break;
    }
    return written;
}

/* JSON生成(値) → 文字列 */
static Value fn_json_stringify(int argc, Value *argv) {
    if (argc < 1) return hajimu_string("null");
    char buf[HW_TEMPLATE_BUF];
    value_to_json(&argv[0], buf, sizeof(buf));
    return hajimu_string(buf);
}

/* --- 情報取得 --- */

static Value fn_route_list(int argc, Value *argv) {
    (void)argc; (void)argv;
    Value arr = hajimu_array();
    for (int i = 0; i < g_server.route_count; i++) {
        char desc[HW_MAX_PATH];
        snprintf(desc, sizeof(desc), "%s %s",
                 method_to_string(g_server.routes[i].method),
                 g_server.routes[i].pattern);
        hajimu_array_push(&arr, hajimu_string(desc));
    }
    return arr;
}

static Value fn_server_info(int argc, Value *argv) {
    (void)argc; (void)argv;
    Value arr = hajimu_array();
    char buf[256];
    snprintf(buf, sizeof(buf), "port: %d", g_server.port);
    hajimu_array_push(&arr, hajimu_string(buf));
    snprintf(buf, sizeof(buf), "routes: %d", g_server.route_count);
    hajimu_array_push(&arr, hajimu_string(buf));
    snprintf(buf, sizeof(buf), "middlewares: %d",
             g_server.middleware_count);
    hajimu_array_push(&arr, hajimu_string(buf));
    snprintf(buf, sizeof(buf), "total_requests: %lld",
             g_server.total_requests);
    hajimu_array_push(&arr, hajimu_string(buf));
    snprintf(buf, sizeof(buf), "errors: %lld", g_server.error_count);
    hajimu_array_push(&arr, hajimu_string(buf));
    return arr;
}

/* --- サーバー起動 / 停止 --- */

static Value fn_server_start(int argc, Value *argv) {
    (void)argc; (void)argv;
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[hajimu_web] エラー: WinSock 初期化に失敗しました\n");
        return hajimu_bool(false);
    }
#endif

    g_server.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server.listen_fd == INVALID_SOCK) {
        fprintf(stderr, "[hajimu_web] エラー: ソケット作成に失敗しました\n");
        return hajimu_bool(false);
    }

    int opt = 1;
    setsockopt(g_server.listen_fd, SOL_SOCKET, SO_REUSEADDR,
               (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)g_server.port);

    if (bind(g_server.listen_fd,
             (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr,
            "[hajimu_web] error: bind port %d failed (%s)\n",
            g_server.port, strerror(errno));
        close_socket(g_server.listen_fd);
        return hajimu_bool(false);
    }

    if (listen(g_server.listen_fd, 128) < 0) {
        fprintf(stderr, "[hajimu_web] エラー: listen に失敗しました\n");
        close_socket(g_server.listen_fd);
        return hajimu_bool(false);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    g_server.running = 1;

    printf("\n");
    printf("  +==========================================+\n");
    printf("  |   はじむウェブ v5.0 サーバー起動          |\n");
    printf("  |                                          |\n");
    printf("  |   http://localhost:%-5d                  |\n",
           g_server.port);
    printf("  |                                          |\n");
    printf("  |   ルート数:        %3d                   |\n",
           g_server.route_count);
    printf("  |   ミドルウェア数:  %2d                    |\n",
           g_server.middleware_count);
    if (g_server.static_dir[0])
        printf("  |   静的ファイル: %-25s |\n", g_server.static_dir);
    if (g_server.template_dir[0])
        printf("  |   テンプレート: %-25s |\n", g_server.template_dir);
    printf("  |   Ctrl+C で停止                          |\n");
    printf("  +==========================================+\n");
    printf("\n");

    /* メインイベントループ (v5.0: スレッドプール) */
    while (!g_shutdown) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        socket_t client_fd = accept(g_server.listen_fd,
            (struct sockaddr *)&client_addr, &client_len);
        if (client_fd == INVALID_SOCK) {
            if (g_shutdown) break;
            continue;
        }
        /* スレッド数チェック */
        pthread_mutex_lock(&g_server.thread_mutex);
        int can_thread = (g_server.active_threads < g_server.max_threads);
        if (can_thread) g_server.active_threads++;
        pthread_mutex_unlock(&g_server.thread_mutex);
        if (can_thread) {
            ClientThreadArg *ca = (ClientThreadArg *)malloc(sizeof(ClientThreadArg));
            ca->fd = client_fd;
            ca->addr = client_addr;
            pthread_t th;
            if (pthread_create(&th, NULL, client_thread_func, ca) == 0) {
                pthread_detach(th);
            } else {
                handle_client(client_fd, &client_addr);
                free(ca);
                pthread_mutex_lock(&g_server.thread_mutex);
                g_server.active_threads--;
                pthread_mutex_unlock(&g_server.thread_mutex);
            }
        } else {
            /* フォールバック: 同期処理 */
            handle_client(client_fd, &client_addr);
        }
    }

    /* クリーンアップ */
    if (g_server.listen_fd != INVALID_SOCK) {
        close_socket(g_server.listen_fd);
        g_server.listen_fd = INVALID_SOCK;
    }
    g_server.running = 0;

    /* SSE クライアント切断 */
    pthread_mutex_lock(&g_server.sse_mutex);
    for (int i = 0; i < HW_MAX_SSE_CLIENTS; i++) {
        if (g_server.sse_clients[i].active) {
            close_socket(g_server.sse_clients[i].fd);
            g_server.sse_clients[i].active = 0;
        }
    }
    pthread_mutex_unlock(&g_server.sse_mutex);
    pthread_mutex_destroy(&g_server.sse_mutex);
    pthread_mutex_destroy(&g_server.thread_mutex);
    pthread_mutex_destroy(&g_server.callback_mutex);

    /* スレッド完了待ち */
    for (int wait = 0; wait < 50 && g_server.active_threads > 0; wait++)
        usleep(100000); /* 100ms */

    for (int i = 0; i < g_server.route_count; i++) {
        if (g_server.routes[i].static_body) {
            free(g_server.routes[i].static_body);
            g_server.routes[i].static_body = NULL;
        }
    }
    for (int i = 0; i < g_server.error_handler_count; i++) {
        if (g_server.error_handlers[i].body) {
            free(g_server.error_handlers[i].body);
            g_server.error_handlers[i].body = NULL;
        }
    }
#ifdef _WIN32
    WSACleanup();
#endif

    printf("\n[hajimu_web] サーバー停止 "
           "(リクエスト数: %lld, エラー数: %lld)\n",
           g_server.total_requests, g_server.error_count);
    return hajimu_bool(true);
}

static Value fn_server_stop(int argc, Value *argv) {
    (void)argc; (void)argv;
    g_shutdown = 1;
    if (g_server.listen_fd != INVALID_SOCK) {
        close_socket(g_server.listen_fd);
        g_server.listen_fd = INVALID_SOCK;
    }
    return hajimu_bool(true);
}

static Value fn_get_port(int argc, Value *argv) {
    (void)argc; (void)argv;
    return hajimu_number(g_server.port);
}

static Value fn_is_running(int argc, Value *argv) {
    (void)argc; (void)argv;
    return hajimu_bool(g_server.running && !g_shutdown);
}


/* ================================================================= */
/* v4.0 新プラグイン関数                                               */
/* ================================================================= */

/* --- ユーザー定義ミドルウェア --- */

/* 使用(関数) or 使用(パス, 関数) — ユーザー定義ミドルウェアを登録 (v5.0: パス限定) */
static Value fn_use(int argc, Value *argv) {
    Value *fn_arg = NULL;
    const char *path = NULL;
    if (argc >= 2 && argv[0].type == VALUE_STRING &&
        (argv[1].type == VALUE_FUNCTION || argv[1].type == VALUE_BUILTIN)) {
        path = argv[0].string.data;
        fn_arg = &argv[1];
    } else if (argc >= 1 &&
               (argv[0].type == VALUE_FUNCTION || argv[0].type == VALUE_BUILTIN)) {
        fn_arg = &argv[0];
    } else {
        return hajimu_bool(false);
    }
    if (g_server.middleware_count >= HW_MAX_MIDDLEWARES)
        return hajimu_bool(false);

    Middleware *mw = &g_server.middlewares[g_server.middleware_count++];
    memset(mw, 0, sizeof(*mw));
    mw->type = MW_USER_CALLBACK;
    mw->enabled = 1;
    mw->callback_func = *fn_arg;
    if (path) {
        snprintf(mw->path, sizeof(mw->path), "%s", path);
        mw->has_path = 1;
    }
    snprintf(mw->name, sizeof(mw->name), "user_%d", g_server.middleware_count);
    if (path)
        printf("[hajimu_web] ユーザーミドルウェア追加: %s\n", path);
    else
        printf("[hajimu_web] ユーザーミドルウェア追加\n");
    return hajimu_bool(true);
}

/* --- レスポンスAPI強化 --- */

/* JSON送信(値) — コールバック内でJSON応答 */
static Value fn_json_send(int argc, Value *argv) {
    if (argc < 1) return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);
    char buf[HW_TEMPLATE_BUF];
    value_to_json(&argv[0], buf, sizeof(buf));
    snprintf(resp->content_type, sizeof(resp->content_type),
             "application/json; charset=utf-8");
    response_set_body(resp, buf, (int)strlen(buf));
    return hajimu_bool(true);
}

/* テキスト送信(文字列) */
static Value fn_text_send(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);
    snprintf(resp->content_type, sizeof(resp->content_type),
             "text/plain; charset=utf-8");
    response_set_body(resp, argv[0].string.data, argv[0].string.length);
    return hajimu_bool(true);
}

/* HTML送信(文字列) */
static Value fn_html_send(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);
    snprintf(resp->content_type, sizeof(resp->content_type),
             "text/html; charset=utf-8");
    response_set_body(resp, argv[0].string.data, argv[0].string.length);
    return hajimu_bool(true);
}

/* ファイル送信(パス, ダウンロード名?) */
static Value fn_send_file(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);
    FILE *f = fopen(argv[0].string.data, "rb");
    if (!f) return hajimu_bool(false);
    fseek(f, 0, SEEK_END); long fsize = ftell(f); fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > HW_MAX_BODY) { fclose(f); return hajimu_bool(false); }
    char *data = (char *)malloc(fsize);
    if (!data) { fclose(f); return hajimu_bool(false); }
    fread(data, 1, fsize, f); fclose(f);
    const char *mime = get_mime_type(argv[0].string.data);
    snprintf(resp->content_type, sizeof(resp->content_type), "%s", mime);
    if (argc >= 2 && argv[1].type == VALUE_STRING) {
        char cd[512];
        snprintf(cd, sizeof(cd), "attachment; filename=\"%s\"",
                 argv[1].string.data);
        response_set_header(resp, "Content-Disposition", cd);
    }
    response_set_body(resp, data, (int)fsize);
    free(data);
    return hajimu_bool(true);
}

/* --- セッション管理 --- */

/* セッション取得(キー) */
static Value fn_session_get(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_null();
    Session *s = find_session(g_server.current_session_id);
    if (!s) return hajimu_null();
    const char *v = session_get_var(s, argv[0].string.data);
    return v ? hajimu_string(v) : hajimu_null();
}

/* セッション設定(キー, 値) */
static Value fn_session_set(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_bool(false);
    Session *s = find_session(g_server.current_session_id);
    if (!s) return hajimu_bool(false);
    return hajimu_bool(session_set_var(s, argv[0].string.data,
                                        argv[1].string.data));
}

/* セッション削除(キー) */
static Value fn_session_del(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    Session *s = find_session(g_server.current_session_id);
    if (!s) return hajimu_bool(false);
    return hajimu_bool(session_delete_var(s, argv[0].string.data));
}

/* セッション破棄() */
static Value fn_session_destroy(int argc, Value *argv) {
    (void)argc; (void)argv;
    Session *s = find_session(g_server.current_session_id);
    if (s) { s->active = 0; g_server.current_session_id[0] = '\0'; }
    return hajimu_bool(s != NULL);
}

/* セッション有効期限(秒) */
static Value fn_session_timeout(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_NUMBER) return hajimu_bool(false);
    g_server.session_timeout = (int)argv[0].number;
    return hajimu_bool(true);
}

/* --- Keep-Alive 設定 --- */

/* キープアライブ(有効, タイムアウト秒?, 最大リクエスト?) */
static Value fn_keep_alive(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_BOOL)
        return hajimu_bool(false);
    g_server.keep_alive_enabled = argv[0].boolean ? 1 : 0;
    if (argc >= 2 && argv[1].type == VALUE_NUMBER)
        g_server.keep_alive_timeout = (int)argv[1].number;
    else
        g_server.keep_alive_timeout = 15;
    if (argc >= 3 && argv[2].type == VALUE_NUMBER)
        g_server.keep_alive_max_requests = (int)argv[2].number;
    else
        g_server.keep_alive_max_requests = 100;
    return hajimu_bool(true);
}

/* --- SSE --- */

/* SSE(パス, コールバック?) */
static Value fn_sse_route(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    if (g_server.route_count >= HW_MAX_ROUTES) return hajimu_bool(false);
    Route *r = &g_server.routes[g_server.route_count++];
    memset(r, 0, sizeof(*r));
    r->method = METHOD_GET;
    snprintf(r->pattern, sizeof(r->pattern), "%s", argv[0].string.data);
    r->has_callback = 1;
    r->is_wildcard = 2;  /* SSE マーカー */
    if (argc >= 2 && (argv[1].type == VALUE_FUNCTION ||
                      argv[1].type == VALUE_BUILTIN))
        r->callback_func = argv[1];
    pthread_mutex_init(&g_server.sse_mutex, NULL);
    return hajimu_bool(true);
}

/* SSE送信(パス, イベント, データ) */
static Value fn_sse_send(int argc, Value *argv) {
    if (argc < 3 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING || argv[2].type != VALUE_STRING)
        return hajimu_bool(false);
    sse_send_to_path(argv[0].string.data, argv[1].string.data,
                     argv[2].string.data);
    return hajimu_bool(true);
}

/* SSEブロードキャスト(イベント, データ) */
static Value fn_sse_broadcast(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING) return hajimu_bool(false);
    sse_send_to_path(NULL, argv[0].string.data, argv[1].string.data);
    return hajimu_bool(true);
}

/* --- エラーハンドラコールバック --- */

/* エラーハンドラ(関数) — v5.0: 複数チェーン */
static Value fn_error_handler(int argc, Value *argv) {
    if (argc < 1 || (argv[0].type != VALUE_FUNCTION &&
                     argv[0].type != VALUE_BUILTIN))
        return hajimu_bool(false);
    if (g_server.error_callback_count >= HW_MAX_ERROR_CALLBACKS)
        return hajimu_bool(false);
    g_server.error_callbacks[g_server.error_callback_count++] = argv[0];
    return hajimu_bool(true);
}

/* --- バリデーション --- */

/* バリデーション(値, ルール) */
static Value fn_validate(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    const char *value = argv[0].string.data;
    const char *rule  = argv[1].string.data;

    if (strcmp(rule, "required") == 0 ||
        strcmp(rule, "\xe5\xbf\x85\xe9\xa0\x88") == 0)     /* 必須 */
        return hajimu_bool(value[0] != '\0');

    const char *colon = strchr(rule, ':');
    if (!colon) colon = strstr(rule, "\xef\xbc\x9a"); /* ： full-width */
    if (colon) {
        int param = atoi(colon + 1);
        /* ASCII colon or UTF-8 full-width colon */
        if (strncmp(rule, "min", 3) == 0 ||
            strncmp(rule, "\xe6\x9c\x80\xe5\xb0\x8f", 6) == 0)
            return hajimu_bool((int)strlen(value) >= param);
        if (strncmp(rule, "max", 3) == 0 ||
            strncmp(rule, "\xe6\x9c\x80\xe5\xa4\xa7", 6) == 0)
            return hajimu_bool((int)strlen(value) <= param);
    }

    if (strcmp(rule, "email") == 0 ||
        strcmp(rule, "\xe3\x83\xa1\xe3\x83\xbc\xe3\x83\xab") == 0)
        return hajimu_bool(strchr(value, '@') && strchr(value, '.'));

    if (strcmp(rule, "number") == 0 ||
        strcmp(rule, "\xe6\x95\xb0\xe5\x80\xa4") == 0) {
        char *end; strtod(value, &end);
        return hajimu_bool(end != value && *end == '\0');
    }

    if (strcmp(rule, "url") == 0 || strcmp(rule, "URL") == 0)
        return hajimu_bool(strncmp(value, "http://", 7) == 0 ||
                           strncmp(value, "https://", 8) == 0);

    return hajimu_bool(true);
}

/* --- HTTPS 設定 --- */

/* HTTPS設定(証明書パス, 鍵パス) */
static Value fn_tls_config(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    snprintf(g_server.tls_cert_path, HW_MAX_PATH, "%s", argv[0].string.data);
    snprintf(g_server.tls_key_path, HW_MAX_PATH, "%s", argv[1].string.data);
    g_server.tls_enabled = 1;
#ifndef HW_ENABLE_TLS
    fprintf(stderr,
        "[hajimu_web] 警告: TLSサポートはビルド時に有効化が必要です\n"
        "  make CFLAGS=\"-DHW_ENABLE_TLS\" LDFLAGS=\"-lssl -lcrypto\"\n"
        "  本番環境では nginx/caddy 等のリバースプロキシを推奨します\n");
    g_server.tls_enabled = 0;
#endif
    return hajimu_bool(g_server.tls_enabled);
}

/* --- 圧縮設定 --- */

/* 圧縮最小サイズ(バイト) */
static Value fn_compression_min_size(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_NUMBER)
        return hajimu_bool(false);
    g_server.compression_min_size = (int)argv[0].number;
    return hajimu_bool(true);
}

/* --- アップロード設定 --- */

/* アップロードディレクトリ(パス) */
static Value fn_upload_dir(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    snprintf(g_server.upload_dir, HW_MAX_PATH, "%s", argv[0].string.data);
    return hajimu_bool(true);
}

/* アップロード最大サイズ(バイト) */
static Value fn_upload_max_size(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_NUMBER) return hajimu_bool(false);
    g_server.upload_max_size = (int)argv[0].number;
    return hajimu_bool(true);
}

/* アップロード保存(リクエスト, インデックス, 保存パス?) */
static Value fn_upload_save(int argc, Value *argv) {
    HttpRequest *req = g_server.current_req;
    if (!req) return hajimu_bool(false);
    if (argc < 1 || argv[0].type != VALUE_NUMBER) return hajimu_bool(false);
    int idx = (int)argv[0].number;
    if (idx < 0 || idx >= req->upload_count) return hajimu_bool(false);

    UploadedFile *uf = &req->uploads[idx];
    char path[HW_MAX_PATH];
    if (argc >= 2 && argv[1].type == VALUE_STRING)
        snprintf(path, sizeof(path), "%s", argv[1].string.data);
    else if (g_server.upload_dir[0])
        snprintf(path, sizeof(path), "%s/%s",
                 g_server.upload_dir, uf->filename);
    else
        snprintf(path, sizeof(path), "%s", uf->filename);

    FILE *f = fopen(path, "wb");
    if (!f) return hajimu_bool(false);
    fwrite(uf->data, 1, uf->data_len, f);
    fclose(f);
    return hajimu_string(path);
}

/* --- ルーターマウント --- */

/* マウント(プレフィックス, ルート配列)
   ルート配列 = [["GET", "/path", コールバック], ...] */
static Value fn_mount(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_ARRAY)
        return hajimu_bool(false);

    const char *prefix = argv[0].string.data;
    int count = 0;
    for (int i = 0; i < argv[1].array.length; i++) {
        Value *entry = &argv[1].array.elements[i];
        if (entry->type != VALUE_ARRAY || entry->array.length < 3)
            continue;
        Value *method_v = &entry->array.elements[0];
        Value *path_v   = &entry->array.elements[1];
        Value *handler  = &entry->array.elements[2];
        if (method_v->type != VALUE_STRING ||
            path_v->type != VALUE_STRING) continue;
        if (handler->type != VALUE_FUNCTION &&
            handler->type != VALUE_BUILTIN) continue;
        if (g_server.route_count >= HW_MAX_ROUTES) break;

        HttpMethod method = string_to_method(method_v->string.data);
        char full_path[HW_MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s%s",
                 prefix, path_v->string.data);

        Route *r = &g_server.routes[g_server.route_count++];
        memset(r, 0, sizeof(*r));
        r->method = method;
        snprintf(r->pattern, sizeof(r->pattern), "%s", full_path);
        int plen = (int)strlen(r->pattern);
        if (plen >= 2 && r->pattern[plen-1] == '*' && r->pattern[plen-2] == '/')
            r->is_wildcard = 1;
        r->has_callback = 1;
        r->callback_func = *handler;
        count++;
    }
    printf("[hajimu_web] マウント: %s (%d ルート)\n", prefix, count);
    return hajimu_number(count);
}


/* ================================================================= */
/* v5.0 新プラグイン関数                                               */
/* ================================================================= */

/* --- 動的リダイレクト (コールバック内) --- */
/* リダイレクト(URL) or リダイレクト(URL, ステータス) */
static Value fn_dynamic_redirect(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);
    int status = 302;
    if (argc >= 2 && argv[1].type == VALUE_NUMBER)
        status = (int)argv[1].number;
    resp->status_code = status;
    response_set_header(resp, "Location", argv[0].string.data);
    char body[512];
    int blen = snprintf(body, sizeof(body),
        "<!DOCTYPE html><html><body>"
        "<p>Redirecting to <a href=\"%s\">%s</a></p>"
        "</body></html>",
        argv[0].string.data, argv[0].string.data);
    response_set_body(resp, body, blen);
    return hajimu_bool(true);
}

/* --- コールバック内テンプレート描画 --- */
/* 描画(ファイル名, キー1, 値1, ...) */
static Value fn_render(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);

    TemplateVar vars[HW_MAX_TEMPLATE_VARS];
    int var_count = 0;
    for (int i = 1; i + 1 < argc && var_count < HW_MAX_TEMPLATE_VARS; i += 2) {
        if (argv[i].type == VALUE_STRING && argv[i+1].type == VALUE_STRING) {
            snprintf(vars[var_count].key, 256, "%s", argv[i].string.data);
            snprintf(vars[var_count].value, HW_MAX_HEADER_VALUE,
                     "%s", argv[i+1].string.data);
            var_count++;
        }
    }
    char *output = render_template_file(argv[0].string.data, vars, var_count);
    if (!output) return hajimu_bool(false);
    snprintf(resp->content_type, sizeof(resp->content_type),
             "text/html; charset=utf-8");
    response_set_body(resp, output, (int)strlen(output));
    free(output);
    return hajimu_bool(true);
}

/* --- Chunked Transfer Encoding --- */
/* 書き込み(データ) — チャンク転送モードでデータを送信 */
static Value fn_write_chunk(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    socket_t fd = g_server.current_fd;
    if (!resp || fd == INVALID_SOCK) return hajimu_bool(false);

    if (!resp->sent) {
        /* 最初の書き込み: ヘッダーを送信 */
        resp->sent = 1;
        char date[64];
        get_http_date(date, sizeof(date));
        char hdr[2048];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Date: %s\r\n"
            "Server: hajimu_web/5.0.0\r\n"
            "Connection: %s\r\n",
            resp->status_code, status_text(resp->status_code),
            resp->content_type, date,
            g_server.keep_alive_enabled ? "keep-alive" : "close");
        for (int i = 0; i < resp->header_count; i++)
            hlen += snprintf(hdr + hlen, sizeof(hdr) - hlen,
                "%s: %s\r\n", resp->headers[i].key, resp->headers[i].value);
        hlen += snprintf(hdr + hlen, sizeof(hdr) - hlen, "\r\n");
        send(fd, hdr, hlen, 0);
        g_server.chunked_started = 1;
    }
    /* チャンクデータ送信 */
    char chunk_hdr[32];
    int ch = snprintf(chunk_hdr, sizeof(chunk_hdr), "%x\r\n",
                      argv[0].string.length);
    send(fd, chunk_hdr, ch, 0);
    send(fd, argv[0].string.data, argv[0].string.length, 0);
    send(fd, "\r\n", 2, 0);
    return hajimu_bool(true);
}

/* 終了(データ?) — チャンク転送を終了 */
static Value fn_end_chunk(int argc, Value *argv) {
    HttpResponse *resp = g_server.current_resp;
    socket_t fd = g_server.current_fd;
    if (!resp || fd == INVALID_SOCK) return hajimu_bool(false);

    if (argc >= 1 && argv[0].type == VALUE_STRING)
        fn_write_chunk(argc, argv);

    /* 終端チャンク */
    send(fd, "0\r\n\r\n", 5, 0);
    resp->sent = 1;
    g_server.chunked_started = 0;
    return hajimu_bool(true);
}

/* --- コンテンツネゴシエーション --- */
/* 受入確認(タイプ) — Accept ヘッダーに指定タイプが含まれるか */
static Value fn_accepts(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    HttpRequest *req = g_server.current_req;
    if (!req) return hajimu_bool(false);
    const char *accept = get_header(req, "Accept");
    if (!accept) return hajimu_bool(false);
    const char *type = argv[0].string.data;
    /* 完全一致 or サブタイプワイルドカード */
    if (strstr(accept, type)) return hajimu_bool(true);
    if (strstr(accept, "*/*")) return hajimu_bool(true);
    /* メジャータイプチェック (e.g. text/star for text/html) */
    char major[64];
    snprintf(major, sizeof(major), "%s", type);
    char *slash = strchr(major, '/');
    if (slash) {
        snprintf(slash, sizeof(major) - (slash - major), "/*");
        if (strstr(accept, major)) return hajimu_bool(true);
    }
    return hajimu_bool(false);
}

/* フォーマット応答(配列) — Content Negotiation で応答切替
   配列 = [["text/html", コールバック], ["application/json", コールバック], ...] */
static Value fn_format(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_ARRAY) return hajimu_bool(false);
    HttpRequest *req = g_server.current_req;
    if (!req) return hajimu_bool(false);
    const char *accept = get_header(req, "Accept");
    if (!accept) accept = "*/*";

    for (int i = 0; i < argv[0].array.length; i++) {
        Value *entry = &argv[0].array.elements[i];
        if (entry->type != VALUE_ARRAY || entry->array.length < 2) continue;
        if (entry->array.elements[0].type != VALUE_STRING) continue;
        const char *type = entry->array.elements[0].string.data;
        if (strstr(accept, type) || strstr(accept, "*/*")) {
            Value *handler = &entry->array.elements[1];
            if (handler->type == VALUE_FUNCTION || handler->type == VALUE_BUILTIN) {
                HttpResponse *resp = g_server.current_resp;
                if (resp)
                    snprintf(resp->content_type, sizeof(resp->content_type),
                             "%s", type);
                Value rv = hajimu_call(handler, 0, NULL);
                return rv;
            } else if (handler->type == VALUE_STRING) {
                return *handler;
            }
        }
    }
    return hajimu_bool(false);
}

/* --- ヘッダーユーティリティ --- */

/* ヘッダー追加(キー, 値) — 既存ヘッダーにカンマ区切りで追記 */
static Value fn_append_header(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);
    /* 既存ヘッダー検索 */
    for (int i = 0; i < resp->header_count; i++) {
        if (strcasecmp(resp->headers[i].key, argv[0].string.data) == 0) {
            char combined[HW_MAX_HEADER_VALUE];
            snprintf(combined, sizeof(combined), "%s, %s",
                     resp->headers[i].value, argv[1].string.data);
            snprintf(resp->headers[i].value, HW_MAX_HEADER_VALUE, "%s", combined);
            return hajimu_bool(true);
        }
    }
    /* 新規追加 */
    response_set_header(resp, argv[0].string.data, argv[1].string.data);
    return hajimu_bool(true);
}

/* Location設定(URL) */
static Value fn_location(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);
    response_set_header(resp, "Location", argv[0].string.data);
    return hajimu_bool(true);
}

/* ダウンロード(パス, ファイル名?) — Content-Disposition: attachment */
static Value fn_download(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    HttpResponse *resp = g_server.current_resp;
    if (!resp) return hajimu_bool(false);
    FILE *f = fopen(argv[0].string.data, "rb");
    if (!f) return hajimu_bool(false);
    fseek(f, 0, SEEK_END); long fsize = ftell(f); fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > HW_MAX_BODY) { fclose(f); return hajimu_bool(false); }
    char *data = (char *)malloc(fsize);
    if (!data) { fclose(f); return hajimu_bool(false); }
    fread(data, 1, fsize, f); fclose(f);
    const char *mime = get_mime_type(argv[0].string.data);
    snprintf(resp->content_type, sizeof(resp->content_type), "%s", mime);
    /* ファイル名決定 */
    const char *dl_name = argv[0].string.data;
    if (argc >= 2 && argv[1].type == VALUE_STRING)
        dl_name = argv[1].string.data;
    else {
        const char *sl = strrchr(dl_name, '/');
        if (sl) dl_name = sl + 1;
    }
    char cd[512];
    snprintf(cd, sizeof(cd), "attachment; filename=\"%s\"", dl_name);
    response_set_header(resp, "Content-Disposition", cd);
    response_set_body(resp, data, (int)fsize);
    free(data);
    return hajimu_bool(true);
}

/* --- ホスト名・プロトコル取得 --- */

/* ホスト名取得() */
static Value fn_hostname(int argc, Value *argv) {
    (void)argc; (void)argv;
    HttpRequest *req = g_server.current_req;
    if (!req) return hajimu_string("");
    const char *host = get_header(req, "Host");
    if (!host) return hajimu_string("");
    char hn[256];
    snprintf(hn, sizeof(hn), "%s", host);
    char *colon = strchr(hn, ':');
    if (colon) *colon = '\0';
    return hajimu_string(hn);
}

/* プロトコル取得() */
static Value fn_protocol(int argc, Value *argv) {
    (void)argc; (void)argv;
    if (g_server.tls_enabled) return hajimu_string("https");
    if (g_server.trust_proxy && g_server.current_req) {
        const char *fp = get_header(g_server.current_req, "X-Forwarded-Proto");
        if (fp) return hajimu_string(fp);
    }
    return hajimu_string("http");
}

/* 安全確認() — HTTPS かどうか */
static Value fn_is_secure(int argc, Value *argv) {
    (void)argc; (void)argv;
    Value proto = fn_protocol(0, NULL);
    return hajimu_bool(proto.type == VALUE_STRING &&
                       strcmp(proto.string.data, "https") == 0);
}

/* --- 設定関数 --- */

/* 静的ファイル追加(パス) — 追加の静的ファイルディレクトリ */
static Value fn_static_dir_add(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_STRING)
        return hajimu_bool(false);
    if (g_server.static_dir_extra_count >= HW_MAX_STATIC_DIRS)
        return hajimu_bool(false);
    int idx = g_server.static_dir_extra_count++;
    snprintf(g_server.static_dirs_extra[idx], HW_MAX_PATH,
             "%s", argv[0].string.data);
    int len = (int)strlen(g_server.static_dirs_extra[idx]);
    if (len > 0 && g_server.static_dirs_extra[idx][len-1] == '/')
        g_server.static_dirs_extra[idx][len-1] = '\0';
    printf("[hajimu_web] 追加静的ファイル: %s\n", g_server.static_dirs_extra[idx]);
    return hajimu_bool(true);
}

/* ディレクトリ一覧設定(有効) */
static Value fn_directory_listing(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_BOOL) return hajimu_bool(false);
    g_server.directory_listing = argv[0].boolean ? 1 : 0;
    return hajimu_bool(true);
}

/* 信頼プロキシ(有効) */
static Value fn_trust_proxy(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_BOOL) return hajimu_bool(false);
    g_server.trust_proxy = argv[0].boolean ? 1 : 0;
    return hajimu_bool(true);
}

/* 最大スレッド数(数) */
static Value fn_max_threads(int argc, Value *argv) {
    if (argc < 1 || argv[0].type != VALUE_NUMBER) return hajimu_bool(false);
    int n = (int)argv[0].number;
    if (n < 1) n = 1;
    if (n > 256) n = 256;
    g_server.max_threads = n;
    return hajimu_bool(true);
}

/* ================================================================= */
/* 関数テーブル（v5.0 全機能）                                              */
/* ================================================================= */

static HajimuPluginFunc functions[] = {
    /* サーバー管理 (6) */
    {"サーバー作成",         fn_server_create,      1, 1},
    {"起動",               fn_server_start,        0, 0},
    {"停止",               fn_server_stop,         0, 0},
    {"ポート取得",          fn_get_port,            0, 0},
    {"実行中",             fn_is_running,          0, 0},
    {"サーバー情報",        fn_server_info,         0, 0},
    /* ミドルウェア (2) */
    {"ミドルウェア",         fn_middleware,           1, 1},
    {"ミドルウェア一覧",     fn_middleware_list,      0, 0},
    /* ルーティング (10) */
    {"ルート追加",          fn_route_add,            5, 5},
    {"GET",                fn_get,                  2, 2},
    {"POST",               fn_post,                 2, 4},
    {"PUT",                fn_put,                  2, 2},
    {"DELETE",             fn_delete,               2, 2},
    {"PATCH",              fn_patch,                2, 2},
    {"ALL",                fn_all_methods,          2, 2},
    {"JSON応答",           fn_json_route,           3, 3},
    {"JSON_POST",          fn_json_post,            3, 3},
    {"ルート一覧",          fn_route_list,           0, 0},
    /* ルートグループ (2) */
    {"グループ",            fn_group,                1, 1},
    {"グループ終了",        fn_group_end,            0, 0},
    /* エラーハンドリング (2) */
    {"エラーページ",        fn_error_page,           3, 3},
    {"JSONエラーページ",    fn_json_error_page,      2, 2},
    /* テンプレート (5) */
    {"テンプレートディレクトリ",  fn_template_dir,         1, 1},
    {"テンプレート変数",         fn_template_var,         2, 2},
    {"テンプレート描画",         fn_template_render,      1, -1},
    {"テンプレート文字列",       fn_template_string,      1, -1},
    {"テンプレートGET",         fn_template_get,         2, -1},
    /* レスポンスヘルパー (2) */
    {"リダイレクト応答",    fn_redirect,             2, 3},
    {"リダイレクト",        fn_dynamic_redirect,     1, 2},
    /* Cookie (2) */
    {"Cookie設定",         fn_set_cookie,           2, 3},
    {"Cookie削除",         fn_delete_cookie,        1, 1},
    /* レスポンス制御 (3) */
    {"ヘッダー設定",        fn_set_header,           2, 2},
    {"ステータス設定",      fn_set_status,           1, 1},
    {"コンテンツタイプ設定", fn_set_content_type,     1, 1},
    /* JSON ユーティリティ (2) */
    {"JSON解析",           fn_json_parse,           1, 1},
    {"JSON生成",           fn_json_stringify,       1, 1},
    /* 設定 (5) */
    {"静的ファイル",        fn_static_dir,           1, 1},
    {"静的キャッシュ",      fn_static_cache,         1, 1},
    {"CORS有効",           fn_cors_enable,          0, 0},
    {"CORS設定",           fn_cors_config,          1, 3},
    {"レート制限設定",      fn_rate_limit_config,    1, 2},
    /* v4.0 ユーザー定義ミドルウェア (1) */
    {"使用",               fn_use,                  1, 2},
    /* v4.0 レスポンスAPI (4) */
    {"JSON送信",           fn_json_send,            1, 1},
    {"テキスト送信",        fn_text_send,            1, 1},
    {"HTML送信",           fn_html_send,            1, 1},
    {"ファイル送信",        fn_send_file,            1, 2},
    /* v4.0 セッション管理 (5) */
    {"セッション取得",      fn_session_get,          1, 1},
    {"セッション設定",      fn_session_set,          2, 2},
    {"セッション削除",      fn_session_del,          1, 1},
    {"セッション破棄",      fn_session_destroy,      0, 0},
    {"セッション有効期限",   fn_session_timeout,      1, 1},
    /* v4.0 Keep-Alive (1) */
    {"キープアライブ",      fn_keep_alive,           1, 3},
    /* v4.0 SSE (3) */
    {"SSE",                fn_sse_route,            1, 2},
    {"SSE送信",            fn_sse_send,             3, 3},
    {"SSEブロードキャスト",  fn_sse_broadcast,        2, 2},
    /* v4.0 エラーハンドラ (1) */
    {"エラーハンドラ",      fn_error_handler,        1, 1},
    /* v4.0 バリデーション (1) */
    {"バリデーション",      fn_validate,             2, 2},
    /* v4.0 HTTPS (1) */
    {"HTTPS設定",          fn_tls_config,           2, 2},
    /* v4.0 圧縮設定 (1) */
    {"圧縮最小サイズ",      fn_compression_min_size, 1, 1},
    /* v4.0 アップロード (3) */
    {"アップロードディレクトリ", fn_upload_dir,       1, 1},
    {"アップロード最大サイズ",   fn_upload_max_size,  1, 1},
    {"アップロード保存",        fn_upload_save,      1, 2},
    /* v4.0 ルーターマウント (1) */
    {"マウント",            fn_mount,                2, 2},
    /* v5.0 テンプレート描画 (1) */
    {"描画",               fn_render,               1, -1},
    /* v5.0 Chunked Transfer (2) */
    {"書き込み",            fn_write_chunk,          1, 1},
    {"応答終了",            fn_end_chunk,            0, 1},
    /* v5.0 コンテンツネゴシエーション (2) */
    {"受入確認",            fn_accepts,              1, 1},
    {"フォーマット応答",     fn_format,               1, 1},
    /* v5.0 ヘッダーユーティリティ (2) */
    {"ヘッダー追加",        fn_append_header,        2, 2},
    {"Location設定",       fn_location,             1, 1},
    /* v5.0 ダウンロード (1) */
    {"ダウンロード",        fn_download,             1, 2},
    /* v5.0 ホスト・プロトコル (3) */
    {"ホスト名取得",        fn_hostname,             0, 0},
    {"プロトコル取得",      fn_protocol,             0, 0},
    {"安全確認",            fn_is_secure,            0, 0},
    /* v5.0 設定 (4) */
    {"静的ファイル追加",    fn_static_dir_add,       1, 1},
    {"ディレクトリ一覧",    fn_directory_listing,    1, 1},
    {"信頼プロキシ",        fn_trust_proxy,          1, 1},
    {"最大スレッド数",      fn_max_threads,          1, 1},
};

/* ================================================================= */
/* プラグイン初期化                                                    */
/* ================================================================= */

HAJIMU_PLUGIN_EXPORT HajimuPluginInfo *hajimu_plugin_init(void) {
    static HajimuPluginInfo info = {
        .name           = "hajimu_web",
        .version        = "5.0.0",
        .author         = "はじむ開発チーム",
        .description    = "HTTP ウェブサーバー v5 — スレッドプール・Keep-Alive・Chunked・Range・コンテンツネゴシエーション・全Express機能対応",
        .functions      = functions,
        .function_count = sizeof(functions) / sizeof(functions[0]),
    };
    return &info;
}
