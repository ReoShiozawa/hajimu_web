/**
 * hajimu_web — はじむ用 HTTP ウェブサーバープラグイン v2.0
 *
 * Python の Flask / Node.js の Express に相当する本格的な HTTP サーバー。
 * 統一拡張子 .hjp（Hajimu Plugin）でクロスプラットフォーム対応。
 *
 * === v2.0 新機能 ===
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

#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>

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
    MW_CUSTOM,
} MiddlewareType;

typedef struct {
    MiddlewareType type;
    char   name[64];
    int    enabled;
    int  (*before)(HttpRequest *req, HttpResponse *resp);
    void (*after)(HttpRequest *req, HttpResponse *resp);
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
} WebServer;

static WebServer g_server = {0};
static volatile int g_shutdown = 0;

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

    /* パラメータ付きルート :param */
    const char *pp = pattern;
    const char *rp = path;
    while (*pp && *rp) {
        if (*pp == ':') {
            pp++;
            char param_name[256] = {0};
            int ni = 0;
            while (*pp && *pp != '/' && ni < 255)
                param_name[ni++] = *pp++;
            param_name[ni] = '\0';

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
        "Server: hajimu_web/2.0.0\r\n"
        "Connection: close\r\n",
        resp->status_code, status_text(resp->status_code),
        resp->content_type, resp->body_length, date);

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

static void send_error(socket_t fd, int status_code, const char *message) {
    /* カスタムエラーハンドラを検索 */
    for (int i = 0; i < g_server.error_handler_count; i++) {
        ErrorHandler *eh = &g_server.error_handlers[i];
        if (eh->status_code == status_code || eh->status_code == 0) {
            send_response(fd, status_code,
                          eh->content_type, eh->body, eh->body_len);
            g_server.error_count++;
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
    g_server.error_count++;
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

static int serve_static_file(socket_t fd, const HttpRequest *req) {
    if (g_server.static_dir[0] == '\0') return 0;

    /* ディレクトリトラバーサル防止 */
    if (strstr(req->path, "..") != NULL) {
        send_error(fd, 403, NULL);
        return 1;
    }

    char filepath[HW_MAX_PATH];
    const char *req_path = req->path;
    if (strcmp(req_path, "/") == 0) req_path = "/index.html";
    snprintf(filepath, sizeof(filepath), "%s%s",
             g_server.static_dir, req_path);

    /* ディレクトリの場合 index.html を探す */
    struct stat st;
    if (stat(filepath, &st) == 0 && S_ISDIR(st.st_mode)) {
        char idx_path[HW_MAX_PATH];
        snprintf(idx_path, sizeof(idx_path), "%s/index.html", filepath);
        if (stat(idx_path, &st) == 0)
            snprintf(filepath, sizeof(filepath), "%s", idx_path);
        else
            return 0;
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

    char date[64];
    get_http_date(date, sizeof(date));

    char header[2048];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Date: %s\r\n"
        "Server: hajimu_web/2.0.0\r\n"
        "Connection: close\r\n",
        mime, file_size, date);

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

    /* セキュリティミドルウェアのヘッダー */
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

    char buf[HW_STATIC_BUF];
    size_t nread;
    while ((nread = fread(buf, 1, sizeof(buf), f)) > 0)
        send(fd, buf, (int)nread, 0);
    fclose(f);
    return 1;
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

static int run_middlewares_before(HttpRequest *req, HttpResponse *resp) {
    for (int i = 0; i < g_server.middleware_count; i++) {
        Middleware *mw = &g_server.middlewares[i];
        if (!mw->enabled) continue;
        int result = 0;
        switch (mw->type) {
            case MW_LOGGER:   result = middleware_logger_before(req, resp); break;
            case MW_CORS:     result = middleware_cors_before(req, resp); break;
            case MW_SECURITY: result = middleware_security_before(req, resp); break;
            case MW_CUSTOM:   if (mw->before) result = mw->before(req, resp); break;
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

    /* [5] headers [[key, value], ...] */
    Value headers = hajimu_array();
    for (int i = 0; i < req->header_count; i++) {
        Value pair = hajimu_array();
        hajimu_array_push(&pair, hajimu_string(req->headers[i].key));
        hajimu_array_push(&pair, hajimu_string(req->headers[i].value));
        hajimu_array_push(&headers, pair);
    }
    hajimu_array_push(&arr, headers);

    /* [6] params [[key, value], ...] */
    Value params = hajimu_array();
    for (int i = 0; i < req->param_count; i++) {
        Value pair = hajimu_array();
        hajimu_array_push(&pair, hajimu_string(req->params[i].key));
        hajimu_array_push(&pair, hajimu_string(req->params[i].value));
        hajimu_array_push(&params, pair);
    }
    hajimu_array_push(&arr, params);

    /* [7] query [[key, value], ...] */
    Value query_params = hajimu_array();
    for (int i = 0; i < req->query_count; i++) {
        Value pair = hajimu_array();
        hajimu_array_push(&pair, hajimu_string(req->query[i].key));
        hajimu_array_push(&pair, hajimu_string(req->query[i].value));
        hajimu_array_push(&query_params, pair);
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

    /* [9] form_fields [[key, value], ...] */
    Value form_fields = hajimu_array();
    for (int i = 0; i < req->parsed_body.field_count; i++) {
        Value pair = hajimu_array();
        hajimu_array_push(&pair,
            hajimu_string(req->parsed_body.fields[i].key));
        hajimu_array_push(&pair,
            hajimu_string(req->parsed_body.fields[i].value));
        hajimu_array_push(&form_fields, pair);
    }
    hajimu_array_push(&arr, form_fields);

    /* [10] cookies [[key, value], ...] */
    Value cookies = hajimu_array();
    for (int i = 0; i < req->cookie_count; i++) {
        Value pair = hajimu_array();
        hajimu_array_push(&pair, hajimu_string(req->cookies[i].key));
        hajimu_array_push(&pair, hajimu_string(req->cookies[i].value));
        hajimu_array_push(&cookies, pair);
    }
    hajimu_array_push(&arr, cookies);

    return arr;
}

/* ================================================================= */
/* リクエスト処理（メインハンドラ）                                     */
/* ================================================================= */

static void handle_client(socket_t client_fd, struct sockaddr_in *addr) {
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
    snprintf(req.client_ip, sizeof(req.client_ip), "%s", client_ip);

    /* ボディ自動解析 */
    auto_parse_body(&req);
    g_server.total_requests++;

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

    if (route) {
        if (route->has_static_response) {
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

    if (resp.body) free(resp.body);
    if (req.body)  free(req.body);
    free(raw);
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
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    return add_route(METHOD_GET, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_post(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING) return hajimu_bool(false);
    if (argc >= 4 && argv[1].type == VALUE_NUMBER)
        return add_route(METHOD_POST, argv[0].string.data,
                         (int)argv[1].number, argv[2].string.data,
                         argv[3].string.data);
    if (argv[1].type != VALUE_STRING) return hajimu_bool(false);
    return add_route(METHOD_POST, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_put(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    return add_route(METHOD_PUT, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_delete(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    return add_route(METHOD_DELETE, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_patch(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
        return hajimu_bool(false);
    return add_route(METHOD_PATCH, argv[0].string.data, 200,
                     "text/html; charset=utf-8", argv[1].string.data);
}

static Value fn_all_methods(int argc, Value *argv) {
    if (argc < 2 || argv[0].type != VALUE_STRING ||
        argv[1].type != VALUE_STRING)
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
    printf("  |   はじむウェブ v2.0 サーバー起動          |\n");
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

    /* メインイベントループ */
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

    /* クリーンアップ */
    if (g_server.listen_fd != INVALID_SOCK) {
        close_socket(g_server.listen_fd);
        g_server.listen_fd = INVALID_SOCK;
    }
    g_server.running = 0;

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
/* 関数テーブル（32関数）                                              */
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
    /* レスポンスヘルパー (1) */
    {"リダイレクト応答",    fn_redirect,             2, 3},
    /* 設定 (4) */
    {"静的ファイル",        fn_static_dir,           1, 1},
    {"静的キャッシュ",      fn_static_cache,         1, 1},
    {"CORS有効",           fn_cors_enable,          0, 0},
    {"CORS設定",           fn_cors_config,          1, 3},
};

/* ================================================================= */
/* プラグイン初期化                                                    */
/* ================================================================= */

HAJIMU_PLUGIN_EXPORT HajimuPluginInfo *hajimu_plugin_init(void) {
    static HajimuPluginInfo info = {
        .name           = "hajimu_web",
        .version        = "2.0.0",
        .author         = "はじむ開発チーム",
        .description    = "HTTP ウェブサーバー v2 — ミドルウェア・テンプレート・エラーハンドリング対応",
        .functions      = functions,
        .function_count = sizeof(functions) / sizeof(functions[0]),
    };
    return &info;
}
