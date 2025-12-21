/*
 * HTTP protocol for ffmpeg client
 * Copyright (c) 2000, 2001 Fabrice Bellard
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdbool.h>

#include "config.h"
#include "config_components.h"

#include <string.h>
#include <time.h>
#if CONFIG_ZLIB
#include <zlib.h>
#endif /* CONFIG_ZLIB */
#if CONFIG_LIBNGHTTP2
#include <nghttp2/nghttp2.h>
#endif /* CONFIG_LIBNGHTTP2 */

#include "libavutil/avassert.h"
#include "libavutil/avstring.h"
#include "libavutil/bprint.h"
#include "libavutil/getenv_utf8.h"
#include "libavutil/macros.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/parseutils.h"

#include "avformat.h"
#include "http.h"
#include "httpauth.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#include "version.h"

/* XXX: POST protocol is not completely implemented because ffmpeg uses
 * only a subset of it. */

/* The IO buffer size is unrelated to the max URL size in itself, but needs
 * to be large enough to fit the full request headers (including long
 * path names). */
#define BUFFER_SIZE   (MAX_URL_SIZE + HTTP_HEADERS_SIZE)
#define MAX_REDIRECTS 8
#define MAX_CACHED_REDIRECTS 32
#define HTTP_SINGLE   1
#define HTTP_MUTLI    2
#define MAX_DATE_LEN  19
#define WHITESPACES " \n\t\r"
typedef enum {
    LOWER_PROTO,
    READ_HEADERS,
    WRITE_REPLY_HEADERS,
    FINISH
}HandshakeState;

typedef struct HTTPContext {
    const AVClass *class;
    URLContext *hd;
    unsigned char buffer[BUFFER_SIZE], *buf_ptr, *buf_end;
    int line_count;
    int http_code;
    /* Used if "Transfer-Encoding: chunked" otherwise -1. */
    uint64_t chunksize;
    int chunkend;
    uint64_t off, end_off, filesize;
    char *uri;
    char *location;
    HTTPAuthState auth_state;
    HTTPAuthState proxy_auth_state;
    char *http_proxy;
    char *headers;
    char *mime_type;
    char *http_version;
    char *user_agent;
    char *referer;
    char *content_type;
    /* Set if the server correctly handles Connection: close and will close
     * the connection after feeding us the content. */
    int willclose;
    int seekable;           /**< Control seekability, 0 = disable, 1 = enable, -1 = probe. */
    int chunked_post;
    /* A flag which indicates if the end of chunked encoding has been sent. */
    int end_chunked_post;
    /* A flag which indicates we have finished to read POST reply. */
    int end_header;
    /* A flag which indicates if we use persistent connections. */
    int multiple_requests;
    uint8_t *post_data;
    int post_datalen;
    int is_akamai;
    int is_mediagateway;
    char *cookies;          ///< holds newline (\n) delimited Set-Cookie header field values (without the "Set-Cookie: " field name)
    /* A dictionary containing cookies keyed by cookie name */
    AVDictionary *cookie_dict;
    int icy;
    /* how much data was read since the last ICY metadata packet */
    uint64_t icy_data_read;
    /* after how many bytes of read data a new metadata packet will be found */
    uint64_t icy_metaint;
    char *icy_metadata_headers;
    char *icy_metadata_packet;
    AVDictionary *metadata;
#if CONFIG_ZLIB
    int compressed;
    z_stream inflate_stream;
    uint8_t *inflate_buffer;
#endif /* CONFIG_ZLIB */
    AVDictionary *chained_options;
    /* -1 = try to send if applicable, 0 = always disabled, 1 = always enabled */
    int send_expect_100;
    char *method;
    int reconnect;
    int reconnect_at_eof;
    int reconnect_on_network_error;
    int reconnect_streamed;
    int reconnect_delay_max;
    char *reconnect_on_http_error;
    int listen;
    char *resource;
    int reply_code;
    int is_multi_client;
    HandshakeState handshake_step;
    int is_connected_server;
    int short_seek_size;
    int64_t expires;
    char *new_location;
    AVDictionary *redirect_cache;
    uint64_t filesize_from_content_range;
    int respect_retry_after;
    unsigned int retry_after;
    int reconnect_max_retries;
    int reconnect_delay_total_max;
#if CONFIG_LIBNGHTTP2
    int http2;                  /**< Enable HTTP/2 support, -1 = auto, 0 = off, 1 = on */
    int is_http2;               /**< Currently using HTTP/2 */
    nghttp2_session *h2_session;
    int32_t h2_stream_id;       /**< Current HTTP/2 stream ID */
    uint8_t *h2_recv_buf;       /**< Buffer for received HTTP/2 data */
    size_t h2_recv_buf_size;
    size_t h2_recv_buf_len;
    size_t h2_recv_buf_pos;
    int h2_stream_closed;       /**< HTTP/2 stream has been closed */
    int h2_goaway;              /**< Received GOAWAY frame */
#endif /* CONFIG_LIBNGHTTP2 */
} HTTPContext;

#define OFFSET(x) offsetof(HTTPContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
#define DEFAULT_USER_AGENT "Lavf/" AV_STRINGIFY(LIBAVFORMAT_VERSION)

static const AVOption options[] = {
    { "seekable", "control seekability of connection", OFFSET(seekable), AV_OPT_TYPE_BOOL, { .i64 = -1 }, -1, 1, D },
    { "chunked_post", "use chunked transfer-encoding for posts", OFFSET(chunked_post), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, E },
    { "http_proxy", "set HTTP proxy to tunnel through", OFFSET(http_proxy), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "headers", "set custom HTTP headers, can override built in default headers", OFFSET(headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "content_type", "set a specific content type for the POST messages", OFFSET(content_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "user_agent", "override User-Agent header", OFFSET(user_agent), AV_OPT_TYPE_STRING, { .str = DEFAULT_USER_AGENT }, 0, 0, D },
    { "referer", "override referer header", OFFSET(referer), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "multiple_requests", "use persistent connections", OFFSET(multiple_requests), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D | E },
    { "post_data", "set custom HTTP post data", OFFSET(post_data), AV_OPT_TYPE_BINARY, .flags = D | E },
    { "mime_type", "export the MIME type", OFFSET(mime_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },
    { "http_version", "export the http response version", OFFSET(http_version), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },
    { "cookies", "set cookies to be sent in applicable future requests, use newline delimited Set-Cookie HTTP field value syntax", OFFSET(cookies), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "icy", "request ICY metadata", OFFSET(icy), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, D },
    { "icy_metadata_headers", "return ICY metadata headers", OFFSET(icy_metadata_headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "icy_metadata_packet", "return current ICY metadata packet", OFFSET(icy_metadata_packet), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "metadata", "metadata read from the bitstream", OFFSET(metadata), AV_OPT_TYPE_DICT, {0}, 0, 0, AV_OPT_FLAG_EXPORT },
    { "auth_type", "HTTP authentication type", OFFSET(auth_state.auth_type), AV_OPT_TYPE_INT, { .i64 = HTTP_AUTH_NONE }, HTTP_AUTH_NONE, HTTP_AUTH_BASIC, D | E, .unit = "auth_type"},
    { "none", "No auth method set, autodetect", 0, AV_OPT_TYPE_CONST, { .i64 = HTTP_AUTH_NONE }, 0, 0, D | E, .unit = "auth_type"},
    { "basic", "HTTP basic authentication", 0, AV_OPT_TYPE_CONST, { .i64 = HTTP_AUTH_BASIC }, 0, 0, D | E, .unit = "auth_type"},
    { "send_expect_100", "Force sending an Expect: 100-continue header for POST", OFFSET(send_expect_100), AV_OPT_TYPE_BOOL, { .i64 = -1 }, -1, 1, E },
    { "location", "The actual location of the data received", OFFSET(location), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "offset", "initial byte offset", OFFSET(off), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "end_offset", "try to limit the request to bytes preceding this offset", OFFSET(end_off), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "method", "Override the HTTP method or set the expected HTTP method from a client", OFFSET(method), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "reconnect", "auto reconnect after disconnect before EOF", OFFSET(reconnect), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_at_eof", "auto reconnect at EOF", OFFSET(reconnect_at_eof), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_on_network_error", "auto reconnect in case of tcp/tls error during connect", OFFSET(reconnect_on_network_error), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_on_http_error", "list of http status codes to reconnect on", OFFSET(reconnect_on_http_error), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "reconnect_streamed", "auto reconnect streamed / non seekable streams", OFFSET(reconnect_streamed), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_delay_max", "max reconnect delay in seconds after which to give up", OFFSET(reconnect_delay_max), AV_OPT_TYPE_INT, { .i64 = 120 }, 0, UINT_MAX/1000/1000, D },
    { "reconnect_max_retries", "the max number of times to retry a connection", OFFSET(reconnect_max_retries), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, D },
    { "reconnect_delay_total_max", "max total reconnect delay in seconds after which to give up", OFFSET(reconnect_delay_total_max), AV_OPT_TYPE_INT, { .i64 = 256 }, 0, UINT_MAX/1000/1000, D },
    { "respect_retry_after", "respect the Retry-After header when retrying connections", OFFSET(respect_retry_after), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, D },
    { "listen", "listen on HTTP", OFFSET(listen), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, 2, D | E },
    { "resource", "The resource requested by a client", OFFSET(resource), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, E },
    { "reply_code", "The http status code to return to a client", OFFSET(reply_code), AV_OPT_TYPE_INT, { .i64 = 200}, INT_MIN, 599, E},
    { "short_seek_size", "Threshold to favor readahead over seek.", OFFSET(short_seek_size), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, D },
#if CONFIG_LIBNGHTTP2
    { "http2", "Enable HTTP/2 support", OFFSET(http2), AV_OPT_TYPE_BOOL, { .i64 = -1 }, -1, 1, D },
#endif
    { NULL }
};

static int http_connect(URLContext *h, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth);
static int http_read_header(URLContext *h);
static int http_shutdown(URLContext *h, int flags);

#if CONFIG_LIBNGHTTP2
/* HTTP/2 buffer size for received data */
#define H2_RECV_BUF_SIZE (256 * 1024)

static ssize_t h2_send_callback(nghttp2_session *session,
                                const uint8_t *data, size_t length,
                                int flags, void *user_data)
{
    URLContext *h = user_data;
    HTTPContext *s = h->priv_data;
    int ret;

    ret = ffurl_write(s->hd, data, length);
    if (ret < 0) {
        if (ret == AVERROR(EAGAIN))
            return NGHTTP2_ERR_WOULDBLOCK;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return ret;
}

static int h2_on_header_callback(nghttp2_session *session,
                                 const nghttp2_frame *frame,
                                 const uint8_t *name, size_t namelen,
                                 const uint8_t *value, size_t valuelen,
                                 uint8_t flags, void *user_data)
{
    URLContext *h = user_data;
    HTTPContext *s = h->priv_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_RESPONSE)
        return 0;

    if (namelen == 7 && !memcmp(name, ":status", 7)) {
        s->http_code = atoi((const char *)value);
        av_log(h, AV_LOG_DEBUG, "HTTP/2 status: %d\n", s->http_code);
    } else if (namelen == 14 && !av_strncasecmp((const char *)name, "content-length", 14)) {
        s->filesize = strtoull((const char *)value, NULL, 10);
    } else if (namelen == 12 && !av_strncasecmp((const char *)name, "content-type", 12)) {
        av_freep(&s->mime_type);
        s->mime_type = av_strndup((const char *)value, valuelen);
    } else if (namelen == 8 && !av_strncasecmp((const char *)name, "location", 8)) {
        /* Resolve relative URLs against current location, like HTTP/1.1 does */
        char redirected_location[MAX_URL_SIZE];
        char *raw_location = av_strndup((const char *)value, valuelen);
        if (!raw_location)
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        ff_make_absolute_url(redirected_location, sizeof(redirected_location),
                             s->location, raw_location);
        av_freep(&raw_location);
        av_freep(&s->new_location);
        s->new_location = av_strdup(redirected_location);
        if (!s->new_location)
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        av_log(h, AV_LOG_DEBUG, "HTTP/2 location: %s (resolved from %.*s)\n",
               s->new_location, (int)valuelen, value);
    } else if (namelen == 16 && !av_strncasecmp((const char *)name, "content-encoding", 16)) {
        /* Handle compression like HTTP/1.1 does */
        av_log(h, AV_LOG_DEBUG, "HTTP/2 content-encoding: %.*s\n", (int)valuelen, value);
#if CONFIG_ZLIB
        if (!av_strncasecmp((const char *)value, "gzip", 4) ||
            !av_strncasecmp((const char *)value, "deflate", 7)) {
            s->compressed = 1;
            inflateEnd(&s->inflate_stream);
            if (inflateInit2(&s->inflate_stream, 32 + 15) != Z_OK) {
                av_log(h, AV_LOG_WARNING, "Failed to init zlib for HTTP/2\n");
                s->compressed = 0;
            }
        }
#endif
    } else if (namelen == 13 && !av_strncasecmp((const char *)name, "accept-ranges", 13)) {
        /* Track if server supports range requests (for seeking) */
        s->seekable = !av_strncasecmp((const char *)value, "bytes", 5) ? 1 : 0;
    } else if (namelen == 10 && !av_strncasecmp((const char *)name, "set-cookie", 10)) {
        /* Handle cookies like HTTP/1.1 */
        if (!s->cookies) {
            s->cookies = av_strndup((const char *)value, valuelen);
        }
    } else if (namelen == 13 && !av_strncasecmp((const char *)name, "content-range", 13)) {
        /* Parse "bytes $from-$to/$document_size" like HTTP/1.1 does */
        const char *p = (const char *)value;
        if (!strncmp(p, "bytes ", 6)) {
            const char *slash;
            p += 6;
            s->off = strtoull(p, NULL, 10);
            if ((slash = strchr(p, '/')) && strlen(slash) > 0)
                s->filesize_from_content_range = strtoull(slash + 1, NULL, 10);
            if (s->seekable == -1)
                h->is_streamed = 0; /* we _can_ in fact seek */
            av_log(h, AV_LOG_DEBUG, "HTTP/2 content-range: off=%"PRIu64" filesize=%"PRIu64"\n",
                   s->off, s->filesize_from_content_range);
        }
    }

    return 0;
}

static int h2_on_data_chunk_recv_callback(nghttp2_session *session,
                                          uint8_t flags, int32_t stream_id,
                                          const uint8_t *data, size_t len,
                                          void *user_data)
{
    URLContext *h = user_data;
    HTTPContext *s = h->priv_data;

    if (stream_id != s->h2_stream_id)
        return 0;

    /* Debug: log first bytes of first chunk */
    if (s->h2_recv_buf_len == 0 && len >= 8) {
        av_log(h, AV_LOG_DEBUG, "HTTP/2 first data bytes: %02x %02x %02x %02x %02x %02x %02x %02x (len=%zu)\n",
               data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], len);
    }

    /* Expand buffer if needed */
    if (s->h2_recv_buf_len + len > s->h2_recv_buf_size) {
        size_t new_size = s->h2_recv_buf_size ? s->h2_recv_buf_size * 2 : H2_RECV_BUF_SIZE;
        while (new_size < s->h2_recv_buf_len + len)
            new_size *= 2;
        uint8_t *new_buf = av_realloc(s->h2_recv_buf, new_size);
        if (!new_buf)
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        s->h2_recv_buf = new_buf;
        s->h2_recv_buf_size = new_size;
    }

    memcpy(s->h2_recv_buf + s->h2_recv_buf_len, data, len);
    s->h2_recv_buf_len += len;

    return 0;
}

static int h2_on_stream_close_callback(nghttp2_session *session,
                                       int32_t stream_id,
                                       uint32_t error_code,
                                       void *user_data)
{
    URLContext *h = user_data;
    HTTPContext *s = h->priv_data;

    if (stream_id == s->h2_stream_id) {
        s->h2_stream_closed = 1;
        av_log(h, AV_LOG_DEBUG, "HTTP/2 stream %d closed with error code %u, received %zu bytes\n",
               stream_id, error_code, s->h2_recv_buf_len);
    }

    return 0;
}

static int h2_on_frame_recv_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data)
{
    URLContext *h = user_data;
    HTTPContext *s = h->priv_data;

    if (frame->hd.type == NGHTTP2_GOAWAY) {
        s->h2_goaway = 1;
        av_log(h, AV_LOG_DEBUG, "HTTP/2 GOAWAY received\n");
    } else if (frame->hd.type == NGHTTP2_HEADERS &&
               frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
        /* Headers complete - apply filesize from Content-Range like HTTP/1.1 does */
        if (s->filesize_from_content_range != UINT64_MAX)
            s->filesize = s->filesize_from_content_range;
    }

    return 0;
}

static int h2_session_init(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    nghttp2_session_callbacks *callbacks;
    int ret;

    ret = nghttp2_session_callbacks_new(&callbacks);
    if (ret != 0) {
        av_log(h, AV_LOG_ERROR, "Failed to create nghttp2 callbacks\n");
        return AVERROR(ENOMEM);
    }

    nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2_on_stream_close_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_on_frame_recv_callback);

    ret = nghttp2_session_client_new(&s->h2_session, callbacks, h);
    nghttp2_session_callbacks_del(callbacks);

    if (ret != 0) {
        av_log(h, AV_LOG_ERROR, "Failed to create nghttp2 session\n");
        return AVERROR(ENOMEM);
    }

    /* Send HTTP/2 connection preface */
    ret = nghttp2_submit_settings(s->h2_session, NGHTTP2_FLAG_NONE, NULL, 0);
    if (ret != 0) {
        av_log(h, AV_LOG_ERROR, "Failed to submit settings\n");
        nghttp2_session_del(s->h2_session);
        s->h2_session = NULL;
        return AVERROR(EIO);
    }

    /* Send the settings frame */
    ret = nghttp2_session_send(s->h2_session);
    if (ret != 0) {
        av_log(h, AV_LOG_ERROR, "Failed to send HTTP/2 preface\n");
        nghttp2_session_del(s->h2_session);
        s->h2_session = NULL;
        return AVERROR(EIO);
    }

    return 0;
}

static void h2_session_close(HTTPContext *s)
{
    if (s->h2_session) {
        nghttp2_session_del(s->h2_session);
        s->h2_session = NULL;
    }
    av_freep(&s->h2_recv_buf);
    s->h2_recv_buf_size = 0;
    s->h2_recv_buf_len = 0;
    s->h2_recv_buf_pos = 0;
    s->h2_stream_id = 0;
    s->h2_stream_closed = 0;
    s->h2_goaway = 0;
    s->is_http2 = 0;
    s->http_code = 0;
}

/* Reset HTTP/2 stream state for a new request while keeping the session */
static void h2_stream_reset(HTTPContext *s)
{
    s->h2_recv_buf_len = 0;
    s->h2_recv_buf_pos = 0;
    s->h2_stream_id = 0;
    s->h2_stream_closed = 0;
    s->http_code = 0;
    s->filesize = UINT64_MAX;
    s->filesize_from_content_range = UINT64_MAX;
    s->off = 0;
}

static int h2_recv_data(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    uint8_t buf[16384];
    int ret;
    ssize_t rv;

    ret = ffurl_read(s->hd, buf, sizeof(buf));
    if (ret < 0) {
        if (ret == AVERROR(EAGAIN))
            return 0;
        return ret;
    }
    if (ret == 0)
        return AVERROR_EOF;

    rv = nghttp2_session_mem_recv(s->h2_session, buf, ret);
    if (rv < 0) {
        av_log(h, AV_LOG_ERROR, "nghttp2_session_mem_recv failed: %s\n",
               nghttp2_strerror((int)rv));
        return AVERROR(EIO);
    }

    /* Send any pending data (like WINDOW_UPDATE) */
    ret = nghttp2_session_send(s->h2_session);
    if (ret != 0) {
        av_log(h, AV_LOG_ERROR, "nghttp2_session_send failed: %s\n",
               nghttp2_strerror(ret));
        return AVERROR(EIO);
    }

    return 0;
}

static int h2_submit_request(URLContext *h, const char *method,
                             const char *authority, const char *path,
                             const char *user_agent)
{
    HTTPContext *s = h->priv_data;
    nghttp2_nv *hdrs = NULL;
    int num_hdrs = 0;
    int max_hdrs = 64;  /* Maximum number of headers */
    int32_t stream_id;
    int ret = 0;
    char *headers_copy = NULL;
    char **lowercase_names = NULL;
    int num_custom_hdrs = 0;

    hdrs = av_malloc_array(max_hdrs, sizeof(*hdrs));
    if (!hdrs)
        return AVERROR(ENOMEM);

    lowercase_names = av_calloc(max_hdrs, sizeof(*lowercase_names));
    if (!lowercase_names) {
        av_free(hdrs);
        return AVERROR(ENOMEM);
    }

#define ADD_HEADER(n, v) do { \
    if (num_hdrs < max_hdrs) { \
        hdrs[num_hdrs].name = (uint8_t *)(n); \
        hdrs[num_hdrs].namelen = strlen(n); \
        hdrs[num_hdrs].value = (uint8_t *)(v); \
        hdrs[num_hdrs].valuelen = strlen(v); \
        hdrs[num_hdrs].flags = NGHTTP2_NV_FLAG_NONE; \
        num_hdrs++; \
    } \
} while(0)

    /* Add pseudo-headers first (required by HTTP/2) */
    ADD_HEADER(":method", method);
    ADD_HEADER(":scheme", "https");
    ADD_HEADER(":authority", authority);
    ADD_HEADER(":path", path);

    /* Parse and add custom headers from s->headers */
    if (s->headers) {
        char *header_line, *saveptr = NULL;
        char *p, *q;
        int has_user_agent = 0, has_accept = 0;

        headers_copy = av_strdup(s->headers);
        if (!headers_copy) {
            ret = AVERROR(ENOMEM);
            goto end;
        }

        /* Convert literal \r\n sequences to actual newlines for parsing */
        p = q = headers_copy;
        while (*p) {
            if (p[0] == '\\' && p[1] == 'r' && p[2] == '\\' && p[3] == 'n') {
                *q++ = '\n';
                p += 4;
            } else if (p[0] == '\\' && p[1] == 'n') {
                *q++ = '\n';
                p += 2;
            } else if (p[0] == '\\' && p[1] == 'r') {
                p += 2;  /* Skip \r */
            } else {
                *q++ = *p++;
            }
        }
        *q = '\0';

        header_line = av_strtok(headers_copy, "\r\n", &saveptr);
        while (header_line && num_hdrs < max_hdrs) {
            char *colon = strchr(header_line, ':');
            if (colon) {
                char *name = header_line;
                char *value = colon + 1;
                size_t name_len = colon - header_line;

                /* Skip leading whitespace in value */
                while (*value == ' ' || *value == '\t')
                    value++;

                /* Create lowercase copy of header name for HTTP/2 */
                lowercase_names[num_custom_hdrs] = av_malloc(name_len + 1);
                if (!lowercase_names[num_custom_hdrs]) {
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
                for (size_t i = 0; i < name_len; i++)
                    lowercase_names[num_custom_hdrs][i] = av_tolower(name[i]);
                lowercase_names[num_custom_hdrs][name_len] = '\0';

                /* Check for user-agent and accept to avoid duplicates */
                if (!strcmp(lowercase_names[num_custom_hdrs], "user-agent"))
                    has_user_agent = 1;
                if (!strcmp(lowercase_names[num_custom_hdrs], "accept"))
                    has_accept = 1;

                hdrs[num_hdrs].name = (uint8_t *)lowercase_names[num_custom_hdrs];
                hdrs[num_hdrs].namelen = name_len;
                hdrs[num_hdrs].value = (uint8_t *)value;
                hdrs[num_hdrs].valuelen = strlen(value);
                hdrs[num_hdrs].flags = NGHTTP2_NV_FLAG_NONE;
                num_hdrs++;
                num_custom_hdrs++;
            }
            header_line = av_strtok(NULL, "\r\n", &saveptr);
        }

        /* Add default headers only if not already present */
        if (!has_user_agent && user_agent)
            ADD_HEADER("user-agent", user_agent);
        if (!has_accept)
            ADD_HEADER("accept", "*/*");
    } else {
        /* No custom headers, add defaults */
        if (user_agent)
            ADD_HEADER("user-agent", user_agent);
        ADD_HEADER("accept", "*/*");
    }

#undef ADD_HEADER

    stream_id = nghttp2_submit_request(s->h2_session, NULL, hdrs, num_hdrs, NULL, h);
    if (stream_id < 0) {
        av_log(h, AV_LOG_ERROR, "Failed to submit HTTP/2 request: %s\n",
               nghttp2_strerror(stream_id));
        ret = AVERROR(EIO);
        goto end;
    }

    s->h2_stream_id = stream_id;
    av_log(h, AV_LOG_DEBUG, "HTTP/2 request submitted on stream %d\n", stream_id);

    /* Send the request */
    ret = nghttp2_session_send(s->h2_session);
    if (ret != 0) {
        av_log(h, AV_LOG_ERROR, "Failed to send HTTP/2 request: %s\n",
               nghttp2_strerror(ret));
        ret = AVERROR(EIO);
        goto end;
    }
    ret = 0;

end:
    av_free(hdrs);
    av_free(headers_copy);
    for (int i = 0; i < num_custom_hdrs; i++)
        av_free(lowercase_names[i]);
    av_free(lowercase_names);
    return ret;
}
#endif /* CONFIG_LIBNGHTTP2 */

void ff_http_init_auth_state(URLContext *dest, const URLContext *src)
{
    memcpy(&((HTTPContext *)dest->priv_data)->auth_state,
           &((HTTPContext *)src->priv_data)->auth_state,
           sizeof(HTTPAuthState));
    memcpy(&((HTTPContext *)dest->priv_data)->proxy_auth_state,
           &((HTTPContext *)src->priv_data)->proxy_auth_state,
           sizeof(HTTPAuthState));
}

static int http_open_cnx_internal(URLContext *h, AVDictionary **options)
{
    const char *path, *proxy_path, *lower_proto = "tcp", *local_path;
    char *env_http_proxy, *env_no_proxy;
    char *hashmark;
    char hostname[1024], hoststr[1024], proto[10], tmp_host[1024];
    char auth[1024], proxyauth[1024] = "";
    char path1[MAX_URL_SIZE], sanitized_path[MAX_URL_SIZE + 1];
    char buf[1024], urlbuf[MAX_URL_SIZE];
    int port, use_proxy, err = 0;
    HTTPContext *s = h->priv_data;

    av_url_split(proto, sizeof(proto), auth, sizeof(auth),
                 hostname, sizeof(hostname), &port,
                 path1, sizeof(path1), s->location);

    av_strlcpy(tmp_host, hostname, sizeof(tmp_host));
    // In case of an IPv6 address, we need to strip the Zone ID,
    // if any. We do it at the first % sign, as percent encoding
    // can be used in the Zone ID itself.
    if (strchr(tmp_host, ':'))
        tmp_host[strcspn(tmp_host, "%")] = '\0';
    ff_url_join(hoststr, sizeof(hoststr), NULL, NULL, tmp_host, port, NULL);

    env_http_proxy = getenv_utf8("http_proxy");
    proxy_path = s->http_proxy ? s->http_proxy : env_http_proxy;

    env_no_proxy = getenv_utf8("no_proxy");
    use_proxy  = !ff_http_match_no_proxy(env_no_proxy, hostname) &&
                 proxy_path && av_strstart(proxy_path, "http://", NULL);
    freeenv_utf8(env_no_proxy);

    if (!strcmp(proto, "https")) {
        lower_proto = "tls";
        use_proxy   = 0;
        if (port < 0)
            port = 443;
        /* pass http_proxy to underlying protocol */
        if (s->http_proxy) {
            err = av_dict_set(options, "http_proxy", s->http_proxy, 0);
            if (err < 0)
                goto end;
        }
#if CONFIG_LIBNGHTTP2
        /* Enable ALPN for HTTP/2 negotiation if enabled */
        if (s->http2 != 0) {
            err = av_dict_set(options, "alpn", "h2,http/1.1", 0);
            if (err < 0)
                goto end;
        }
#endif
    }
    if (port < 0)
        port = 80;

    hashmark = strchr(path1, '#');
    if (hashmark)
        *hashmark = '\0';

    if (path1[0] == '\0') {
        path = "/";
    } else if (path1[0] == '?') {
        snprintf(sanitized_path, sizeof(sanitized_path), "/%s", path1);
        path = sanitized_path;
    } else {
        path = path1;
    }
    local_path = path;
    if (use_proxy) {
        /* Reassemble the request URL without auth string - we don't
         * want to leak the auth to the proxy. */
        ff_url_join(urlbuf, sizeof(urlbuf), proto, NULL, hostname, port, "%s",
                    path1);
        path = urlbuf;
        av_url_split(NULL, 0, proxyauth, sizeof(proxyauth),
                     hostname, sizeof(hostname), &port, NULL, 0, proxy_path);
    }

    ff_url_join(buf, sizeof(buf), lower_proto, NULL, hostname, port, NULL);

    if (!s->hd) {
        err = ffurl_open_whitelist(&s->hd, buf, AVIO_FLAG_READ_WRITE,
                                   &h->interrupt_callback, options,
                                   h->protocol_whitelist, h->protocol_blacklist, h);
    }

end:
    freeenv_utf8(env_http_proxy);
    return err < 0 ? err : http_connect(
        h, path, local_path, hoststr, auth, proxyauth);
}

static int http_should_reconnect(HTTPContext *s, int err)
{
    const char *status_group;
    char http_code[4];

    switch (err) {
    case AVERROR_HTTP_BAD_REQUEST:
    case AVERROR_HTTP_UNAUTHORIZED:
    case AVERROR_HTTP_FORBIDDEN:
    case AVERROR_HTTP_NOT_FOUND:
    case AVERROR_HTTP_TOO_MANY_REQUESTS:
    case AVERROR_HTTP_OTHER_4XX:
        status_group = "4xx";
        break;

    case AVERROR_HTTP_SERVER_ERROR:
        status_group = "5xx";
        break;

    default:
        return s->reconnect_on_network_error;
    }

    if (!s->reconnect_on_http_error)
        return 0;

    if (av_match_list(status_group, s->reconnect_on_http_error, ',') > 0)
        return 1;

    snprintf(http_code, sizeof(http_code), "%d", s->http_code);

    return av_match_list(http_code, s->reconnect_on_http_error, ',') > 0;
}

static char *redirect_cache_get(HTTPContext *s)
{
    AVDictionaryEntry *re;
    int64_t expiry;
    char *delim;

    re = av_dict_get(s->redirect_cache, s->location, NULL, AV_DICT_MATCH_CASE);
    if (!re) {
        return NULL;
    }

    delim = strchr(re->value, ';');
    if (!delim) {
        return NULL;
    }

    expiry = strtoll(re->value, NULL, 10);
    if (time(NULL) > expiry) {
        return NULL;
    }

    return delim + 1;
}

static int redirect_cache_set(HTTPContext *s, const char *source, const char *dest, int64_t expiry)
{
    char *value;
    int ret;

    value = av_asprintf("%"PRIi64";%s", expiry, dest);
    if (!value) {
        return AVERROR(ENOMEM);
    }

    ret = av_dict_set(&s->redirect_cache, source, value, AV_DICT_MATCH_CASE | AV_DICT_DONT_STRDUP_VAL);
    if (ret < 0)
        return ret;

    return 0;
}

/* return non zero if error */
static int http_open_cnx(URLContext *h, AVDictionary **options)
{
    HTTPAuthType cur_auth_type, cur_proxy_auth_type;
    HTTPContext *s = h->priv_data;
    int ret, conn_attempts = 1, auth_attempts = 0, redirects = 0;
    int reconnect_delay = 0;
    int reconnect_delay_total = 0;
    uint64_t off;
    char *cached;

redo:

    cached = redirect_cache_get(s);
    if (cached) {
        av_free(s->location);
        s->location = av_strdup(cached);
        if (!s->location) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        goto redo;
    }

    av_dict_copy(options, s->chained_options, 0);

    cur_auth_type       = s->auth_state.auth_type;
    cur_proxy_auth_type = s->auth_state.auth_type;

    off = s->off;
    ret = http_open_cnx_internal(h, options);
    if (ret < 0) {
        if (!http_should_reconnect(s, ret) ||
            reconnect_delay > s->reconnect_delay_max ||
            (s->reconnect_max_retries >= 0 && conn_attempts > s->reconnect_max_retries) ||
            reconnect_delay_total > s->reconnect_delay_total_max)
            goto fail;

        /* Both fields here are in seconds. */
        if (s->respect_retry_after && s->retry_after > 0) {
            reconnect_delay = s->retry_after;
            if (reconnect_delay > s->reconnect_delay_max)
                goto fail;
            s->retry_after = 0;
        }

        av_log(h, AV_LOG_WARNING, "Will reconnect at %"PRIu64" in %d second(s).\n", off, reconnect_delay);
        ret = ff_network_sleep_interruptible(1000U * 1000 * reconnect_delay, &h->interrupt_callback);
        if (ret != AVERROR(ETIMEDOUT))
            goto fail;
        reconnect_delay_total += reconnect_delay;
        reconnect_delay = 1 + 2 * reconnect_delay;
        conn_attempts++;

        /* restore the offset (http_connect resets it) */
        s->off = off;

        ffurl_closep(&s->hd);
        goto redo;
    }

    auth_attempts++;
    if (s->http_code == 401) {
        if ((cur_auth_type == HTTP_AUTH_NONE || s->auth_state.stale) &&
            s->auth_state.auth_type != HTTP_AUTH_NONE && auth_attempts < 4) {
            ffurl_closep(&s->hd);
            goto redo;
        } else
            goto fail;
    }
    if (s->http_code == 407) {
        if ((cur_proxy_auth_type == HTTP_AUTH_NONE || s->proxy_auth_state.stale) &&
            s->proxy_auth_state.auth_type != HTTP_AUTH_NONE && auth_attempts < 4) {
            ffurl_closep(&s->hd);
            goto redo;
        } else
            goto fail;
    }
    if ((s->http_code == 301 || s->http_code == 302 ||
         s->http_code == 303 || s->http_code == 307 || s->http_code == 308) &&
        s->new_location) {
        /* url moved, get next */
#if CONFIG_LIBNGHTTP2
        h2_session_close(s);
#endif
        ffurl_closep(&s->hd);
        if (redirects++ >= MAX_REDIRECTS)
            return AVERROR(EIO);

        if (!s->expires) {
            s->expires = (s->http_code == 301 || s->http_code == 308) ? INT64_MAX : -1;
        }

        if (s->expires > time(NULL) && av_dict_count(s->redirect_cache) < MAX_CACHED_REDIRECTS) {
            redirect_cache_set(s, s->location, s->new_location, s->expires);
        }

        av_free(s->location);
        s->location = s->new_location;
        s->new_location = NULL;

        /* Restart the authentication process with the new target, which
         * might use a different auth mechanism. */
        memset(&s->auth_state, 0, sizeof(s->auth_state));
        auth_attempts         = 0;
        goto redo;
    }
    return 0;

fail:
    if (s->hd)
        ffurl_closep(&s->hd);
    if (ret < 0)
        return ret;
    return ff_http_averror(s->http_code, AVERROR(EIO));
}

int ff_http_do_new_request(URLContext *h, const char *uri) {
    return ff_http_do_new_request2(h, uri, NULL);
}

int ff_http_do_new_request2(URLContext *h, const char *uri, AVDictionary **opts)
{
    HTTPContext *s = h->priv_data;
    AVDictionary *options = NULL;
    int ret;
    char hostname1[1024], hostname2[1024], proto1[10], proto2[10];
    int port1, port2;

    if (!h->prot ||
        !(!strcmp(h->prot->name, "http") ||
          !strcmp(h->prot->name, "https")))
        return AVERROR(EINVAL);

    av_url_split(proto1, sizeof(proto1), NULL, 0,
                 hostname1, sizeof(hostname1), &port1,
                 NULL, 0, s->location);
    av_url_split(proto2, sizeof(proto2), NULL, 0,
                 hostname2, sizeof(hostname2), &port2,
                 NULL, 0, uri);
    if (strcmp(proto1, proto2) != 0) {
        av_log(h, AV_LOG_INFO, "Cannot reuse HTTP connection for different protocol %s vs %s\n",
               proto1, proto2);
        return AVERROR(EINVAL);
    }
    if (port1 != port2 || strncmp(hostname1, hostname2, sizeof(hostname2)) != 0) {
        av_log(h, AV_LOG_INFO, "Cannot reuse HTTP connection for different host: %s:%d != %s:%d\n",
            hostname1, port1,
            hostname2, port2
        );
        return AVERROR(EINVAL);
    }

    if (!s->end_chunked_post) {
        ret = http_shutdown(h, h->flags);
        if (ret < 0)
            return ret;
    }

    if (s->willclose)
        return AVERROR_EOF;

    s->end_chunked_post = 0;
    s->chunkend      = 0;
    s->off           = 0;
    s->icy_data_read = 0;

    av_free(s->location);
    s->location = av_strdup(uri);
    if (!s->location)
        return AVERROR(ENOMEM);

    av_free(s->uri);
    s->uri = av_strdup(uri);
    if (!s->uri)
        return AVERROR(ENOMEM);

    if ((ret = av_opt_set_dict(s, opts)) < 0)
        return ret;

    av_log(s, AV_LOG_INFO, "Opening \'%s\' for %s\n", uri, h->flags & AVIO_FLAG_WRITE ? "writing" : "reading");
    ret = http_open_cnx(h, &options);
    av_dict_free(&options);
    return ret;
}

int ff_http_averror(int status_code, int default_averror)
{
    switch (status_code) {
        case 400: return AVERROR_HTTP_BAD_REQUEST;
        case 401: return AVERROR_HTTP_UNAUTHORIZED;
        case 403: return AVERROR_HTTP_FORBIDDEN;
        case 404: return AVERROR_HTTP_NOT_FOUND;
        case 429: return AVERROR_HTTP_TOO_MANY_REQUESTS;
        default: break;
    }
    if (status_code >= 400 && status_code <= 499)
        return AVERROR_HTTP_OTHER_4XX;
    else if (status_code >= 500)
        return AVERROR_HTTP_SERVER_ERROR;
    else
        return default_averror;
}

const char* ff_http_get_new_location(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    return s->new_location;
}

static int http_write_reply(URLContext* h, int status_code)
{
    int ret, body = 0, reply_code, message_len;
    const char *reply_text, *content_type;
    HTTPContext *s = h->priv_data;
    char message[BUFFER_SIZE];
    content_type = "text/plain";

    if (status_code < 0)
        body = 1;
    switch (status_code) {
    case AVERROR_HTTP_BAD_REQUEST:
    case 400:
        reply_code = 400;
        reply_text = "Bad Request";
        break;
    case AVERROR_HTTP_FORBIDDEN:
    case 403:
        reply_code = 403;
        reply_text = "Forbidden";
        break;
    case AVERROR_HTTP_NOT_FOUND:
    case 404:
        reply_code = 404;
        reply_text = "Not Found";
        break;
    case AVERROR_HTTP_TOO_MANY_REQUESTS:
    case 429:
        reply_code = 429;
        reply_text = "Too Many Requests";
        break;
    case 200:
        reply_code = 200;
        reply_text = "OK";
        content_type = s->content_type ? s->content_type : "application/octet-stream";
        break;
    case AVERROR_HTTP_SERVER_ERROR:
    case 500:
        reply_code = 500;
        reply_text = "Internal server error";
        break;
    default:
        return AVERROR(EINVAL);
    }
    if (body) {
        s->chunked_post = 0;
        message_len = snprintf(message, sizeof(message),
                 "HTTP/1.1 %03d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %zu\r\n"
                 "%s"
                 "\r\n"
                 "%03d %s\r\n",
                 reply_code,
                 reply_text,
                 content_type,
                 strlen(reply_text) + 6, // 3 digit status code + space + \r\n
                 s->headers ? s->headers : "",
                 reply_code,
                 reply_text);
    } else {
        s->chunked_post = 1;
        message_len = snprintf(message, sizeof(message),
                 "HTTP/1.1 %03d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Transfer-Encoding: chunked\r\n"
                 "%s"
                 "\r\n",
                 reply_code,
                 reply_text,
                 content_type,
                 s->headers ? s->headers : "");
    }
    av_log(h, AV_LOG_TRACE, "HTTP reply header: \n%s----\n", message);
    if ((ret = ffurl_write(s->hd, message, message_len)) < 0)
        return ret;
    return 0;
}

static void handle_http_errors(URLContext *h, int error)
{
    av_assert0(error < 0);
    http_write_reply(h, error);
}

static int http_handshake(URLContext *c)
{
    int ret, err;
    HTTPContext *ch = c->priv_data;
    URLContext *cl = ch->hd;
    switch (ch->handshake_step) {
    case LOWER_PROTO:
        av_log(c, AV_LOG_TRACE, "Lower protocol\n");
        if ((ret = ffurl_handshake(cl)) > 0)
            return 2 + ret;
        if (ret < 0)
            return ret;
        ch->handshake_step = READ_HEADERS;
        ch->is_connected_server = 1;
        return 2;
    case READ_HEADERS:
        av_log(c, AV_LOG_TRACE, "Read headers\n");
        if ((err = http_read_header(c)) < 0) {
            handle_http_errors(c, err);
            return err;
        }
        ch->handshake_step = WRITE_REPLY_HEADERS;
        return 1;
    case WRITE_REPLY_HEADERS:
        av_log(c, AV_LOG_TRACE, "Reply code: %d\n", ch->reply_code);
        if ((err = http_write_reply(c, ch->reply_code)) < 0)
            return err;
        ch->handshake_step = FINISH;
        return 1;
    case FINISH:
        return 0;
    }
    // this should never be reached.
    return AVERROR(EINVAL);
}

static int http_listen(URLContext *h, const char *uri, int flags,
                       AVDictionary **options) {
    HTTPContext *s = h->priv_data;
    int ret;
    char hostname[1024], proto[10];
    char lower_url[100];
    const char *lower_proto = "tcp";
    int port;
    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname), &port,
                 NULL, 0, uri);
    if (!strcmp(proto, "https"))
        lower_proto = "tls";
    ff_url_join(lower_url, sizeof(lower_url), lower_proto, NULL, hostname, port,
                NULL);
    if ((ret = av_dict_set_int(options, "listen", s->listen, 0)) < 0)
        goto fail;
    if ((ret = ffurl_open_whitelist(&s->hd, lower_url, AVIO_FLAG_READ_WRITE,
                                    &h->interrupt_callback, options,
                                    h->protocol_whitelist, h->protocol_blacklist, h
                                   )) < 0)
        goto fail;
    s->handshake_step = LOWER_PROTO;
    if (s->listen == HTTP_SINGLE) { /* single client */
        s->reply_code = 200;
        while ((ret = http_handshake(h)) > 0);
    }
fail:
    av_dict_free(&s->chained_options);
    av_dict_free(&s->cookie_dict);
    return ret;
}

static int http_open(URLContext *h, const char *uri, int flags,
                     AVDictionary **options)
{
    HTTPContext *s = h->priv_data;
    int ret;

    if( s->seekable == 1 )
        h->is_streamed = 0;
    else
        h->is_streamed = 1;

    s->filesize = UINT64_MAX;

    s->location = av_strdup(uri);
    if (!s->location)
        return AVERROR(ENOMEM);

    s->uri = av_strdup(uri);
    if (!s->uri)
        return AVERROR(ENOMEM);

    if (options)
        av_dict_copy(&s->chained_options, *options, 0);

    if (s->headers) {
        int len = strlen(s->headers);
        if (len < 2 || strcmp("\r\n", s->headers + len - 2)) {
            av_log(h, AV_LOG_WARNING,
                   "No trailing CRLF found in HTTP header. Adding it.\n");
            ret = av_reallocp(&s->headers, len + 3);
            if (ret < 0)
                goto bail_out;
            s->headers[len]     = '\r';
            s->headers[len + 1] = '\n';
            s->headers[len + 2] = '\0';
        }
    }

    if (s->listen) {
        return http_listen(h, uri, flags, options);
    }
    ret = http_open_cnx(h, options);
bail_out:
    if (ret < 0) {
        av_dict_free(&s->chained_options);
        av_dict_free(&s->cookie_dict);
        av_dict_free(&s->redirect_cache);
        av_freep(&s->new_location);
        av_freep(&s->uri);
    }
    return ret;
}

static int http_accept(URLContext *s, URLContext **c)
{
    int ret;
    HTTPContext *sc = s->priv_data;
    HTTPContext *cc;
    URLContext *sl = sc->hd;
    URLContext *cl = NULL;

    av_assert0(sc->listen);
    if ((ret = ffurl_alloc(c, s->filename, s->flags, &sl->interrupt_callback)) < 0)
        goto fail;
    cc = (*c)->priv_data;
    if ((ret = ffurl_accept(sl, &cl)) < 0)
        goto fail;
    cc->hd = cl;
    cc->is_multi_client = 1;
    return 0;
fail:
    if (c) {
        ffurl_closep(c);
    }
    return ret;
}

static int http_getc(HTTPContext *s)
{
    int len;
    if (s->buf_ptr >= s->buf_end) {
        len = ffurl_read(s->hd, s->buffer, BUFFER_SIZE);
        if (len < 0) {
            return len;
        } else if (len == 0) {
            return AVERROR_EOF;
        } else {
            s->buf_ptr = s->buffer;
            s->buf_end = s->buffer + len;
        }
    }
    return *s->buf_ptr++;
}

static int http_get_line(HTTPContext *s, char *line, int line_size)
{
    int ch;
    char *q;

    q = line;
    for (;;) {
        ch = http_getc(s);
        if (ch < 0)
            return ch;
        if (ch == '\n') {
            /* process line */
            if (q > line && q[-1] == '\r')
                q--;
            *q = '\0';

            return 0;
        } else {
            if ((q - line) < line_size - 1)
                *q++ = ch;
        }
    }
}

static int check_http_code(URLContext *h, int http_code, const char *end)
{
    HTTPContext *s = h->priv_data;
    /* error codes are 4xx and 5xx, but regard 401 as a success, so we
     * don't abort until all headers have been parsed. */
    if (http_code >= 400 && http_code < 600 &&
        (http_code != 401 || s->auth_state.auth_type != HTTP_AUTH_NONE) &&
        (http_code != 407 || s->proxy_auth_state.auth_type != HTTP_AUTH_NONE)) {
        end += strspn(end, SPACE_CHARS);
        av_log(h, AV_LOG_WARNING, "HTTP error %d %s\n", http_code, end);
        return ff_http_averror(http_code, AVERROR(EIO));
    }
    return 0;
}

static int parse_location(HTTPContext *s, const char *p)
{
    char redirected_location[MAX_URL_SIZE];
    ff_make_absolute_url(redirected_location, sizeof(redirected_location),
                         s->location, p);
    av_freep(&s->new_location);
    s->new_location = av_strdup(redirected_location);
    if (!s->new_location)
        return AVERROR(ENOMEM);
    return 0;
}

/* "bytes $from-$to/$document_size" */
static void parse_content_range(URLContext *h, const char *p)
{
    HTTPContext *s = h->priv_data;
    const char *slash;

    if (!strncmp(p, "bytes ", 6)) {
        p     += 6;
        s->off = strtoull(p, NULL, 10);
        if ((slash = strchr(p, '/')) && strlen(slash) > 0)
            s->filesize_from_content_range = strtoull(slash + 1, NULL, 10);
    }
    if (s->seekable == -1 && (!s->is_akamai || s->filesize != 2147483647))
        h->is_streamed = 0; /* we _can_ in fact seek */
}

static int parse_content_encoding(URLContext *h, const char *p)
{
    if (!av_strncasecmp(p, "gzip", 4) ||
        !av_strncasecmp(p, "deflate", 7)) {
#if CONFIG_ZLIB
        HTTPContext *s = h->priv_data;

        s->compressed = 1;
        inflateEnd(&s->inflate_stream);
        if (inflateInit2(&s->inflate_stream, 32 + 15) != Z_OK) {
            av_log(h, AV_LOG_WARNING, "Error during zlib initialisation: %s\n",
                   s->inflate_stream.msg);
            return AVERROR(ENOSYS);
        }
        if (zlibCompileFlags() & (1 << 17)) {
            av_log(h, AV_LOG_WARNING,
                   "Your zlib was compiled without gzip support.\n");
            return AVERROR(ENOSYS);
        }
#else
        av_log(h, AV_LOG_WARNING,
               "Compressed (%s) content, need zlib with gzip support\n", p);
        return AVERROR(ENOSYS);
#endif /* CONFIG_ZLIB */
    } else if (!av_strncasecmp(p, "identity", 8)) {
        // The normal, no-encoding case (although servers shouldn't include
        // the header at all if this is the case).
    } else {
        av_log(h, AV_LOG_WARNING, "Unknown content coding: %s\n", p);
    }
    return 0;
}

// Concat all Icy- header lines
static int parse_icy(HTTPContext *s, const char *tag, const char *p)
{
    int len = 4 + strlen(p) + strlen(tag);
    int is_first = !s->icy_metadata_headers;
    int ret;

    av_dict_set(&s->metadata, tag, p, 0);

    if (s->icy_metadata_headers)
        len += strlen(s->icy_metadata_headers);

    if ((ret = av_reallocp(&s->icy_metadata_headers, len)) < 0)
        return ret;

    if (is_first)
        *s->icy_metadata_headers = '\0';

    av_strlcatf(s->icy_metadata_headers, len, "%s: %s\n", tag, p);

    return 0;
}

static int parse_http_date(const char *date_str, struct tm *buf)
{
    char date_buf[MAX_DATE_LEN];
    int i, j, date_buf_len = MAX_DATE_LEN-1;
    char *date;

    // strip off any punctuation or whitespace
    for (i = 0, j = 0; date_str[i] != '\0' && j < date_buf_len; i++) {
        if ((date_str[i] >= '0' && date_str[i] <= '9') ||
            (date_str[i] >= 'A' && date_str[i] <= 'Z') ||
            (date_str[i] >= 'a' && date_str[i] <= 'z')) {
            date_buf[j] = date_str[i];
            j++;
        }
    }
    date_buf[j] = '\0';
    date = date_buf;

    // move the string beyond the day of week
    while ((*date < '0' || *date > '9') && *date != '\0')
        date++;

    return av_small_strptime(date, "%d%b%Y%H%M%S", buf) ? 0 : AVERROR(EINVAL);
}

static int parse_set_cookie(const char *set_cookie, AVDictionary **dict)
{
    char *param, *next_param, *cstr, *back;
    char *saveptr = NULL;

    if (!set_cookie[0])
        return 0;

    if (!(cstr = av_strdup(set_cookie)))
        return AVERROR(EINVAL);

    // strip any trailing whitespace
    back = &cstr[strlen(cstr)-1];
    while (strchr(WHITESPACES, *back)) {
        *back='\0';
        if (back == cstr)
            break;
        back--;
    }

    next_param = cstr;
    while ((param = av_strtok(next_param, ";", &saveptr))) {
        char *name, *value;
        next_param = NULL;
        param += strspn(param, WHITESPACES);
        if ((name = av_strtok(param, "=", &value))) {
            if (av_dict_set(dict, name, value, 0) < 0) {
                av_free(cstr);
                return -1;
            }
        }
    }

    av_free(cstr);
    return 0;
}

static int parse_cookie(HTTPContext *s, const char *p, AVDictionary **cookies)
{
    AVDictionary *new_params = NULL;
    const AVDictionaryEntry *e, *cookie_entry;
    char *eql, *name;

    // ensure the cookie is parsable
    if (parse_set_cookie(p, &new_params))
        return -1;

    // if there is no cookie value there is nothing to parse
    cookie_entry = av_dict_iterate(new_params, NULL);
    if (!cookie_entry || !cookie_entry->value) {
        av_dict_free(&new_params);
        return -1;
    }

    // ensure the cookie is not expired or older than an existing value
    if ((e = av_dict_get(new_params, "expires", NULL, 0)) && e->value) {
        struct tm new_tm = {0};
        if (!parse_http_date(e->value, &new_tm)) {
            AVDictionaryEntry *e2;

            // if the cookie has already expired ignore it
            if (av_timegm(&new_tm) < av_gettime() / 1000000) {
                av_dict_free(&new_params);
                return 0;
            }

            // only replace an older cookie with the same name
            e2 = av_dict_get(*cookies, cookie_entry->key, NULL, 0);
            if (e2 && e2->value) {
                AVDictionary *old_params = NULL;
                if (!parse_set_cookie(p, &old_params)) {
                    e2 = av_dict_get(old_params, "expires", NULL, 0);
                    if (e2 && e2->value) {
                        struct tm old_tm = {0};
                        if (!parse_http_date(e->value, &old_tm)) {
                            if (av_timegm(&new_tm) < av_timegm(&old_tm)) {
                                av_dict_free(&new_params);
                                av_dict_free(&old_params);
                                return -1;
                            }
                        }
                    }
                }
                av_dict_free(&old_params);
            }
        }
    }
    av_dict_free(&new_params);

    // duplicate the cookie name (dict will dupe the value)
    if (!(eql = strchr(p, '='))) return AVERROR(EINVAL);
    if (!(name = av_strndup(p, eql - p))) return AVERROR(ENOMEM);

    // add the cookie to the dictionary
    av_dict_set(cookies, name, eql, AV_DICT_DONT_STRDUP_KEY);

    return 0;
}

static int cookie_string(AVDictionary *dict, char **cookies)
{
    const AVDictionaryEntry *e = NULL;
    int len = 1;

    // determine how much memory is needed for the cookies string
    while ((e = av_dict_iterate(dict, e)))
        len += strlen(e->key) + strlen(e->value) + 1;

    // reallocate the cookies
    e = NULL;
    if (*cookies) av_free(*cookies);
    *cookies = av_malloc(len);
    if (!*cookies) return AVERROR(ENOMEM);
    *cookies[0] = '\0';

    // write out the cookies
    while ((e = av_dict_iterate(dict, e)))
        av_strlcatf(*cookies, len, "%s%s\n", e->key, e->value);

    return 0;
}

static void parse_expires(HTTPContext *s, const char *p)
{
    struct tm tm;

    if (!parse_http_date(p, &tm)) {
        s->expires = av_timegm(&tm);
    }
}

static void parse_cache_control(HTTPContext *s, const char *p)
{
    char *age;
    int offset;

    /* give 'Expires' higher priority over 'Cache-Control' */
    if (s->expires) {
        return;
    }

    if (av_stristr(p, "no-cache") || av_stristr(p, "no-store")) {
        s->expires = -1;
        return;
    }

    age = av_stristr(p, "s-maxage=");
    offset = 9;
    if (!age) {
        age = av_stristr(p, "max-age=");
        offset = 8;
    }

    if (age) {
        s->expires = time(NULL) + atoi(p + offset);
    }
}

static int process_line(URLContext *h, char *line, int line_count, int *parsed_http_code)
{
    HTTPContext *s = h->priv_data;
    const char *auto_method =  h->flags & AVIO_FLAG_READ ? "POST" : "GET";
    char *tag, *p, *end, *method, *resource, *version;
    int ret;

    /* end of header */
    if (line[0] == '\0') {
        s->end_header = 1;
        return 0;
    }

    p = line;
    if (line_count == 0) {
        if (s->is_connected_server) {
            // HTTP method
            method = p;
            while (*p && !av_isspace(*p))
                p++;
            *(p++) = '\0';
            av_log(h, AV_LOG_TRACE, "Received method: %s\n", method);
            if (s->method) {
                if (av_strcasecmp(s->method, method)) {
                    av_log(h, AV_LOG_ERROR, "Received and expected HTTP method do not match. (%s expected, %s received)\n",
                           s->method, method);
                    return ff_http_averror(400, AVERROR(EIO));
                }
            } else {
                // use autodetected HTTP method to expect
                av_log(h, AV_LOG_TRACE, "Autodetected %s HTTP method\n", auto_method);
                if (av_strcasecmp(auto_method, method)) {
                    av_log(h, AV_LOG_ERROR, "Received and autodetected HTTP method did not match "
                           "(%s autodetected %s received)\n", auto_method, method);
                    return ff_http_averror(400, AVERROR(EIO));
                }
                if (!(s->method = av_strdup(method)))
                    return AVERROR(ENOMEM);
            }

            // HTTP resource
            while (av_isspace(*p))
                p++;
            resource = p;
            while (*p && !av_isspace(*p))
                p++;
            *(p++) = '\0';
            av_log(h, AV_LOG_TRACE, "Requested resource: %s\n", resource);
            if (!(s->resource = av_strdup(resource)))
                return AVERROR(ENOMEM);

            // HTTP version
            while (av_isspace(*p))
                p++;
            version = p;
            while (*p && !av_isspace(*p))
                p++;
            *p = '\0';
            if (av_strncasecmp(version, "HTTP/", 5)) {
                av_log(h, AV_LOG_ERROR, "Malformed HTTP version string.\n");
                return ff_http_averror(400, AVERROR(EIO));
            }
            av_log(h, AV_LOG_TRACE, "HTTP version string: %s\n", version);
        } else {
            if (av_strncasecmp(p, "HTTP/1.0", 8) == 0)
                s->willclose = 1;
            while (*p != '/' && *p != '\0')
                p++;
            while (*p == '/')
                p++;
            av_freep(&s->http_version);
            s->http_version = av_strndup(p, 3);
            while (!av_isspace(*p) && *p != '\0')
                p++;
            while (av_isspace(*p))
                p++;
            s->http_code = strtol(p, &end, 10);

            av_log(h, AV_LOG_TRACE, "http_code=%d\n", s->http_code);

            *parsed_http_code = 1;

            if ((ret = check_http_code(h, s->http_code, end)) < 0)
                return ret;
        }
    } else {
        while (*p != '\0' && *p != ':')
            p++;
        if (*p != ':')
            return 1;

        *p  = '\0';
        tag = line;
        p++;
        while (av_isspace(*p))
            p++;
        if (!av_strcasecmp(tag, "Location")) {
            if ((ret = parse_location(s, p)) < 0)
                return ret;
        } else if (!av_strcasecmp(tag, "Content-Length") &&
                   s->filesize == UINT64_MAX) {
            s->filesize = strtoull(p, NULL, 10);
        } else if (!av_strcasecmp(tag, "Content-Range")) {
            parse_content_range(h, p);
        } else if (!av_strcasecmp(tag, "Accept-Ranges") &&
                   !strncmp(p, "bytes", 5) &&
                   s->seekable == -1) {
            h->is_streamed = 0;
        } else if (!av_strcasecmp(tag, "Transfer-Encoding") &&
                   !av_strncasecmp(p, "chunked", 7)) {
            s->filesize  = UINT64_MAX;
            s->chunksize = 0;
        } else if (!av_strcasecmp(tag, "WWW-Authenticate")) {
            ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!av_strcasecmp(tag, "Authentication-Info")) {
            ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!av_strcasecmp(tag, "Proxy-Authenticate")) {
            ff_http_auth_handle_header(&s->proxy_auth_state, tag, p);
        } else if (!av_strcasecmp(tag, "Connection")) {
            if (!strcmp(p, "close"))
                s->willclose = 1;
        } else if (!av_strcasecmp(tag, "Server")) {
            if (!av_strcasecmp(p, "AkamaiGHost")) {
                s->is_akamai = 1;
            } else if (!av_strncasecmp(p, "MediaGateway", 12)) {
                s->is_mediagateway = 1;
            }
        } else if (!av_strcasecmp(tag, "Content-Type")) {
            av_free(s->mime_type);
            s->mime_type = av_get_token((const char **)&p, ";");
        } else if (!av_strcasecmp(tag, "Set-Cookie")) {
            if (parse_cookie(s, p, &s->cookie_dict))
                av_log(h, AV_LOG_WARNING, "Unable to parse '%s'\n", p);
        } else if (!av_strcasecmp(tag, "Icy-MetaInt")) {
            s->icy_metaint = strtoull(p, NULL, 10);
        } else if (!av_strncasecmp(tag, "Icy-", 4)) {
            if ((ret = parse_icy(s, tag, p)) < 0)
                return ret;
        } else if (!av_strcasecmp(tag, "Content-Encoding")) {
            if ((ret = parse_content_encoding(h, p)) < 0)
                return ret;
        } else if (!av_strcasecmp(tag, "Expires")) {
            parse_expires(s, p);
        } else if (!av_strcasecmp(tag, "Cache-Control")) {
            parse_cache_control(s, p);
        } else if (!av_strcasecmp(tag, "Retry-After")) {
            /* The header can be either an integer that represents seconds, or a date. */
            struct tm tm;
            int date_ret = parse_http_date(p, &tm);
            if (!date_ret) {
                time_t retry   = av_timegm(&tm);
                int64_t now    = av_gettime() / 1000000;
                int64_t diff   = ((int64_t) retry) - now;
                s->retry_after = (unsigned int) FFMAX(0, diff);
            } else {
                s->retry_after = strtoul(p, NULL, 10);
            }
        }
    }
    return 1;
}

/**
 * Create a string containing cookie values for use as a HTTP cookie header
 * field value for a particular path and domain from the cookie values stored in
 * the HTTP protocol context. The cookie string is stored in *cookies, and may
 * be NULL if there are no valid cookies.
 *
 * @return a negative value if an error condition occurred, 0 otherwise
 */
static int get_cookies(HTTPContext *s, char **cookies, const char *path,
                       const char *domain)
{
    // cookie strings will look like Set-Cookie header field values.  Multiple
    // Set-Cookie fields will result in multiple values delimited by a newline
    int ret = 0;
    char *cookie, *set_cookies, *next;
    char *saveptr = NULL;

    // destroy any cookies in the dictionary.
    av_dict_free(&s->cookie_dict);

    if (!s->cookies)
        return 0;

    next = set_cookies = av_strdup(s->cookies);
    if (!next)
        return AVERROR(ENOMEM);

    *cookies = NULL;
    while ((cookie = av_strtok(next, "\n", &saveptr)) && !ret) {
        AVDictionary *cookie_params = NULL;
        const AVDictionaryEntry *cookie_entry, *e;

        next = NULL;
        // store the cookie in a dict in case it is updated in the response
        if (parse_cookie(s, cookie, &s->cookie_dict))
            av_log(s, AV_LOG_WARNING, "Unable to parse '%s'\n", cookie);

        // continue on to the next cookie if this one cannot be parsed
        if (parse_set_cookie(cookie, &cookie_params))
            goto skip_cookie;

        // if the cookie has no value, skip it
        cookie_entry = av_dict_iterate(cookie_params, NULL);
        if (!cookie_entry || !cookie_entry->value)
            goto skip_cookie;

        // if the cookie has expired, don't add it
        if ((e = av_dict_get(cookie_params, "expires", NULL, 0)) && e->value) {
            struct tm tm_buf = {0};
            if (!parse_http_date(e->value, &tm_buf)) {
                if (av_timegm(&tm_buf) < av_gettime() / 1000000)
                    goto skip_cookie;
            }
        }

        // if no domain in the cookie assume it applied to this request
        if ((e = av_dict_get(cookie_params, "domain", NULL, 0)) && e->value) {
            // find the offset comparison is on the min domain (b.com, not a.b.com)
            int domain_offset = strlen(domain) - strlen(e->value);
            if (domain_offset < 0)
                goto skip_cookie;

            // match the cookie domain
            if (av_strcasecmp(&domain[domain_offset], e->value))
                goto skip_cookie;
        }

        // if a cookie path is provided, ensure the request path is within that path
        e = av_dict_get(cookie_params, "path", NULL, 0);
        if (e && av_strncasecmp(path, e->value, strlen(e->value)))
            goto skip_cookie;

        // cookie parameters match, so copy the value
        if (!*cookies) {
            *cookies = av_asprintf("%s=%s", cookie_entry->key, cookie_entry->value);
        } else {
            char *tmp = *cookies;
            *cookies = av_asprintf("%s; %s=%s", tmp, cookie_entry->key, cookie_entry->value);
            av_free(tmp);
        }
        if (!*cookies)
            ret = AVERROR(ENOMEM);

    skip_cookie:
        av_dict_free(&cookie_params);
    }

    av_free(set_cookies);

    return ret;
}

static inline int has_header(const char *str, const char *header)
{
    /* header + 2 to skip over CRLF prefix. (make sure you have one!) */
    if (!str)
        return 0;
    return av_stristart(str, header + 2, NULL) || av_stristr(str, header);
}

static int http_read_header(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    char line[MAX_URL_SIZE];
    int err = 0, http_err = 0;

    av_freep(&s->new_location);
    s->expires = 0;
    s->chunksize = UINT64_MAX;
    s->filesize_from_content_range = UINT64_MAX;

    for (;;) {
        int parsed_http_code = 0;

        if ((err = http_get_line(s, line, sizeof(line))) < 0)
            return err;

        av_log(h, AV_LOG_TRACE, "header='%s'\n", line);

        err = process_line(h, line, s->line_count, &parsed_http_code);
        if (err < 0) {
            if (parsed_http_code) {
                http_err = err;
            } else {
                /* Prefer to return HTTP code error if we've already seen one. */
                if (http_err)
                    return http_err;
                else
                    return err;
            }
        }
        if (err == 0)
            break;
        s->line_count++;
    }
    if (http_err)
        return http_err;

    // filesize from Content-Range can always be used, even if using chunked Transfer-Encoding
    if (s->filesize_from_content_range != UINT64_MAX)
        s->filesize = s->filesize_from_content_range;

    if (s->seekable == -1 && s->is_mediagateway && s->filesize == 2000000000)
        h->is_streamed = 1; /* we can in fact _not_ seek */

    // add any new cookies into the existing cookie string
    cookie_string(s->cookie_dict, &s->cookies);
    av_dict_free(&s->cookie_dict);

    return err;
}

/**
 * Escape unsafe characters in path in order to pass them safely to the HTTP
 * request. Insipred by the algorithm in GNU wget:
 * - escape "%" characters not followed by two hex digits
 * - escape all "unsafe" characters except which are also "reserved"
 * - pass through everything else
 */
static void bprint_escaped_path(AVBPrint *bp, const char *path)
{
#define NEEDS_ESCAPE(ch) \
    ((ch) <= ' ' || (ch) >= '\x7f' || \
     (ch) == '"' || (ch) == '%' || (ch) == '<' || (ch) == '>' || (ch) == '\\' || \
     (ch) == '^' || (ch) == '`' || (ch) == '{' || (ch) == '}' || (ch) == '|')
    while (*path) {
        char buf[1024];
        char *q = buf;
        while (*path && q - buf < sizeof(buf) - 4) {
            if (path[0] == '%' && av_isxdigit(path[1]) && av_isxdigit(path[2])) {
                *q++ = *path++;
                *q++ = *path++;
                *q++ = *path++;
            } else if (NEEDS_ESCAPE(*path)) {
                q += snprintf(q, 4, "%%%02X", (uint8_t)*path++);
            } else {
                *q++ = *path++;
            }
        }
        av_bprint_append_data(bp, buf, q - buf);
    }
}

static int http_connect(URLContext *h, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth)
{
    HTTPContext *s = h->priv_data;
    int post, err;
    AVBPrint request;
    char *authstr = NULL, *proxyauthstr = NULL;
    uint64_t off = s->off;
    const char *method;
    int send_expect_100 = 0;

#if CONFIG_LIBNGHTTP2
    /* Check if HTTP/2 was negotiated via ALPN or session already exists */
    if (s->http2 != 0 && s->hd) {
        char *alpn_selected = NULL;
        int need_new_session = 0;

        /* Check if we already have an HTTP/2 session */
        if (s->h2_session && s->is_http2) {
            /* Reuse existing session, just reset stream state */
            h2_stream_reset(s);
            av_log(h, AV_LOG_DEBUG, "Reusing HTTP/2 session\n");
        } else {
            av_opt_get(s->hd->priv_data, "alpn_selected", 0, (uint8_t **)&alpn_selected);
            if (alpn_selected && !strcmp(alpn_selected, "h2")) {
                need_new_session = 1;
                s->is_http2 = 1;
                av_freep(&s->http_version);
                s->http_version = av_strdup("2");
                av_log(h, AV_LOG_INFO, "Using HTTP/2\n");
            }
            av_free(alpn_selected);
        }

        if (s->is_http2) {
            if (need_new_session) {
                /* Initialize HTTP/2 session */
                err = h2_session_init(h);
                if (err < 0)
                    return err;
            }

            /* Determine method */
            post = h->flags & AVIO_FLAG_WRITE;
            if (s->method)
                method = s->method;
            else
                method = post ? "POST" : "GET";

            /* Submit HTTP/2 request */
            err = h2_submit_request(h, method, hoststr, path, s->user_agent);
            if (err < 0)
                return err;

            /* Read response headers */
            while (!s->h2_stream_closed && s->http_code == 0) {
                err = h2_recv_data(h);
                if (err < 0 && err != AVERROR_EOF)
                    return err;
                if (err == AVERROR_EOF)
                    break;
            }

            s->off = off;
            /* For redirect responses, always return 0 to allow redirect handling */
            if (s->http_code >= 300 && s->http_code < 400)
                return 0;
            return (off == s->filesize) ? AVERROR_EOF : 0;
        }
    }
#endif

    av_bprint_init_for_buffer(&request, s->buffer, sizeof(s->buffer));

    /* send http header */
    post = h->flags & AVIO_FLAG_WRITE;

    if (s->post_data) {
        /* force POST method and disable chunked encoding when
         * custom HTTP post data is set */
        post            = 1;
        s->chunked_post = 0;
    }

    if (s->method)
        method = s->method;
    else
        method = post ? "POST" : "GET";

    authstr      = ff_http_auth_create_response(&s->auth_state, auth,
                                                local_path, method);
    proxyauthstr = ff_http_auth_create_response(&s->proxy_auth_state, proxyauth,
                                                local_path, method);

     if (post && !s->post_data) {
        if (s->send_expect_100 != -1) {
            send_expect_100 = s->send_expect_100;
        } else {
            send_expect_100 = 0;
            /* The user has supplied authentication but we don't know the auth type,
             * send Expect: 100-continue to get the 401 response including the
             * WWW-Authenticate header, or an 100 continue if no auth actually
             * is needed. */
            if (auth && *auth &&
                s->auth_state.auth_type == HTTP_AUTH_NONE &&
                s->http_code != 401)
                send_expect_100 = 1;
        }
    }

    av_bprintf(&request, "%s ", method);
    bprint_escaped_path(&request, path);
    av_bprintf(&request, " HTTP/1.1\r\n");

    if (post && s->chunked_post)
        av_bprintf(&request, "Transfer-Encoding: chunked\r\n");
    /* set default headers if needed */
    if (!has_header(s->headers, "\r\nUser-Agent: "))
        av_bprintf(&request, "User-Agent: %s\r\n", s->user_agent);
    if (s->referer) {
        /* set default headers if needed */
        if (!has_header(s->headers, "\r\nReferer: "))
            av_bprintf(&request, "Referer: %s\r\n", s->referer);
    }
    if (!has_header(s->headers, "\r\nAccept: "))
        av_bprintf(&request, "Accept: */*\r\n");
    // Note: we send the Range header on purpose, even when we're probing,
    // since it allows us to detect more reliably if a (non-conforming)
    // server supports seeking by analysing the reply headers.
    if (!has_header(s->headers, "\r\nRange: ") && !post && (s->off > 0 || s->end_off || s->seekable != 0)) {
        av_bprintf(&request, "Range: bytes=%"PRIu64"-", s->off);
        if (s->end_off)
            av_bprintf(&request, "%"PRId64, s->end_off - 1);
        av_bprintf(&request, "\r\n");
    }
    if (send_expect_100 && !has_header(s->headers, "\r\nExpect: "))
        av_bprintf(&request, "Expect: 100-continue\r\n");

    if (!has_header(s->headers, "\r\nConnection: "))
        av_bprintf(&request, "Connection: %s\r\n", s->multiple_requests ? "keep-alive" : "close");

    if (!has_header(s->headers, "\r\nHost: "))
        av_bprintf(&request, "Host: %s\r\n", hoststr);
    if (!has_header(s->headers, "\r\nContent-Length: ") && s->post_data)
        av_bprintf(&request, "Content-Length: %d\r\n", s->post_datalen);

    if (!has_header(s->headers, "\r\nContent-Type: ") && s->content_type)
        av_bprintf(&request, "Content-Type: %s\r\n", s->content_type);
    if (!has_header(s->headers, "\r\nCookie: ") && s->cookies) {
        char *cookies = NULL;
        if (!get_cookies(s, &cookies, path, hoststr) && cookies) {
            av_bprintf(&request, "Cookie: %s\r\n", cookies);
            av_free(cookies);
        }
    }
    if (!has_header(s->headers, "\r\nIcy-MetaData: ") && s->icy)
        av_bprintf(&request, "Icy-MetaData: 1\r\n");

    /* now add in custom headers */
    if (s->headers)
        av_bprintf(&request, "%s", s->headers);

    if (authstr)
        av_bprintf(&request, "%s", authstr);
    if (proxyauthstr)
        av_bprintf(&request, "Proxy-%s", proxyauthstr);
    av_bprintf(&request, "\r\n");

    av_log(h, AV_LOG_DEBUG, "request: %s\n", request.str);

    if (!av_bprint_is_complete(&request)) {
        av_log(h, AV_LOG_ERROR, "overlong headers\n");
        err = AVERROR(EINVAL);
        goto done;
    }

    if ((err = ffurl_write(s->hd, request.str, request.len)) < 0)
        goto done;

    if (s->post_data)
        if ((err = ffurl_write(s->hd, s->post_data, s->post_datalen)) < 0)
            goto done;

    /* init input buffer */
    s->buf_ptr          = s->buffer;
    s->buf_end          = s->buffer;
    s->line_count       = 0;
    s->off              = 0;
    s->icy_data_read    = 0;
    s->filesize         = UINT64_MAX;
    s->willclose        = 0;
    s->end_chunked_post = 0;
    s->end_header       = 0;
#if CONFIG_ZLIB
    s->compressed       = 0;
#endif
    if (post && !s->post_data && !send_expect_100) {
        /* Pretend that it did work. We didn't read any header yet, since
         * we've still to send the POST data, but the code calling this
         * function will check http_code after we return. */
        s->http_code = 200;
        err = 0;
        goto done;
    }

    /* wait for header */
    err = http_read_header(h);
    if (err < 0)
        goto done;

    if (s->new_location)
        s->off = off;

    err = (off == s->off) ? 0 : -1;
done:
    av_freep(&authstr);
    av_freep(&proxyauthstr);
    return err;
}

static int http_buf_read(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int len;

    if (s->chunksize != UINT64_MAX) {
        if (s->chunkend) {
            return AVERROR_EOF;
        }
        if (!s->chunksize) {
            char line[32];
            int err;

            do {
                if ((err = http_get_line(s, line, sizeof(line))) < 0)
                    return err;
            } while (!*line);    /* skip CR LF from last chunk */

            s->chunksize = strtoull(line, NULL, 16);

            av_log(h, AV_LOG_TRACE,
                   "Chunked encoding data size: %"PRIu64"\n",
                    s->chunksize);

            if (!s->chunksize && s->multiple_requests) {
                http_get_line(s, line, sizeof(line)); // read empty chunk
                s->chunkend = 1;
                return 0;
            }
            else if (!s->chunksize) {
                av_log(h, AV_LOG_DEBUG, "Last chunk received, closing conn\n");
                ffurl_closep(&s->hd);
                return 0;
            }
            else if (s->chunksize == UINT64_MAX) {
                av_log(h, AV_LOG_ERROR, "Invalid chunk size %"PRIu64"\n",
                       s->chunksize);
                return AVERROR(EINVAL);
            }
        }
        size = FFMIN(size, s->chunksize);
    }

    /* read bytes from input buffer first */
    len = s->buf_end - s->buf_ptr;
    if (len > 0) {
        if (len > size)
            len = size;
        memcpy(buf, s->buf_ptr, len);
        s->buf_ptr += len;
    } else {
        uint64_t target_end = s->end_off ? s->end_off : s->filesize;
        if ((!s->willclose || s->chunksize == UINT64_MAX) && s->off >= target_end)
            return AVERROR_EOF;
        len = ffurl_read(s->hd, buf, size);
        if ((!len || len == AVERROR_EOF) &&
            (!s->willclose || s->chunksize == UINT64_MAX) && s->off < target_end) {
            av_log(h, AV_LOG_ERROR,
                   "Stream ends prematurely at %"PRIu64", should be %"PRIu64"\n",
                   s->off, target_end
                  );
            return AVERROR(EIO);
        }
    }
    if (len > 0) {
        s->off += len;
        if (s->chunksize > 0 && s->chunksize != UINT64_MAX) {
            av_assert0(s->chunksize >= len);
            s->chunksize -= len;
        }
    }
    return len;
}

#if CONFIG_ZLIB
#define DECOMPRESS_BUF_SIZE (256 * 1024)
static int http_buf_read_compressed(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int ret;

    if (!s->inflate_buffer) {
        s->inflate_buffer = av_malloc(DECOMPRESS_BUF_SIZE);
        if (!s->inflate_buffer)
            return AVERROR(ENOMEM);
    }

    if (s->inflate_stream.avail_in == 0) {
        int read = http_buf_read(h, s->inflate_buffer, DECOMPRESS_BUF_SIZE);
        if (read <= 0)
            return read;
        s->inflate_stream.next_in  = s->inflate_buffer;
        s->inflate_stream.avail_in = read;
    }

    s->inflate_stream.avail_out = size;
    s->inflate_stream.next_out  = buf;

    ret = inflate(&s->inflate_stream, Z_SYNC_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END)
        av_log(h, AV_LOG_WARNING, "inflate return value: %d, %s\n",
               ret, s->inflate_stream.msg);

    return size - s->inflate_stream.avail_out;
}
#endif /* CONFIG_ZLIB */

#if CONFIG_LIBNGHTTP2
/* Read raw bytes from HTTP/2 buffer (for use by compression) */
static int h2_buf_read(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    size_t available;
    int err;

    /* Return data from buffer first */
    available = s->h2_recv_buf_len - s->h2_recv_buf_pos;
    if (available > 0) {
        size_t to_copy = FFMIN(available, (size_t)size);
        memcpy(buf, s->h2_recv_buf + s->h2_recv_buf_pos, to_copy);
        s->h2_recv_buf_pos += to_copy;
        s->off += to_copy;

        /* Compact buffer */
        if (s->h2_recv_buf_pos > s->h2_recv_buf_len / 2) {
            memmove(s->h2_recv_buf, s->h2_recv_buf + s->h2_recv_buf_pos,
                    s->h2_recv_buf_len - s->h2_recv_buf_pos);
            s->h2_recv_buf_len -= s->h2_recv_buf_pos;
            s->h2_recv_buf_pos = 0;
        }
        return (int)to_copy;
    }

    if (s->h2_stream_closed)
        return AVERROR_EOF;

    /* Receive more data */
    while (!s->h2_stream_closed) {
        err = h2_recv_data(h);
        if (err < 0)
            return err;

        available = s->h2_recv_buf_len - s->h2_recv_buf_pos;
        if (available > 0) {
            size_t to_copy = FFMIN(available, (size_t)size);
            memcpy(buf, s->h2_recv_buf + s->h2_recv_buf_pos, to_copy);
            s->h2_recv_buf_pos += to_copy;
            s->off += to_copy;
            return (int)to_copy;
        }
    }

    return AVERROR_EOF;
}

#if CONFIG_ZLIB
static int h2_buf_read_compressed(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int ret;

    if (!s->inflate_buffer) {
        s->inflate_buffer = av_malloc(DECOMPRESS_BUF_SIZE);
        if (!s->inflate_buffer)
            return AVERROR(ENOMEM);
    }

    if (s->inflate_stream.avail_in == 0) {
        int read = h2_buf_read(h, s->inflate_buffer, DECOMPRESS_BUF_SIZE);
        if (read <= 0)
            return read;
        s->inflate_stream.next_in  = s->inflate_buffer;
        s->inflate_stream.avail_in = read;
    }

    s->inflate_stream.avail_out = size;
    s->inflate_stream.next_out  = buf;

    ret = inflate(&s->inflate_stream, Z_SYNC_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END)
        av_log(h, AV_LOG_WARNING, "HTTP/2 inflate return value: %d, %s\n",
               ret, s->inflate_stream.msg);

    return size - s->inflate_stream.avail_out;
}
#endif /* CONFIG_ZLIB */
#endif /* CONFIG_LIBNGHTTP2 */

static int64_t http_seek_internal(URLContext *h, int64_t off, int whence, int force_reconnect);

static int http_read_stream(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int err, read_ret;
    int64_t seek_ret;
    int reconnect_delay = 0;
    int reconnect_delay_total = 0;
    int conn_attempts = 1;

    if (!s->hd)
        return AVERROR_EOF;

#if CONFIG_LIBNGHTTP2
    /* HTTP/2 read path */
    if (s->is_http2 && s->h2_session) {
        size_t available;
        size_t to_copy;

#if CONFIG_ZLIB
        /* Handle compressed content using HTTP/2 specific decompression */
        if (s->compressed)
            return h2_buf_read_compressed(h, buf, size);
#endif

        /* Return data from buffer first */
        available = s->h2_recv_buf_len - s->h2_recv_buf_pos;
        if (available > 0) {
            to_copy = FFMIN(available, (size_t)size);
            memcpy(buf, s->h2_recv_buf + s->h2_recv_buf_pos, to_copy);
            s->h2_recv_buf_pos += to_copy;
            s->off += to_copy;

            /* Compact buffer if we've consumed enough */
            if (s->h2_recv_buf_pos > s->h2_recv_buf_len / 2) {
                memmove(s->h2_recv_buf, s->h2_recv_buf + s->h2_recv_buf_pos,
                        s->h2_recv_buf_len - s->h2_recv_buf_pos);
                s->h2_recv_buf_len -= s->h2_recv_buf_pos;
                s->h2_recv_buf_pos = 0;
            }

            return (int)to_copy;
        }

        /* Check if stream is closed */
        if (s->h2_stream_closed) {
            /* Check for premature EOF (like HTTP/1.1 does) - only if filesize is known */
            if (s->filesize != UINT64_MAX && s->off < s->filesize) {
                av_log(h, AV_LOG_ERROR,
                       "HTTP/2 stream ends prematurely at %"PRIu64", should be %"PRIu64"\n",
                       s->off, s->filesize);
                return AVERROR(EIO);
            }
            return AVERROR_EOF;
        }

        /* Receive more data */
        err = h2_recv_data(h);
        if (err < 0)
            return err;

        /* Check again for available data */
        available = s->h2_recv_buf_len - s->h2_recv_buf_pos;
        if (available > 0) {
            to_copy = FFMIN(available, (size_t)size);
            memcpy(buf, s->h2_recv_buf + s->h2_recv_buf_pos, to_copy);
            s->h2_recv_buf_pos += to_copy;
            s->off += to_copy;
            return (int)to_copy;
        }

        /* No data available yet, keep trying until we get data or stream closes */
        if (h->flags & AVIO_FLAG_NONBLOCK)
            return AVERROR(EAGAIN);

        /* Loop until we have data or stream is closed */
        while (!s->h2_stream_closed) {
            err = h2_recv_data(h);
            if (err < 0)
                return err;

            available = s->h2_recv_buf_len - s->h2_recv_buf_pos;
            if (available > 0) {
                to_copy = FFMIN(available, (size_t)size);
                memcpy(buf, s->h2_recv_buf + s->h2_recv_buf_pos, to_copy);
                s->h2_recv_buf_pos += to_copy;
                s->off += to_copy;
                return (int)to_copy;
            }
        }

        /* Final premature EOF check - only if filesize is known */
        if (s->filesize != UINT64_MAX && s->off < s->filesize) {
            av_log(h, AV_LOG_ERROR,
                   "HTTP/2 stream ends prematurely at %"PRIu64", should be %"PRIu64"\n",
                   s->off, s->filesize);
            return AVERROR(EIO);
        }
        return AVERROR_EOF;
    }
#endif /* CONFIG_LIBNGHTTP2 */

    if (s->end_chunked_post && !s->end_header) {
        err = http_read_header(h);
        if (err < 0)
            return err;
    }

#if CONFIG_ZLIB
    if (s->compressed)
        return http_buf_read_compressed(h, buf, size);
#endif /* CONFIG_ZLIB */
    read_ret = http_buf_read(h, buf, size);
    while (read_ret < 0) {
        uint64_t target = h->is_streamed ? 0 : s->off;
        bool is_premature = s->filesize > 0 && s->off < s->filesize;

        if (read_ret == AVERROR_EXIT)
            break;

        if (h->is_streamed && !s->reconnect_streamed)
            break;

        if (!(s->reconnect && is_premature) &&
            !(s->reconnect_at_eof && read_ret == AVERROR_EOF)) {
            if (is_premature)
                return AVERROR(EIO);
            else
                break;
        }

        if (reconnect_delay > s->reconnect_delay_max || (s->reconnect_max_retries >= 0 && conn_attempts > s->reconnect_max_retries) ||
            reconnect_delay_total > s->reconnect_delay_total_max)
            return AVERROR(EIO);

        av_log(h, AV_LOG_WARNING, "Will reconnect at %"PRIu64" in %d second(s), error=%s.\n", s->off, reconnect_delay, av_err2str(read_ret));
        err = ff_network_sleep_interruptible(1000U*1000*reconnect_delay, &h->interrupt_callback);
        if (err != AVERROR(ETIMEDOUT))
            return err;
        reconnect_delay_total += reconnect_delay;
        reconnect_delay = 1 + 2*reconnect_delay;
        conn_attempts++;
        seek_ret = http_seek_internal(h, target, SEEK_SET, 1);
        if (seek_ret >= 0 && seek_ret != target) {
            av_log(h, AV_LOG_ERROR, "Failed to reconnect at %"PRIu64".\n", target);
            return read_ret;
        }

        read_ret = http_buf_read(h, buf, size);
    }

    return read_ret;
}

// Like http_read_stream(), but no short reads.
// Assumes partial reads are an error.
static int http_read_stream_all(URLContext *h, uint8_t *buf, int size)
{
    int pos = 0;
    while (pos < size) {
        int len = http_read_stream(h, buf + pos, size - pos);
        if (len < 0)
            return len;
        pos += len;
    }
    return pos;
}

static void update_metadata(URLContext *h, char *data)
{
    char *key;
    char *val;
    char *end;
    char *next = data;
    HTTPContext *s = h->priv_data;

    while (*next) {
        key = next;
        val = strstr(key, "='");
        if (!val)
            break;
        end = strstr(val, "';");
        if (!end)
            break;

        *val = '\0';
        *end = '\0';
        val += 2;

        av_dict_set(&s->metadata, key, val, 0);
        av_log(h, AV_LOG_VERBOSE, "Metadata update for %s: %s\n", key, val);

        next = end + 2;
    }
}

static int store_icy(URLContext *h, int size)
{
    HTTPContext *s = h->priv_data;
    /* until next metadata packet */
    uint64_t remaining;

    if (s->icy_metaint < s->icy_data_read)
        return AVERROR_INVALIDDATA;
    remaining = s->icy_metaint - s->icy_data_read;

    if (!remaining) {
        /* The metadata packet is variable sized. It has a 1 byte header
         * which sets the length of the packet (divided by 16). If it's 0,
         * the metadata doesn't change. After the packet, icy_metaint bytes
         * of normal data follows. */
        uint8_t ch;
        int len = http_read_stream_all(h, &ch, 1);
        if (len < 0)
            return len;
        if (ch > 0) {
            char data[255 * 16 + 1];
            int ret;
            len = ch * 16;
            ret = http_read_stream_all(h, data, len);
            if (ret < 0)
                return ret;
            data[len] = 0;
            if ((ret = av_opt_set(s, "icy_metadata_packet", data, 0)) < 0)
                return ret;
            update_metadata(h, data);
        }
        s->icy_data_read = 0;
        remaining        = s->icy_metaint;
    }

    return FFMIN(size, remaining);
}

static int http_read(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;

    if (s->icy_metaint > 0) {
        size = store_icy(h, size);
        if (size < 0)
            return size;
    }

    size = http_read_stream(h, buf, size);
    if (size > 0)
        s->icy_data_read += size;
    return size;
}

/* used only when posting data */
static int http_write(URLContext *h, const uint8_t *buf, int size)
{
    char temp[11] = "";  /* 32-bit hex + CRLF + nul */
    int ret;
    char crlf[] = "\r\n";
    HTTPContext *s = h->priv_data;

    if (!s->chunked_post) {
        /* non-chunked data is sent without any special encoding */
        return ffurl_write(s->hd, buf, size);
    }

    /* silently ignore zero-size data since chunk encoding that would
     * signal EOF */
    if (size > 0) {
        /* upload data using chunked encoding */
        snprintf(temp, sizeof(temp), "%x\r\n", size);

        if ((ret = ffurl_write(s->hd, temp, strlen(temp))) < 0 ||
            (ret = ffurl_write(s->hd, buf, size)) < 0          ||
            (ret = ffurl_write(s->hd, crlf, sizeof(crlf) - 1)) < 0)
            return ret;
    }
    return size;
}

static int http_shutdown(URLContext *h, int flags)
{
    int ret = 0;
    char footer[] = "0\r\n\r\n";
    HTTPContext *s = h->priv_data;

    /* signal end of chunked encoding if used */
    if (((flags & AVIO_FLAG_WRITE) && s->chunked_post) ||
        ((flags & AVIO_FLAG_READ) && s->chunked_post && s->listen)) {
        ret = ffurl_write(s->hd, footer, sizeof(footer) - 1);
        ret = ret > 0 ? 0 : ret;
        /* flush the receive buffer when it is write only mode */
        if (!(flags & AVIO_FLAG_READ)) {
            char buf[1024];
            int read_ret;
            s->hd->flags |= AVIO_FLAG_NONBLOCK;
            read_ret = ffurl_read(s->hd, buf, sizeof(buf));
            s->hd->flags &= ~AVIO_FLAG_NONBLOCK;
            if (read_ret < 0 && read_ret != AVERROR(EAGAIN)) {
                av_log(h, AV_LOG_ERROR, "URL read error: %s\n", av_err2str(read_ret));
                ret = read_ret;
            }
        }
        s->end_chunked_post = 1;
    }

    return ret;
}

static int http_close(URLContext *h)
{
    int ret = 0;
    HTTPContext *s = h->priv_data;

#if CONFIG_ZLIB
    inflateEnd(&s->inflate_stream);
    av_freep(&s->inflate_buffer);
#endif /* CONFIG_ZLIB */

#if CONFIG_LIBNGHTTP2
    h2_session_close(s);
#endif /* CONFIG_LIBNGHTTP2 */

    if (s->hd && !s->end_chunked_post)
        /* Close the write direction by sending the end of chunked encoding. */
        ret = http_shutdown(h, h->flags);

    if (s->hd)
        ffurl_closep(&s->hd);
    av_dict_free(&s->chained_options);
    av_dict_free(&s->cookie_dict);
    av_dict_free(&s->redirect_cache);
    av_freep(&s->new_location);
    av_freep(&s->uri);
    return ret;
}

static int64_t http_seek_internal(URLContext *h, int64_t off, int whence, int force_reconnect)
{
    HTTPContext *s = h->priv_data;
    URLContext *old_hd = s->hd;
    uint64_t old_off = s->off;
    uint8_t old_buf[BUFFER_SIZE];
    int old_buf_size, ret;
    AVDictionary *options = NULL;

    if (whence == AVSEEK_SIZE)
        return s->filesize;
    else if (!force_reconnect &&
             ((whence == SEEK_CUR && off == 0) ||
              (whence == SEEK_SET && off == s->off)))
        return s->off;
    else if ((s->filesize == UINT64_MAX && whence == SEEK_END))
        return AVERROR(ENOSYS);

    if (whence == SEEK_CUR)
        off += s->off;
    else if (whence == SEEK_END)
        off += s->filesize;
    else if (whence != SEEK_SET)
        return AVERROR(EINVAL);
    if (off < 0)
        return AVERROR(EINVAL);
    s->off = off;

    if (s->off && h->is_streamed)
        return AVERROR(ENOSYS);

    /* do not try to make a new connection if seeking past the end of the file */
    if (s->end_off || s->filesize != UINT64_MAX) {
        uint64_t end_pos = s->end_off ? s->end_off : s->filesize;
        if (s->off >= end_pos)
            return s->off;
    }

    /* if the location changed (redirect), revert to the original uri */
    if (strcmp(s->uri, s->location)) {
        char *new_uri;
        new_uri = av_strdup(s->uri);
        if (!new_uri)
            return AVERROR(ENOMEM);
        av_free(s->location);
        s->location = new_uri;
    }

    /* we save the old context in case the seek fails */
    old_buf_size = s->buf_end - s->buf_ptr;
    memcpy(old_buf, s->buf_ptr, old_buf_size);
    s->hd = NULL;

    /* if it fails, continue on old connection */
    if ((ret = http_open_cnx(h, &options)) < 0) {
        av_dict_free(&options);
        memcpy(s->buffer, old_buf, old_buf_size);
        s->buf_ptr = s->buffer;
        s->buf_end = s->buffer + old_buf_size;
        s->hd      = old_hd;
        s->off     = old_off;
        return ret;
    }
    av_dict_free(&options);
    ffurl_close(old_hd);
    return off;
}

static int64_t http_seek(URLContext *h, int64_t off, int whence)
{
    return http_seek_internal(h, off, whence, 0);
}

static int http_get_file_handle(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    return ffurl_get_file_handle(s->hd);
}

static int http_get_short_seek(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    if (s->short_seek_size >= 1)
        return s->short_seek_size;
    return ffurl_get_short_seek(s->hd);
}

#define HTTP_CLASS(flavor)                          \
static const AVClass flavor ## _context_class = {   \
    .class_name = # flavor,                         \
    .item_name  = av_default_item_name,             \
    .option     = options,                          \
    .version    = LIBAVUTIL_VERSION_INT,            \
}

#if CONFIG_HTTP_PROTOCOL
HTTP_CLASS(http);

const URLProtocol ff_http_protocol = {
    .name                = "http",
    .url_open2           = http_open,
    .url_accept          = http_accept,
    .url_handshake       = http_handshake,
    .url_read            = http_read,
    .url_write           = http_write,
    .url_seek            = http_seek,
    .url_close           = http_close,
    .url_get_file_handle = http_get_file_handle,
    .url_get_short_seek  = http_get_short_seek,
    .url_shutdown        = http_shutdown,
    .priv_data_size      = sizeof(HTTPContext),
    .priv_data_class     = &http_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,tls,rtp,tcp,udp,crypto,httpproxy,data"
};
#endif /* CONFIG_HTTP_PROTOCOL */

#if CONFIG_HTTPS_PROTOCOL
HTTP_CLASS(https);

const URLProtocol ff_https_protocol = {
    .name                = "https",
    .url_open2           = http_open,
    .url_read            = http_read,
    .url_write           = http_write,
    .url_seek            = http_seek,
    .url_close           = http_close,
    .url_get_file_handle = http_get_file_handle,
    .url_get_short_seek  = http_get_short_seek,
    .url_shutdown        = http_shutdown,
    .priv_data_size      = sizeof(HTTPContext),
    .priv_data_class     = &https_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,tls,rtp,tcp,udp,crypto,httpproxy"
};
#endif /* CONFIG_HTTPS_PROTOCOL */

#if CONFIG_HTTPPROXY_PROTOCOL
static int http_proxy_close(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    if (s->hd)
        ffurl_closep(&s->hd);
    return 0;
}

static int http_proxy_open(URLContext *h, const char *uri, int flags)
{
    HTTPContext *s = h->priv_data;
    char hostname[1024], hoststr[1024];
    char auth[1024], pathbuf[1024], *path;
    char lower_url[100];
    int port, ret = 0, auth_attempts = 0;
    HTTPAuthType cur_auth_type;
    char *authstr;

    if( s->seekable == 1 )
        h->is_streamed = 0;
    else
        h->is_streamed = 1;

    av_url_split(NULL, 0, auth, sizeof(auth), hostname, sizeof(hostname), &port,
                 pathbuf, sizeof(pathbuf), uri);
    ff_url_join(hoststr, sizeof(hoststr), NULL, NULL, hostname, port, NULL);
    path = pathbuf;
    if (*path == '/')
        path++;

    ff_url_join(lower_url, sizeof(lower_url), "tcp", NULL, hostname, port,
                NULL);
redo:
    ret = ffurl_open_whitelist(&s->hd, lower_url, AVIO_FLAG_READ_WRITE,
                               &h->interrupt_callback, NULL,
                               h->protocol_whitelist, h->protocol_blacklist, h);
    if (ret < 0)
        return ret;

    authstr = ff_http_auth_create_response(&s->proxy_auth_state, auth,
                                           path, "CONNECT");
    snprintf(s->buffer, sizeof(s->buffer),
             "CONNECT %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "%s%s"
             "\r\n",
             path,
             hoststr,
             authstr ? "Proxy-" : "", authstr ? authstr : "");
    av_freep(&authstr);

    if ((ret = ffurl_write(s->hd, s->buffer, strlen(s->buffer))) < 0)
        goto fail;

    s->buf_ptr    = s->buffer;
    s->buf_end    = s->buffer;
    s->line_count = 0;
    s->filesize   = UINT64_MAX;
    cur_auth_type = s->proxy_auth_state.auth_type;

    /* Note: This uses buffering, potentially reading more than the
     * HTTP header. If tunneling a protocol where the server starts
     * the conversation, we might buffer part of that here, too.
     * Reading that requires using the proper ffurl_read() function
     * on this URLContext, not using the fd directly (as the tls
     * protocol does). This shouldn't be an issue for tls though,
     * since the client starts the conversation there, so there
     * is no extra data that we might buffer up here.
     */
    ret = http_read_header(h);
    if (ret < 0)
        goto fail;

    auth_attempts++;
    if (s->http_code == 407 &&
        (cur_auth_type == HTTP_AUTH_NONE || s->proxy_auth_state.stale) &&
        s->proxy_auth_state.auth_type != HTTP_AUTH_NONE && auth_attempts < 2) {
        ffurl_closep(&s->hd);
        goto redo;
    }

    if (s->http_code < 400)
        return 0;
    ret = ff_http_averror(s->http_code, AVERROR(EIO));

fail:
    http_proxy_close(h);
    return ret;
}

static int http_proxy_write(URLContext *h, const uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    return ffurl_write(s->hd, buf, size);
}

const URLProtocol ff_httpproxy_protocol = {
    .name                = "httpproxy",
    .url_open            = http_proxy_open,
    .url_read            = http_buf_read,
    .url_write           = http_proxy_write,
    .url_close           = http_proxy_close,
    .url_get_file_handle = http_get_file_handle,
    .priv_data_size      = sizeof(HTTPContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
};
#endif /* CONFIG_HTTPPROXY_PROTOCOL */
