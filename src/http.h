/*
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once
#ifndef HTTP_H
#define HTTP_H

#include <curl/curl.h>

#ifndef HTTP_SHARED
#define HTTP_EXPORT
#else
#ifdef _WIN32
#ifdef HTTP_BUILD_SHARED
#define HTTP_EXPORT __declspec(dllexport)
#else
#define HTTP_EXPORT __declspec(dllimport)
#endif
#else
#define HTTP_EXPORT __attribute__((visibility("default")))
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_HEADER_LEN
#define MAX_HEADER_LEN CURL_MAX_HTTP_HEADER
#endif

/**
 * HTTP status codes
 */
#define HTTP_STATUS_OK 200
#define HTTP_STATUS_CREATED 201
#define HTTP_STATUS_ACCEPTED 202
#define HTTP_STATUS_PARTIALCONTENT 206
#define HTTP_STATUS_BADREQUEST 400
#define HTTP_STATUS_UNAUTHORIZED 401
#define HTTP_STATUS_FORBIDDEN 403
#define HTTP_STATUS_NOTFOUND 404
#define HTTP_STATUS_CONFLICT 409
#define HTTP_STATUS_GATEWAYTIMEOUT 504

#define HTTP_HEADER_AUTHORIZATION "Authorization"
#define HTTP_HEADER_CONTENTLENGTH "Content-Length"
#define HTTP_HEADER_CONTENTTYPE "Content-Type"
#define HTTP_HEADER_SESSIONID "Session-Id"
#define HTTP_HEADER_CONTENTRANGE "Content-Range"
#define HTTP_HEADER_RANGE "Range"

#define HTTP_CONTENTTYPE_JSON "application/json"
#define HTTP_CONTENTTYPE_TEXT "text/plain"
#define HTTP_CONTENTTYPE_STREAM "application/octet-stream"

/**
 * @struct http_body_t
 * This data structure is used throughout the library to represent http body.
 */
struct http_body_t {
    void *stream;
    unsigned long long len;
    size_t (*fread)(void *data, size_t size, size_t count, struct http_body_t *body);
};
extern HTTP_EXPORT struct http_body_t *http_body_init(void);
extern HTTP_EXPORT void http_body_cleanup(struct http_body_t *body);
extern HTTP_EXPORT size_t http_body_readall(void *data, size_t size, size_t count, struct http_body_t *body);


/**
 * @struct http_request_t
 * Http request.
 */
struct http_request_t {
    CURL *curl;
    struct curl_slist *header;
    struct http_body_t *body;
};
extern HTTP_EXPORT struct http_request_t *http_request_init(void);
extern HTTP_EXPORT void http_request_cleanup(struct http_request_t *req);
extern HTTP_EXPORT void http_request_reset(struct http_request_t *req);
extern HTTP_EXPORT void http_add_header(struct http_request_t *req, const char *header);
extern HTTP_EXPORT void http_add_header2(struct http_request_t  *req, const char *name, const char *value);
extern HTTP_EXPORT void http_add_oauth2header(struct http_request_t *req, char *(*get_access_token)(void), void (*free_access_token)(char *token));

struct http_response_t {
    long status;
    struct curl_slist *header;
    struct http_body_t *body;

    //
    // Request internal information from the curl session
    //
    // The total time in seconds for the previous transfer, including name resolving, TCP connect etc.
    double total_time;
    // The time, in seconds, it took from the start until the name resolving was completed.
    double namelookup_time;
    // The time, in seconds, it took from the start until the connect to the remote host (or proxy) was completed.
    double connect_time;
    // The average upload speed that curl measured for the complete upload. Measured in bytes/second.
    double upload_speed;
    // The average download speed that curl measured for the complete download. Measured in bytes/second.
    double download_speed;
    // The total amount of bytes that were uploaded.
    double upload_size;
    // This counts actual payload data, what's also commonly called body.
    double download_size;
};
extern HTTP_EXPORT struct http_response_t *http_response_init(void);
extern HTTP_EXPORT void http_response_cleanup(struct http_response_t *resp);
extern HTTP_EXPORT char *http_get_header(struct http_response_t *resp, const char *header);

extern HTTP_EXPORT const char *http_get(struct http_request_t *req, const char *url);
extern HTTP_EXPORT const char *http_post(struct http_request_t *req, const char *url, const char *content_type, const char *content);
extern HTTP_EXPORT const char *http_put(struct http_request_t *req, const char *url, const char *content_type);
extern HTTP_EXPORT const char *http_delete(struct http_request_t *req, const char *url);
extern HTTP_EXPORT const char *http_do(struct http_request_t *req, struct http_response_t *resp);

extern HTTP_EXPORT void http_cleanup(struct http_request_t *req, struct http_response_t *resp);

#ifdef __cplusplus
}
#endif
#endif
