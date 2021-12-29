/*
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#define __STDC_WANT_LIB_EXT1__ 1

#include "http.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_MSC_VER)
#include <windows.h>
#define _CRT_SECURE_NO_WARNINGS
/* The Microsoft Visual C compiler doesn't support the "inline" keyword. */
#define inline
#endif /* _MSC_VER */

#ifndef ENCODE_MAX_SIZE
#define ENCODE_MAX_SIZE 1024
#endif

#define GB ((unsigned long long)1ULL << 30)

static size_t header_readall(char *buffer, size_t size, size_t count, struct curl_slist **header)
{
    size_t sz = count * size;
    char *h = strndup(buffer, sz);
    if (!h) {
        return 0;
    }
    if (strlen(h) > 0) {
        *header = curl_slist_append(*header, h);
    }
    free(h);
    return sz;
}

struct http_body_t *http_body_init(void) {
    struct http_body_t *body = (struct http_body_t *)malloc(sizeof(struct http_body_t));
    if (body) {
        body->stream = NULL;
        body->len = (unsigned long long)0ULL;
        body->fread = NULL;
    }
    return body;
}

void http_body_cleanup(struct http_body_t *body) {
    if (body) {
        body->fread = NULL;
        if (body->stream) {
            free(body->stream);
            body->stream = NULL;
        }
        free(body);
        body = NULL;
    }
}

size_t http_body_readall(void *data, size_t size, size_t count, struct http_body_t *body) {
    size_t sz = size * count;
    size_t len = body->len + sz;
    body->stream = realloc(body->stream, len + 1);
    if (!body->stream) {
        return 0;
    }

    memcpy(((char *)body->stream) + body->len, data, sz);
    ((char *)body->stream)[len] = '\0';
    body->len = len;
    return sz;
}

struct http_request_t *http_request_init(void) {
    struct http_request_t *req = (struct http_request_t *)malloc(sizeof(struct http_request_t));
    if (req) {
        req->curl = curl_easy_init();
        if (!req->curl) {
            http_request_cleanup(req);
            return NULL;
        }

        // follow any Location: header that the server sends as part of a HTTP header in a 3xx response.
        curl_easy_setopt(req->curl, CURLOPT_FOLLOWLOCATION, 1L);
        // used to make sure the lib is threadsafe
        curl_easy_setopt(req->curl, CURLOPT_NOSIGNAL, 1L);

        req->header = NULL;
        req->body = NULL;
    }
    return req;
}

void http_request_cleanup(struct http_request_t *req)
{
    if (req) {
        if (req->curl) {
            curl_easy_cleanup(req->curl);
            req->curl = NULL;
        }
        if (req->header) {
            curl_slist_free_all(req->header);
            req->header = NULL;
        }
        if (req->body) {
            http_body_cleanup(req->body);
            req->body = NULL;
        }
        free(req);
        req = NULL;
    }
}

void http_request_reset(struct http_request_t *req) {
    if (req) {
        if (req->header) {
            curl_slist_free_all(req->header);
            req->header = NULL;
        }
        if (req->body) {
            http_body_cleanup(req->body);
            req->body = NULL;
        }
        if (req->curl) {
            curl_easy_reset(req->curl);
            // follow any Location: header that the server sends as part of a HTTP header in a 3xx response.
            curl_easy_setopt(req->curl, CURLOPT_FOLLOWLOCATION, 1L);
            // used to make sure the lib is threadsafe
            curl_easy_setopt(req->curl, CURLOPT_NOSIGNAL, 1L);
        }
    }
}

void http_add_header(struct http_request_t *req, const char *header) {
    if (!req || !header)
        return;
    if (strlen(header) > 0) {
        req->header = curl_slist_append(req->header, header);
    }
}

void http_add_header2(struct http_request_t  *req, const char *name, const char *value)
{
    if (!req || !name || !value)
        return;
    if (strlen(name) > 0) {
        char header[MAX_HEADER_LEN + 1] = { 0 };
        snprintf(header, MAX_HEADER_LEN, "%s:%s", name, value);
        http_add_header(req, header);
    }
}

void http_add_oauth2header(struct http_request_t *req, char *(*get_access_token)(void), void (*free_access_token)(char *token)) {
    if (req && get_access_token) {
        char *token = get_access_token();
        if (token) {
            char header[MAX_HEADER_LEN + 1] = { 0 };
            snprintf(header, MAX_HEADER_LEN, HTTP_HEADER_AUTHORIZATION ":Bearer %s", token);
            http_add_header(req, header);

            if (free_access_token) {
                free_access_token(token);
            }
        }
    }
}

struct http_response_t *http_response_init(void) {
    struct http_response_t *resp = (struct http_response_t *)malloc(sizeof(struct http_response_t));
    if (resp) {
        resp->status = 0L;
        resp->header = NULL;
        resp->body = NULL;
        resp->total_time = 0.0;
        resp->namelookup_time = 0.0;
        resp->connect_time = 0.0;
        resp->upload_speed = 0.0;
        resp->download_speed = 0.0;
        resp->upload_size = 0.0;
        resp->download_size = 0.0;
    }
    return resp;
}

void http_response_cleanup(struct http_response_t *resp) {
    if (resp) {
        if (resp->header) {
            curl_slist_free_all(resp->header);
            resp->header = NULL;
        }
        if (resp->body) {
            http_body_cleanup(resp->body);
            resp->body = NULL;
        }
        free(resp);
        resp = NULL;
    }
}

char *http_get_header(struct http_response_t *resp, const char *header) {
    if (resp) {
        struct curl_slist *h = resp->header;
        while (h) {
            if (strstr(h->data, header)) {
                char *val = strchr(h->data, ':');
                if (val && strlen(val) > 1)
                    return strdup(val + 1);
            }
            h = h->next;
        }
    }
    return NULL;
}

const char *http_get(struct http_request_t *req, const char *url) {
    if (!req) {
        return NULL;
    }

    CURLcode code = curl_easy_setopt(req->curl, CURLOPT_URL, url);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    return NULL;
}

const char *http_post(struct http_request_t *req, const char *url, const char *content_type, const char *content) {
    if (!req)
        return NULL;
    CURLcode code;
    long len = 0L;

    code = curl_easy_setopt(req->curl, CURLOPT_POSTFIELDSIZE, (content) ? strlen(content) : 0);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    code = curl_easy_setopt(req->curl, CURLOPT_POST, 1L);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    code = curl_easy_setopt(req->curl, CURLOPT_URL, url);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    if (content_type) {
        char content_type_header[MAX_HEADER_LEN + 1] = { 0 };
        snprintf(content_type_header, MAX_HEADER_LEN, HTTP_HEADER_CONTENTTYPE ": %s", ((!content_type) ? HTTP_CONTENTTYPE_STREAM : content_type));
        http_add_header(req, content_type_header);
    }

    // If you want to do a zero-byte POST, you need to set CURLOPT_POSTFIELDSIZE explicitly to zero,
    // as simply setting CURLOPT_POSTFIELDS to NULL or "" just effectively disables the sending of the specified string.
    // libcurl will instead assume that you'll send the POST data using the read callback!
    // Using POST with HTTP 1.1 implies the use of a "Expect: 100-continue" header. You can disable this header with CURLOPT_HTTPHEADER as usual.
    if (content) {
        code = curl_easy_setopt(req->curl, CURLOPT_POSTFIELDS, content);
        if (code != CURLE_OK)
            return curl_easy_strerror(code);
        len = strlen(content);
    }

    code = curl_easy_setopt(req->curl, CURLOPT_POSTFIELDSIZE, len);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    return NULL;
}

const char *http_put(struct http_request_t *req, const char *url, const char *content_type) {
    if (!req)
        return NULL;
    CURLcode code;

    code = curl_easy_setopt(req->curl, CURLOPT_UPLOAD, 1L);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    code = curl_easy_setopt(req->curl, CURLOPT_URL, url);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    char content_type_header[MAX_HEADER_LEN + 1] = { 0 };
    snprintf(content_type_header, MAX_HEADER_LEN, HTTP_HEADER_CONTENTTYPE ": %s", ((!content_type) ? HTTP_CONTENTTYPE_STREAM : content_type));
    http_add_header(req, content_type_header);

    if (req->body) {
        code = (req->body->len < (unsigned long long)2 * GB) ? curl_easy_setopt(req->curl, CURLOPT_INFILESIZE, req->body->len) : curl_easy_setopt(req->curl, CURLOPT_INFILESIZE_LARGE, req->body->len);
        if (code != CURLE_OK)
            return curl_easy_strerror(code);
    } else {
        code = curl_easy_setopt(req->curl, CURLOPT_INFILESIZE, 0);
        if (code != CURLE_OK)
            return curl_easy_strerror(code);
    }

    return NULL;
}

const char *http_delete(struct http_request_t *req, const char *url) {
    if (!req)
        return NULL;

    CURLcode code = curl_easy_setopt(req->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    code = curl_easy_setopt(req->curl, CURLOPT_URL, url);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    return NULL;
}

const char *http_do(struct http_request_t *req, struct http_response_t *resp) {
    if (!req)
        return NULL;
    if (!resp)
        return NULL;

    CURLcode code = curl_easy_setopt(req->curl, CURLOPT_HTTPHEADER, req->header);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    code = curl_easy_setopt(req->curl, CURLOPT_HEADERDATA, &resp->header);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    code = curl_easy_setopt(req->curl, CURLOPT_HEADERFUNCTION, header_readall);
    if (code != CURLE_OK)
        return curl_easy_strerror(code);

    if (req->body) {
        code = curl_easy_setopt(req->curl, CURLOPT_READDATA, req->body);
        if (code != CURLE_OK)
            return curl_easy_strerror(code);

        code = curl_easy_setopt(req->curl, CURLOPT_READFUNCTION, req->body->fread);
        if (code != CURLE_OK)
            return curl_easy_strerror(code);
    }

    if (resp->body) {
        code = curl_easy_setopt(req->curl, CURLOPT_WRITEDATA, resp->body);
        if (code != CURLE_OK)
            return curl_easy_strerror(code);

        code = curl_easy_setopt(req->curl, CURLOPT_WRITEFUNCTION, resp->body->fread);
        if (code != CURLE_OK)
            return curl_easy_strerror(code);
    }

    // Perform the http request, code will get the return code
    code = curl_easy_perform(req->curl);
    if (code != CURLE_OK) {
        resp->status = code;
        return curl_easy_strerror(code);
    }

    curl_easy_getinfo(req->curl, CURLINFO_RESPONSE_CODE, &(resp->status));
    curl_easy_getinfo(req->curl, CURLINFO_TOTAL_TIME, &(resp->total_time));
    curl_easy_getinfo(req->curl, CURLINFO_NAMELOOKUP_TIME, &(resp->namelookup_time));
    curl_easy_getinfo(req->curl, CURLINFO_CONNECT_TIME, &(resp->connect_time));
    curl_easy_getinfo(req->curl, CURLINFO_SPEED_UPLOAD, &(resp->upload_speed));
    curl_easy_getinfo(req->curl, CURLINFO_SPEED_DOWNLOAD, &(resp->download_speed));
    curl_easy_getinfo(req->curl, CURLINFO_SIZE_UPLOAD, &(resp->upload_size));
    curl_easy_getinfo(req->curl, CURLINFO_SIZE_DOWNLOAD, &(resp->download_size));

    return NULL;
}

void http_cleanup(struct http_request_t *req, struct http_response_t *resp) {
    http_request_cleanup(req);
    http_response_cleanup(resp);
}