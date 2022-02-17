# A tiny _HTTP client library_ built on top of [libcurl](https://curl.se/libcurl/).


### Prerequisities
- OpenSSL `1.1.1` (libssl-dev)
- ZLIB (zlib1g-dev)

### Build
```
cmake -S . -B build -GNinja
cmake --build build
```

### GET
```C
#include <http.h>
#include <stdio.h>

char *get_token() { return (char *)"my oAuth2 token\0"; }

const char *get_url() { return "https://raw.githubusercontent.com/kuba--/http/master/README.md\0"; }

// ...

struct http_request_t *req = http_request_init();
http_add_oauth2header(req, get_token, NULL);

struct http_response_t *resp = http_response_init();
resp->body = http_body_init();
resp->body->fread = http_body_readall;

char *err = (char *)http_get(req, get_url());
if (err) {
    printf("%s\n", err);
    goto cleanup;
}

err = (char *)http_do(req, resp);
if (err) {
    printf("%s\n", err);
    goto cleanup;
}

printf("[%ld] [%.2f]s [%.2f]s:\n%s\n", resp->status, resp->total_time, resp->connect_time, (char *)resp->body->stream);

cleanup:
http_cleanup(req, resp);
```