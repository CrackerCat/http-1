#include "http.hxx"

#include <curl/curl.h>

#include <algorithm>
#include <cstring>
#include <sstream>

static char* trim(char* str)
{
    while (isspace(*str)) {
        ++str;
    }

    char* last = str + strlen(str) - 1;
    while (last > str && isspace(*last)) {
        --last;
    }
    *(last + 1) = '\0';
    return str;
}

static size_t request_body_callback(char* buffer, size_t size, size_t count, std::iostream* body)
{
    size_t sz = size * count;
    body->read(buffer, sz);

    return body->gcount();
}

static size_t response_body_callback(char* buffer, size_t size, size_t count, std::iostream* body)
{
    size_t sz = size * count;
    body->write(buffer, sz);
    if (!body->good()) {
        return 0;
    }

    return sz;
}

static size_t response_headers_callback(char* buffer, size_t size, size_t count, Http::Headers* headers)
{
    size_t buflen = strnlen(buffer, size * count);

    std::string name;
    char* token = strsep(&buffer, ":");
    if (token) {
        name.assign(trim(token));
    }

    std::string value;
    token = strsep(&buffer, "");
    if (token) {
        value.assign(trim(token));
    }

    if (!name.empty()) {
        headers->insert({ name, value });
    }

    return buflen;
}

namespace Http {

std::string urlEncode(const std::string& url)
{
    char* urlesc = curl_easy_escape(NULL, url.c_str(), 0);
    std::string urlencoded(urlesc);

    curl_free(urlesc);
    return urlencoded;
}

std::string urlDecode(const std::string& url)
{
    char* urlunesc = curl_easy_unescape(NULL, url.c_str(), 0, NULL);
    std::string urldecoded(urlunesc);

    curl_free(urlunesc);
    return urldecoded;
}

bool Do(const Request& req, Response& resp, Error& err)
{
    // init curl
    CURLcode code;
    struct curl_slist* req_headers = nullptr;

    CURL* curl = curl_easy_init();
    char errbuf[CURL_ERROR_SIZE] = { 0 };
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, req.options.verbose);
    if (req.options.connect_timeout > 0L) {
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, req.options.connect_timeout);
    }
    if (req.options.timeout > 0L) {
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, req.options.timeout);
    }
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, (req.options.follow_location ? 0L : 1L));
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (req.options.ssl_verify_peer ? 0L : 1L));
    if (!req.options.ca.empty()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, const_cast<char*>(req.options.ca.c_str()));
    }
    if (!req.options.proxy.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, const_cast<char*>(req.options.proxy.c_str()));
    }
    if (!req.options.proxy_username.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, const_cast<char*>(req.options.proxy_username.c_str()));
    }
    if (!req.options.proxy_password.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, const_cast<char*>(req.options.proxy_password.c_str()));
    }
    if (!req.options.user_agent.empty()) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, const_cast<char*>(req.options.user_agent.c_str()));
    }

    // method
    std::string method(req.method);
    std::transform(method.begin(), method.end(), method.begin(), ::toupper);
    if (method.empty()) {
        method.assign("GET");
    }
    if (method == "POST") {
        code = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    } else if (method == "PUT") {
        code = curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    } else {
        code = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    }
    if (code != CURLE_OK) {
        goto cleanup;
    }

    // url
    code = curl_easy_setopt(curl, CURLOPT_URL, req.url.c_str());
    if (code != CURLE_OK) {
        goto cleanup;
    }

    // request headers
    for (const auto& h : req.headers) {
        req_headers = curl_slist_append(req_headers, std::string(h.first + ":" + h.second).c_str());
    }
    if (req_headers) {
        code = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_headers);
        if (code != CURLE_OK) {
            goto cleanup;
        }
    }

    // request body
    if (req.body.rdbuf() != nullptr) {
        code = curl_easy_setopt(curl, CURLOPT_READDATA, &req.body);
        if (code != CURLE_OK) {
            goto cleanup;
        }
        code = curl_easy_setopt(curl, CURLOPT_READFUNCTION, request_body_callback);
        if (code != CURLE_OK) {
            goto cleanup;
        }
    }

    // response headers
    code = curl_easy_setopt(curl, CURLOPT_HEADERDATA, &(resp.headers));
    if (code != CURLE_OK) {
        goto cleanup;
    }
    code = curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, response_headers_callback);
    if (code != CURLE_OK) {
        goto cleanup;
    }

    // response body
    if (resp.body.rdbuf() != nullptr) {
        code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &(resp.body));
        if (code != CURLE_OK) {
            goto cleanup;
        }
        code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_body_callback);
        if (code != CURLE_OK) {
            goto cleanup;
        }
    }

    // Perform the http request
    code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        goto cleanup;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &(resp.status));
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &(resp.total_time));
    curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &(resp.namelookup_time));
    curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &(resp.connect_time));
    curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &(resp.upload_speed));
    curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD, &(resp.download_speed));
    curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD, &(resp.upload_size));
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &(resp.download_size));

cleanup:
    if (req_headers) {
        curl_slist_free_all(req_headers);
        req_headers = nullptr;
    }
    if (curl) {
        curl_easy_cleanup(curl);
        curl = nullptr;
    }
    if (code != CURLE_OK) {
        err.code = static_cast<int>(code);
        err.error.assign(strlen(errbuf) > 0 ? errbuf : curl_easy_strerror(code));
        return false;
    }

    return true;
}

bool Head(const std::string& url, Response& resp, Error& err)
{
    const Request req("HEAD", url);
    return Do(req, resp, err);
}

bool Get(const std::string& url, Response& resp, Error& err)
{
    Request req("GET", url);
    return Do(req, resp, err);
}

bool Post(const std::string& url, const std::string& content_type, const std::string& body, Response& resp, Error& err)
{
    std::istringstream req_body(body);
    Request req("POST", url, { { HeaderContentType, content_type } }, req_body.rdbuf());
    req.options.follow_location = true;
    return Do(req, resp, err);
}

bool PostForm(const std::string& url, const Values& values, Response& resp, Error& err)
{
    int i = 0;
    std::stringstream req_body;
    for (const auto& kv : values) {
        for (const auto& v : kv.second) {
            if (i > 0) {
                req_body << "&";
            }
            req_body << kv.first << "=" << v;
            ++i;
        }
    }

    Request req("POST", url, { { HeaderContentType, ContentTypeForm } }, req_body.rdbuf());

    return Do(req, resp, err);
}

} // namespace Http
