#pragma once
#ifndef HTTP_HTTP_HXX
#define HTTP_HTTP_HXX

#include <cstdint>

#include <initializer_list>
#include <map>
#include <sstream>
#include <string>

namespace Http {

constexpr long StatusOK { 200L };
constexpr long StatusCreated { 201L };
constexpr long StatusAccepted { 202L };
constexpr long StatusPartialContent { 206L };
constexpr long StatusBadRequest { 400L };
constexpr long StatusUnauthorized { 401L };
constexpr long StatusForbidden { 403L };
constexpr long StatusNotFound { 404L };
constexpr long StatusConflict { 409L };
constexpr long StatusInternalServerError { 500L };
constexpr long StatusGatewayTimeout { 504L };

const std::string HeaderAuthorization("Authorization");
const std::string HeaderContentLength("Content-Length");
const std::string HeaderContentType("Content-Type");

const std::string ContentTypeJSON("application/json");
const std::string ContentTypeText("text/plain");
const std::string ContentTypeStream("application/octet-stream");
const std::string ContentTypeForm("application/x-www-form-urlencoded");

// This function converts the given input string to a URL encoded string.
std::string urlEncode(const std::string& url);

// This function converts the given URL encoded input string to a "plain string".
std::string urlDecode(const std::string& url);

using Headers = std::multimap<std::string, std::string>;
using Values = std::multimap<std::string, std::initializer_list<std::string>>;

struct Options {
    // Make the library display a lot of verbose information about its operations.
    // The verbose information will be sent to stderr.
    bool verbose = false;

    // Set timeout (in seconds) for the connect phase.
    long connect_timeout = 0L;

    // Set maximum time (in seconds) the transfer is allowed to complete.
    long timeout = 0L;

    // Set follow any location: header that the server sends as part of a HTTP
    // header in a 3xx response.
    bool follow_location = true;

    // Set path to Certificate Authority (CA) bundle.
    std::string ca;

    // Pass a parameter to enable or disable.
    // If enabled, and the verification fails to prove that the certificate is authentic, the connection fails.
    bool ssl_verify_peer = false;

    // Set the proxy to use for the upcoming request.
    std::string proxy;
    std::string proxy_username;
    std::string proxy_password;

    // It will be used to set the User-Agent: header in the HTTP request.
    std::string user_agent;
};

struct Request {
    Request(const std::string& method, const std::string& url, const Headers headers = {}, std::streambuf* sb = nullptr)
        : method(method)
        , url(url)
        , headers(headers)
        , body(sb)
        , options({})
    {
    }
    ~Request() = default;

    std::string method;
    std::string url;
    Headers headers;
    std::iostream body;

    Options options;
};

struct Response {
    Response(std::streambuf* sb = nullptr)
        : status(0L)
        , headers({})
        , body(sb)
        , __sb("")
    {
        if (sb != nullptr) {
            body.rdbuf(sb);
        }
    }
    ~Response() = default;

    long status;
    Headers headers;

    std::iostream body { &__sb };

    // The total time in seconds for the previous transfer, including name
    // resolving, TCP connect etc.
    double total_time;
    // The time, in seconds, it took from the start until the name resolving was
    // completed.
    double namelookup_time;
    // The time, in seconds, it took from the start until the connect to the
    // remote host (or proxy) was completed.
    double connect_time;
    // The average upload speed that curl measured for the complete upload.
    // Measured in bytes/second.
    double upload_speed;
    // The average download speed that curl measured for the complete download.
    // Measured in bytes/second.
    double download_speed;
    // The total amount of bytes that were uploaded.
    double upload_size;
    // This counts actual payload data, what's also commonly called body.
    double download_size;

private:
    std::stringbuf __sb;
};

struct Error {
    int code;
    std::string error;
};

bool Do(const Request& req, Response& resp, Error& err);

bool Head(const std::string& url, Response& resp, Error& err);
bool Get(const std::string& url, Response& resp, Error& err);
bool Post(const std::string& url, const std::string& content_type, const std::string& body, Response& resp, Error& err);
bool PostForm(const std::string& url, const Values& values, Response& resp, Error& err);

} // namespace Http

#endif