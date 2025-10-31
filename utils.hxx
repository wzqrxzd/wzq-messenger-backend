#ifndef UTILS_HXX
#define UTILS_HXX

#include <crow.h>
#include <nlohmann/json.hpp>

// Для std::string
inline crow::response json_response(int code, const std::string& body) {
    crow::response res(code, body);
    res.set_header("Content-Type", "application/json");
    return res;
}

// Для const char*
inline crow::response json_response(int code, const char* body) {
    crow::response res(code, body);
    res.set_header("Content-Type", "application/json");
    return res;
}

// Для nlohmann::json
inline crow::response json_response(int code, const nlohmann::json& body) {
    crow::response res(code, body.dump());
    res.set_header("Content-Type", "application/json");
    return res;
}

#endif
