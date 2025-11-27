#ifndef UTILS_HXX
#define UTILS_HXX

#include <crow.h>
#include <nlohmann/json.hpp>
#include <concepts>
#include <type_traits>

template <typename T>
concept string = std::is_convertible_v<T, std::string> || std::is_convertible_v<T, const char*>;

inline crow::response json_response(int code, string auto const& body) {
    crow::response res(code, body);
    res.set_header("Content-Type", "application/json");
    return res;
}


inline crow::response json_response(int code, const nlohmann::json& body) {
    crow::response res(code, body.dump());
    res.set_header("Content-Type", "application/json");
    return res;
}

#endif
