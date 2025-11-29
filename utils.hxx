#ifndef UTILS_HXX
#define UTILS_HXX

#include "crow/http_response.h"
#include "database.hxx"
#include "error.hxx"
#include <crow.h>
#include <nlohmann/json.hpp>
#include <concepts>
#include <spdlog/spdlog.h>
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

template <typename Func>
crow::response trySafe(Func f)
{
  try {
    return f();
  } catch (const AuthException& e) {
    spdlog::debug("AuthError: {}", e.what());
    return json_response(400, std::format(R"({{"error":"{}"}})", e.what()));
  } catch (const JsonException& e) {
    spdlog::debug("JsonError: {}", e.what());
    return json_response(400, std::format(R"({{"error":"{}"}})", e.what()));
  } catch (const pqxx::sql_error& e) {
    spdlog::error("SQL error: {}, Query: {}", e.what(), e.query());
    return json_response(500, R"({"error":"Internal server error"})");
  } catch (const pqxx::broken_connection& e) {
    spdlog::error("Database connection lost: {}", e.what());
    return json_response(500, R"({"error":"Internal server error"})");
  } catch (const pqxx::failure& e) {
    spdlog::error("PQXX failure: {}", e.what());
    return json_response(500, R"({"error":"Internal server error"})");
  } catch (const std::exception& e) {
    spdlog::warn("Unknown exception: {}", e.what());
    return json_response(500, R"({"error":"Internal server error"})");
  }
}

#endif
