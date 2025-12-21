#ifndef ERROR_HXX
#define ERROR_HXX

#include "crow.h"
#include <exception>
#include <fmt/format.h>
#include <string>
#include <unordered_map>

template <typename>
inline constexpr bool always_false = false;

enum class AuthError {
  TokenExpired,
  InvalidCredentials,
  PermissionDenied,
  UserAlreadyExist
};

static const std::unordered_map<AuthError, std::string> ErrorCodes {
  {AuthError::TokenExpired, "Token expired"},
  {AuthError::InvalidCredentials, "Invalid credentials"},
  {AuthError::PermissionDenied, "Permission denied"},
  {AuthError::UserAlreadyExist, "User already exist."}
};

class BaseException : public std::exception {
  public:
    explicit BaseException(std::string message) : message(std::move(message)) {}

    const char* what() const noexcept override {
      return message.c_str();
    }

  protected:
    std::string message;
};

class AuthException : public BaseException {
  public:
    explicit AuthException(const AuthError& code, const std::string& message = "") : BaseException(ErrorCodes.at(code) + fmt::format(" ({})", message)), code(code){}
    AuthError getCode() const { return code; }
  private:
    AuthError code;
};

class JsonException : public BaseException {
  public:
    explicit JsonException(const std::string& message) : BaseException(message) {}
};

template <typename T>
T getJsonField(const crow::json::rvalue& body_json, const std::string& field)
{
  if (!body_json)
    throw JsonException("Malformed json");
  if (!body_json.has(field))
  {
    throw JsonException(fmt::format("Missing field \"{}\"", field));
  }

  try {
    if constexpr (std::is_same_v<T, std::string>) {
      return body_json[field].s();
    } else if constexpr (std::is_same_v<T, int>) {
      return body_json[field].i();
    } else if constexpr (std::is_same_v<T, double>) {
      return body_json[field].d();
    } else if constexpr (std::is_same_v<T, bool>) {
      return body_json[field].b();
    } else {
      static_assert(always_false<T>, "Unsupported type for getJsonField");
    }
  } catch (...) {
    throw std::runtime_error(std::format("Field \"{}\" has wrong type", field));
  }
}

template <typename T>
std::optional<T> getOptionalJsonField(const crow::json::rvalue& body_json, const std::string& field)
{
  if (!body_json)
    throw JsonException("Malformed json");
  if (!body_json.has(field))
    return std::nullopt;
  
  try {
    if constexpr (std::is_same_v<T, std::string>) {
      return body_json[field].s();
    } else if constexpr (std::is_same_v<T, int>) {
      return body_json[field].i();
    } else if constexpr (std::is_same_v<T, double>) {
      return body_json[field].d();
    } else if constexpr (std::is_same_v<T, bool>) {
      return body_json[field].b();
    } else {
      static_assert(always_false<T>, "Unsupported type for getJsonField");
    }
  } catch (...) {
    throw std::runtime_error(std::format("Field \"{}\" has wrong type", field));
  }
}

#endif
