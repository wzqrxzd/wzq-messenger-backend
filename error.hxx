#ifndef ERROR_HXX
#define ERROR_HXX

#include <exception>
#include <string>
#include <unordered_map>

enum class AuthError {
  TokenExpired,
  InvalidCredentials,
  PermissionDenied,
};

static const std::unordered_map<AuthError, std::string> ErrorCodes {
  {AuthError::TokenExpired, "Token expired"},
  {AuthError::InvalidCredentials, "Invalid credentials"},
  {AuthError::PermissionDenied, "Permission denied"}
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
    explicit AuthException(const AuthError& code, const std::string& message = "") : BaseException(ErrorCodes.at(code)), code(code){}
    AuthError getCode() const { return code; }
  private:
    AuthError code;
};

class JsonException : public BaseException {
  public:
    explicit JsonException(const std::string& message) : BaseException(message) {}
};

class DbException : public BaseException {
  public:
    explicit DbException(const std::string& message) : BaseException(message) {}
};



#endif
