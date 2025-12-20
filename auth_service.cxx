#include "auth_service.hxx"
#include <sodium.h>
#include "env_utils.hxx"
#include "jwt-cpp/jwt.h"
#include "utils.hxx"
#include <argon2.h>
#include <spdlog/spdlog.h>

AuthService::AuthService() : secret(env_utils::getEnvVar("JWT_SECRET")) {}

std::string AuthService::hashPassword(const std::string& password)
{
  char hash[128];
  uint8_t salt[16];
  randombytes_buf(salt, sizeof(salt));
  argon2i_hash_encoded(
        2,              // t_cost
        1 << 16,        // m_cost (64 MB)
        1,              // parallelism
        password.c_str(),
        password.size(),
        salt,
        sizeof(salt),
        32,             // hashlen
        hash,
        sizeof(hash)
  );
  return std::string(hash);
}

bool AuthService::verifyPassword(const std::string& hash, const std::string& password)
{
  return argon2i_verify(hash.c_str(), password.c_str(), password.size()) == ARGON2_OK;
}

bool AuthService::authorizeRequest(const crow::request& req)
{
  auto authHeader = req.get_header_value("Authorization");
  if (authHeader.empty())
    return false;

  std::string token = authHeader.substr(7);
  spdlog::debug("{}", token);

  if (!verifyJWT(token))
    return false;

  return true;

}

bool AuthService::verifyJWT(const std::string& token)
{
  try {
    auto decoded = jwt::decode(token);
    jwt::verify()
      .allow_algorithm(jwt::algorithm::hs256(secret))
      .with_issuer("wzq_server")
      .verify(decoded);
    return true;
  } catch (...) {
    return false;
  }
}

std::string AuthService::generateJWT(const std::string& username)
{
  auto token = jwt::create()
                .set_issuer("wzq_server")
                .set_type("JWT")
                .set_payload_claim("user", jwt::claim(username))
                .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes(60))
                .sign(jwt::algorithm::hs256{secret});
  return token;
}


std::string AuthService::getUsernameFromToken(const std::string& token)
{
  auto decoded = jwt::decode(token);
  return decoded.get_payload_claim("user").as_string();
}


std::string AuthService::authorize(const crow::request& req)
{
  if (!authorizeRequest(req))
    throw AuthException(AuthError::TokenExpired);

  std::string token = getTokenFromRequest(req);
  std::string username = getUsernameFromToken(token);

  return username;
}
