#include "jwt_utils.hxx"
#include "jwt-cpp/jwt.h"

std::string jwt_utils::generateJWT(const std::string &username, const std::string &secret)
{
  auto token = jwt::create()
                .set_issuer("wzq_server")
                .set_type("JWT")
                .set_payload_claim("user", jwt::claim(username))
                .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes(60))
                .sign(jwt::algorithm::hs256{secret});
  return token;
}

bool jwt_utils::verifyJWT(const std::string &token, const std::string &secret)
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

std::string jwt_utils::getUsernameFromToken(const std::string &token)
{
  auto decoded = jwt::decode(token);
  return decoded.get_payload_claim("user").as_string();
}
