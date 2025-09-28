#ifndef JWT_HANDLER_HXX
#define JWT_HANDLER_HXX

#include <string>

namespace jwt_utils {
  std::string generateJWT(const std::string& username, const std::string& secret);
  bool verifyJWT(const std::string& token, const std::string& secret);
  std::string getUsernameFromToken(const std::string& token);
}

#endif
