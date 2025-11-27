#ifndef AUTH_SERVICE
#define AUTH_SERVICE

#include <string>
#include "crow.h"

class AuthService {
  public:
    AuthService();

    bool verifyPassword(const std::string& hash, const std::string& password);
    std::string hashPassword(const std::string& password);

    bool authorizeRequest(const crow::request& req);
    std::string generateJWT(const std::string& username);
    std::string getUsernameFromToken(const std::string& token);
  private:
    bool verifyJWT(const std::string& token);
    std::string secret;
};

#endif
