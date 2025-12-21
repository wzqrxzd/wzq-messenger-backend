#ifndef LOGIN_ROUTE
#define LOGIN_ROUTE

#include "route.hxx"
#include "crow.h"
#include "types/UserFields.hxx"

class LoginRoute : public Route
{
  public:
    explicit LoginRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db);
    void setup() override;

    UserFields loadUserData(const crow::request& req);
    void ensureUserExist(const std::string& username);
    void verifyPassword(const UserFields& user);
    crow::response buildLoginRouteResponse(const std::string& token, const int& userId);
    int getUserId(const std::string& username);
};

#endif
