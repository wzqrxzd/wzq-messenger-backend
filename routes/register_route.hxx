#ifndef REGISTER_ROUTE_HXX
#define REGISTER_ROUTE_HXX

#include "crow/http_response.h"
#include "route.hxx"
#include "crow.h"
#include "types/UserFields.hxx"

class RegisterRoute : public Route
{
  public:
    explicit RegisterRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db);
    void setup() override;
  private:
    UserFields loadUserData(const crow::request& req);
    void insertUserToDB(const UserFields& user);
    void ensureUserNotExist(const std::string& username);
    crow::response buildRegisterRouteResponse(const std::string& token);
};

#endif
