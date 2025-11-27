#ifndef LOGIN_ROUTE
#define LOGIN_ROUTE

#include "route.hxx"
#include "crow.h"

class LoginRoute : public Route
{
  public:
    explicit LoginRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db);
    void setup() override;
};

#endif
