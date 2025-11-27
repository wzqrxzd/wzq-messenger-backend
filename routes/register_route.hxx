#ifndef REGISTER_ROUTE_HXX
#define REGISTER_ROUTE_HXX

#include "route.hxx"
#include "crow.h"

class RegisterRoute : public Route
{
  public:
    explicit RegisterRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db);
    void setup() override;
};

#endif
