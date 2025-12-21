#ifndef SERVER_HXX
#define SERVER_HXX

#include "auth_service.hxx"
#include "crow.h"
#include "database.hxx"
#include "crow/middlewares/cors.h"
#include "error.hxx"
#include "route.hxx"
#include "route_manager.hxx"
#include <fmt/format.h>
#include <pqxx/pqxx>
#include <functional>
#include <spdlog/spdlog.h>
#include <unordered_set>

class Server
{
  public:
    Server();
    void run();
  private:
    void setupRoutes();

    crow::App<crow::CORSHandler> app;
    AuthService auth;
    RouteManager routeManager;
    Database dbHandle;

    const int port{8080};

    const std::string secret;
};

#endif
