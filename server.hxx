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

struct ExceptionMiddleware
{
  struct context {};

  void before_handle(crow::request& req, crow::response& res, context& ctx) {}

  void after_handle(crow::request& req, crow::response& res, context& ctx) {}

  void handle_exception(const std::exception& e, crow::response& res)
  {
    res.set_header("Content-Type", "application/json");

    if (auto authException = dynamic_cast<const AuthException*>(&e))
    {
      spdlog::debug("AuthError: {}", e.what());
      res.code = 400;
      res.write(std::format(R"({{"error":"{}"}})", e.what()));
    }
    else if (auto jsonException = dynamic_cast<const JsonException*>(&e))
    {
      spdlog::debug("JsonError: {}", e.what());
      res.code = 400;
      res.write(std::format(R"({{"error":"{}"}})", e.what()));
    }
    else if (auto sqlException = dynamic_cast<const pqxx::sql_error*>(&e))
    {
      spdlog::error("SQL error: {}, Query: {}", e.what(), sqlException->query());
      res.code = 500;
      res.write(R"({"error":"Internal server error"})");
    }
    else if (auto conectionException = dynamic_cast<const pqxx::failure*>(&e))
    {
      spdlog::error("Database connection lost: {}", e.what());
      res.code = 500;
      res.write(R"({"error":"Internal server error"})");
    }
    else if (auto postgresException = dynamic_cast<const pqxx::failure*>(&e))
    {
      spdlog::error("PQXX failure: {}", e.what());
      res.code = 500;
      res.write(R"({"error":"Internal server error"})");
    }
    else
    {
      spdlog::warn("Unknown exception: {}", e.what());
      res.code = 500;
      res.write(R"({"error":"Internal server error"})");
    }

    res.end();
  }
};

class Server
{
  public:
    Server();
    void run();
  private:
    void setupRoutes();

    crow::App<crow::CORSHandler, ExceptionMiddleware> app;
    AuthService auth;
    RouteManager routeManager;
    Database dbHandle;

    const int port{8080};

    const std::string secret;
};

#endif
