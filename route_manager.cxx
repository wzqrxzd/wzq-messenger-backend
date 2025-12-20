#include "route_manager.hxx"

RouteManager::RouteManager(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db) : app(app), auth(auth), db(db), wsController() {}

void RouteManager::setupRoutes()
{
  for (const auto& route : routes)
  {
    route->setup();
  }
}

RouteManager::~RouteManager() noexcept
{
  for (const auto& route : routes)
  {
    delete route;
  }
}
