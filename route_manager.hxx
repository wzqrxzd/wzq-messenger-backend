#ifndef ROUTE_MANAGER
#define ROUTE_MANAGER

#include "auth_service.hxx"
#include "route.hxx"
#include "websocket_controller.hxx"

template <typename T>
concept RouteConcept = requires(T t) {
  { t.setup() } -> std::same_as<void>;
};

template <typename T>
concept WsConcept = requires(T t) {
  { t.isWebSocket() } -> std::same_as<void>;
};

class RouteManager {
  public:
    explicit RouteManager(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db);
    void setupRoutes();
    template <RouteConcept T>
    void addRoute() {
      Route* ptr = nullptr;

      if constexpr(WsConcept<T>) {
        ptr = new T(app, wsController, auth, db);
      } else {
        ptr = new T(app, auth, db);
      }

      routes.push_back(std::move(ptr));
    };
  private:
    crow::App<crow::CORSHandler>& app;
    AuthService& auth;
    Database& db;
    WebsocketController wsController;

    std::vector<Route*> routes;
};

#endif
