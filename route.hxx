#ifndef ROUTE_HXX
#define ROUTE_HXX

#include "crow/middlewares/cors.h"
#include "database.hxx"
#include "auth_service.hxx"
#include "crow.h"
#include "websocket_controller.hxx"

class Route
{
  public:
    explicit Route(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db) : app(app), dbHandle(db), auth(auth) {}
    virtual void setup() = 0;
    virtual ~Route() = default;

  protected:
    crow::App<crow::CORSHandler>& app;
    Database& dbHandle;
    AuthService& auth;
};

class WsAccessRoute : public Route
{
  public:
    explicit WsAccessRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : Route(app, auth, db), wsController(ws){}
    void isWebSocket(){};
  protected:
    WebsocketController& wsController;
};

#endif
