#ifndef USER_INFO_ROUTE
#define USER_INFO_ROUTE

#include "route.hxx"
#include "websocket_controller.hxx"
#include "crow.h"

class UserInfoRoute : public WsAccessRoute
{
  public:
    explicit UserInfoRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
};

#endif
