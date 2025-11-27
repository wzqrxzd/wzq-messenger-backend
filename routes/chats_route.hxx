#ifndef CHAT_ROUTE
#define CHAT_ROUTE

#include "route.hxx"
#include "websocket_controller.hxx"
#include "crow.h"

class ChatsRoute : public WsAccessRoute
{
  public:
    explicit ChatsRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
};

#endif
