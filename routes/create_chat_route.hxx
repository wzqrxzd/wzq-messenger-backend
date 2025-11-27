#ifndef CREATE_CHAT_ROUTE
#define CREATE_CHAT_ROUTE

#include "route.hxx"
#include "websocket_controller.hxx"
#include "crow.h"

class CreateChatRoute : public WsAccessRoute
{
  public:
    explicit CreateChatRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
};

#endif
