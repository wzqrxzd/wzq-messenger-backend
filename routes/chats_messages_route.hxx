#ifndef CHAT_MESSAGES_ROUTE
#define CHAT_MESSAGES_ROUTE

#include "route.hxx"
#include "websocket_controller.hxx"
#include "crow.h"

class ChatsMessagesRoute : public WsAccessRoute
{
  public:
    explicit ChatsMessagesRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
};

#endif
