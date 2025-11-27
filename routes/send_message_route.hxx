#ifndef SEND_MESSAGE_ROUTE
#define SEND_MESSAGE_ROUTE

#include "route.hxx"
#include "websocket_controller.hxx"
#include "crow.h"

class SendMessageRoute : public WsAccessRoute
{
  public:
    explicit SendMessageRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
};

#endif
