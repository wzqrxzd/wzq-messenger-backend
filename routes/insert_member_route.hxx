#ifndef INSERT_MEMBER_ROUTE
#define INSERT_MEMBER_ROUTE

#include "route.hxx"
#include "websocket_controller.hxx"
#include "crow.h"

class InsertMemberRoute : public WsAccessRoute
{
  public:
    explicit InsertMemberRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
};

#endif
