#ifndef DELETE_CHAT_ROUTE
#define DELETE_CHAT_ROUTE

#include "route.hxx"

class DeleteChatRoute : public WsAccessRoute {
  public:
    explicit DeleteChatRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
};

#endif
