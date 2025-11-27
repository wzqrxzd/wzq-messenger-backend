#ifndef DELETE_MESSAGE_ROUTE
#define DELETE_MESSAGE_ROUTE

#include "route.hxx"

class DeleteMessageRoute : public WsAccessRoute {
  public:
    explicit DeleteMessageRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
};

#endif
