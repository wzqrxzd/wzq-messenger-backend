#ifndef WSROUTE_HXX
#define WSROUTE_HXX

#include "route.hxx"

class WSRoute : public WsAccessRoute
{
  public:
    explicit WSRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;
};

#endif
