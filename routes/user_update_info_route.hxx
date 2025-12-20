#ifndef USER_UPDATE_INFO_ROUTE
#define USER_UPDATE_INFO_ROUTE

#include "route.hxx"
#include "types/UserFields.hxx"
#include "websocket_controller.hxx"
#include "crow.h"

class UserUpdateInfoRoute : public WsAccessRoute
{
  public:
    explicit UserUpdateInfoRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db);
    void setup() override;

  private:
    UserFields parseRequest(const crow::request& req);
    void ensureOwner(const std::string& username, const int& expectUserId);
    void changeUserData(const UserFields& userUpdatedFields, const int& expectUserId);
};

#endif
