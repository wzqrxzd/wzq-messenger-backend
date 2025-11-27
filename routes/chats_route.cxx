#include "routes/chats_route.hxx"
#include "route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

ChatsRoute::ChatsRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void ChatsRoute::setup()
{
  CROW_ROUTE(app, "/chats").methods(crow::HTTPMethod::GET)([this](const crow::request& req){
    if (!auth.authorizeRequest(req))
      return json_response(401, R"({"error":"not valid token"})");
    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = auth.getUsernameFromToken(token);

    ConnectionGuard DB(dbHandle);

    pqxx::work W(DB.get());
    pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
    int userId = R_request_userId[0]["id"].as<int>();

    nlohmann::json res_json = nlohmann::json::array();

    try {
      pqxx::result R = W.exec_prepared("get_user_chats", userId);

      for (auto row : R)
      {
        res_json.push_back({
          {"chat_id", row["id"].as<int>()},
          {"chat_name", row["name"].c_str()}
        });
      }
    } catch (...) {
      spdlog::error("get_user_chats error");
      return json_response(500, R"({"error":"server_error"})");
    }

    return json_response(200, res_json);
  });
}
