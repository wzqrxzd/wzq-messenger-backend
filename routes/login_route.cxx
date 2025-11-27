#include "login_route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

LoginRoute::LoginRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db) : Route(app, auth, db) {}

void LoginRoute::setup()
{
   CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
    auto body = req.body;
    auto body_json = crow::json::load(body);
    if (!body_json)
      return json_response(400, "Invalid JSON");
    if (!body_json.has("username"))
      return json_response(400, "Missing username field");
    if (!body_json.has("password"))
      return json_response(400, "Missing password field");

    std::string username = body_json["username"].s();
    std::string password = body_json["password"].s();

    ConnectionGuard DB(dbHandle);
    try {
      pqxx::work W(DB.get());
      pqxx::result R = W.exec_prepared("find_user", username);

      if(R.size() == 0)
        return json_response(401, R"({"error":"unauthorized"})");

      std::string storedHash = R[0]["password_hash"].c_str();
      if (!auth.verifyPassword(storedHash, password))
        return json_response(401, R"({"error":"unauthorized"})");

      std::string token = auth.generateJWT(username);
      pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
      int user_id = R_user[0]["id"].as<int>();
      return json_response(200, fmt::format(R"({{"token":"{}","user_id":"{}"}})", token, user_id));
    } catch (const std::exception& e) {
      spdlog::error("error: {}", e.what());
      return json_response(400, R"({"status":"bad_request"})");
    }
  });
};
