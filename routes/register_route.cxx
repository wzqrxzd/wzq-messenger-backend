#include "register_route.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

RegisterRoute::RegisterRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db) : Route(app, auth, db) {}

void RegisterRoute::setup()
{
  CROW_ROUTE(app, "/register").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
    auto body = req.body;

    auto body_json = crow::json::load(body);
    if (!body_json)
      return json_response(400, "Invalid JSON");
    if (!body_json.has("name"))
      return json_response(400, "Missing name field");
    if (!body_json.has("username"))
      return json_response(400, "Missing username field");
    if (!body_json.has("password"))
      return json_response(400, "Missing password field");

    std::string name = body_json["name"].s();
    std::string username = body_json["username"].s();
    std::string password = body_json["password"].s();
    std::string description = "";

    std::string hashedPassword = auth.hashPassword(password);

    ConnectionGuard DB(dbHandle);
    try {
      pqxx::work W(DB.get());
      W.exec_prepared("insert_user", username, hashedPassword, name, description);
      W.commit();
      auto token = auth.generateJWT(username);
      return json_response(200, fmt::format(R"({{"status":"registered", "token":"{}"}})", token));
    } catch (const std::exception& e)
    {
      spdlog::warn("error: {}", e.what());
      return json_response(400, R"({"error":"user already exists"})");
    }
  });
}
