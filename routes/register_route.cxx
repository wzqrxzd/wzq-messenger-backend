#include "register_route.hxx"
#include "error.hxx"
#include "utils.hxx"
#include <spdlog/spdlog.h>
#include <fmt/format.h>

RegisterRoute::RegisterRoute(crow::App<crow::CORSHandler>& app, AuthService& auth, Database& db) : Route(app, auth, db) {}

void RegisterRoute::setup()
{
  CROW_ROUTE(app, "/register").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
    return trySafe([&](){
    auto body_json = crow::json::load(req.body);

    std::string name = getJsonField<std::string>(body_json, "name");
    std::string username = getJsonField<std::string>(body_json, "username");
    std::string password = getJsonField<std::string>(body_json, "password");
    std::string description = "";

    std::string hashedPassword = auth.hashPassword(password);

    ConnectionGuard DB(dbHandle);

    pqxx::work W(DB.get());

    W.exec_prepared("insert_user", username, hashedPassword, name, description);
    W.commit();

    auto token = auth.generateJWT(username);

    return json_response(200, fmt::format(R"({{"status":"registered", "token":"{}"}})", token));
  });
  });
}
