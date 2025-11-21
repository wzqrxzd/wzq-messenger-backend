#include "crow/common.h"
#include "database.hxx"
#include "server.hxx"
#include "jwt_utils.hxx"
#include <set>
#include <spdlog/spdlog.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <format>
#include "utils.hxx"


struct WsClient {
    crow::websocket::connection* conn;
    int userId;
    std::set<int> chatIds;
};

std::mutex wsMutex;
std::set<std::shared_ptr<WsClient>> wsClients;

void sendMessageToChat(int chatId, const std::string& message)
{
    std::lock_guard<std::mutex> lock(wsMutex);
    spdlog::info("cahtId {} message {}", chatId, message);
    for (auto& client : wsClients) {
        if (client->chatIds.count(chatId)) {
            client->conn->send_text(message);
        }
    }
}

void Server::webSocketMessageRoute() {
    CROW_ROUTE(app, "/ws")
    .websocket(&this->app)
    .onopen([](crow::websocket::connection& conn) {
    })
    .onclose([](crow::websocket::connection& conn, const std::string& reason, uint16_t code) {
        std::lock_guard<std::mutex> lock(wsMutex);
        for (auto it = wsClients.begin(); it != wsClients.end(); ) {
            if ((*it)->conn == &conn) {
                it = wsClients.erase(it);
            } else {
                ++it;
            }
        }
        spdlog::info("[WebSocket] Closed: {} (code {})", reason, code);
    })
    .onmessage([this](crow::websocket::connection& conn, const std::string& msg, bool) {
        ConnectionGuard DB(dbHandle);
        try {
            auto data = nlohmann::json::parse(msg);
            if (data.contains("token")) {
                std::string token = data["token"];
                std::string username = jwt_utils::getUsernameFromToken(token);
                spdlog::info("{} \n {}", token, username);

                pqxx::work W(DB.get());
                pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
                if (R_user.empty()) {
                    spdlog::warn("[WS] User not found in DB: {}", username);
                    conn.send_text(R"({"error":"user_not_found"})");
                    conn.close("auth failed");
                    return;
                }

                int userId = R_user[0]["id"].as<int>();
                spdlog::info("[WS] userId={}", userId);

                pqxx::result R_chats = W.exec_prepared("get_user_chats", userId);
                std::set<int> chatIds;
                for (auto row : R_chats) {
                    int chatId = row["id"].as<int>();
                    chatIds.insert(chatId);
                    spdlog::info("[WS] chatId loaded: {}", chatId);
                }

                auto client = std::make_shared<WsClient>(WsClient{&conn, userId, chatIds});
                {
                    std::lock_guard<std::mutex> lock(wsMutex);
                    wsClients.insert(client);
                }

                conn.send_text(R"({"status":"ws_auth_ok"})");
            }
        } catch (...) {
            conn.send_text(R"({"error":"ws_auth_failed"})");
            conn.close("auth failed");
        }
    });
}

void Server::registerRoute()
{
  CROW_ROUTE(app, "/register").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
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

    std::string hashedPassword = hashPassword(password);

    ConnectionGuard DB(dbHandle);
    try {
      pqxx::work W(DB.get());
      W.exec_prepared("insert_user", username, hashedPassword);
      W.commit();
      auto token = jwt_utils::generateJWT(username, this->secret);
      return json_response(200, fmt::format(R"({{"status":"registered", "token":"{}"}})", token));
    } catch (const std::exception& e)
    {
      spdlog::warn("error: {}", e.what());
      return json_response(400, R"({"error":"user already exists"})");
    }
  });
}

void Server::loginRoute()
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
      if (!verifyPassword(storedHash, password))
        return json_response(401, R"({"error":"unauthorized"})");

      std::string token = jwt_utils::generateJWT(username, this->secret);
      pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
      int user_id = R_user[0]["id"].as<int>();
      return json_response(200, fmt::format(R"({{"token":"{}","user_id":"{}"}})", token, user_id));
    } catch (const std::exception& e) {
      spdlog::error("error: {}", e.what());
      return json_response(400, R"({"status":"bad_request"})");
    }
  });

}

void Server::protectedRoute()
{
  CROW_ROUTE(app, "/protected").methods(crow::HTTPMethod::GET)([this](const crow::request& req){
    auto authHeader = req.get_header_value("Authorization");
    if (authHeader.empty())
      return json_response(400, R"({"error":"missing_token"})");     

    std::string token = authHeader.substr(7);

    if (!jwt_utils::verifyJWT(token, this->secret))
      return json_response(400, R"({"error":"token expired"})");     

    return json_response(200, R"({"status":"token_valid"})");
  });
}

void Server::createChatRoute()
{
  CROW_ROUTE(app, "/chats").methods(crow::HTTPMethod::POST)([this](const crow::request& req){
    if (!authorize(req))
      return json_response(401, R"({"error":"not valid token"})");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("name"))
      return json_response(400, R"({"error":"invalid_json"})");

    std::string chat_name = body_json["name"].s();

    ConnectionGuard DB(dbHandle);
    try {
      pqxx::work W(DB.get());

      int chat_id = W.exec_prepared("insert_chat", chat_name)[0]["id"].as<int>();
      pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
      int user_id = R_user[0]["id"].as<int>();

      W.exec_prepared("insert_chat_member", chat_id, user_id);
      W.commit();

      nlohmann::json notify = {
          {"type", "new_chat"},
          {"chat_id", chat_id},
          {"chat_name", chat_name}
      };

      {
          std::lock_guard<std::mutex> lock(wsMutex);
          for (auto& client : wsClients) {
              if (client->userId == user_id) {
                  client->chatIds.insert(chat_id);
                  client->conn->send_text(notify.dump());
                  spdlog::info("[WS] Sent new_chat notify to userId={} chatId={}", user_id, chat_id);
              }
          }
      }

      return json_response(200, fmt::format(R"({{"chat_id":"{}"}})", std::to_string(chat_id)));
    } catch (const std::exception& e) {
      spdlog::info("DB error: {}", e.what());
      return json_response(500, R"({"error":"Internal server error"})");
    }
  });

}
void Server::sendMessageRoute()
{
  CROW_ROUTE(app, "/chats/<int>/messages").methods(crow::HTTPMethod::POST)([this](const crow::request& req, int chatId){
    if (!authorize(req))
      return json_response(401, R"({"error":"not valid token"})");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("content"))
      return json_response(400, R"({"error":"invalid_json"})");

    std::string content = body_json["content"].s();


    ConnectionGuard DB(dbHandle);
    pqxx::work W(DB.get());
    pqxx::result R_user = W.exec_prepared("find_user_by_username", username);
    int userId = R_user[0]["id"].as<int>();

    pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

    if (R.empty())
      return json_response(403, R"({"error":"user_not_in_the_chat"})");

    pqxx::result R_msg = W.exec_prepared("insert_message", chatId, userId, content);
    int messageId = R_msg[0]["id"].as<int>();

    W.commit();
    nlohmann::json notify_json = {
        {"type", "new_message"},
        {"chat_id", chatId},
        {"message_id", messageId},
        {"sender_id", userId},
        {"sender_name", username},
        {"content", content}
    };
    sendMessageToChat(chatId, notify_json.dump());
    spdlog::info("messageId = {}", messageId);
    return json_response(200, fmt::format(R"({{"status":"message_sent","message_id":"{}"}})", std::to_string(messageId)));
  });
}

void Server::deleteMessageRoute()
{
  CROW_ROUTE(app, "/chats/<int>/messages/<int>").methods(crow::HTTPMethod::DELETE)([this](const crow::request& req, int chatId, int messageId){
    if (!authorize(req))
      return json_response(401, R"({"error":"not valid token"})");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    ConnectionGuard DB(dbHandle);
    try {
      pqxx::work W(DB.get());

      pqxx::result R_request_user = W.exec_prepared("find_user_by_username", username);
      pqxx::result R_user_message = W.exec_prepared("find_user_by_message", messageId);
      int userId = R_request_user[0]["id"].as<int>();
      int senderId = R_user_message[0]["sender_id"].as<int>();

      spdlog::info("userId = {}, senderId = {}", userId, senderId);

      if (userId != senderId)
        return json_response(401, R"({"error":"sender id != user id"})");

      W.exec_prepared("delete_message", messageId);

      W.commit();

      return json_response(200, fmt::format(R"({{"status":"deleted","message_id":"{}"}})",std::to_string(messageId)));
    } catch (const std::exception& e) {
      spdlog::info("DB error: {}", e.what());
      return json_response(500, R"({"error":"Internal server error"})");
    }
  });


}

void Server::deleteChatRoute()
{
  CROW_ROUTE(app, "/chats/<int>").methods(crow::HTTPMethod::DELETE)([this](const crow::request& req, int chatId){
    if (!authorize(req))
      return json_response(401, "{\"error\":\"not valid token\"}");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    ConnectionGuard DB(dbHandle);
    try {
      pqxx::work W(DB.get());
      pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
      int userId = R_request_userId[0]["id"].as<int>();

      pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

      if (R.empty())
        return json_response(403, R"({"error":"user_not_in_the_chat"})");

      W.exec_prepared("delete_chat_messages", chatId);
      W.exec_prepared("delete_chat_members", chatId);
      W.exec_prepared("delete_chat", chatId);

      W.commit();

      nlohmann::json notify = {
          {"type", "delete_chat"},
          {"chat_id", chatId}
      };

      {
          std::lock_guard<std::mutex> lock(wsMutex);
          for (auto& client : wsClients) {
              if (client->userId == userId) {
                  client->chatIds.erase(chatId);
                  client->conn->send_text(notify.dump());
                  spdlog::info("[WS] Sent delete_chat notify to userId={} chatId={}", userId, chatId);
              }
          }
      }
      return json_response(200, R"({"status":"chat_deleted"})");
    } catch (const std::exception& e) {
        spdlog::info("DB error: {}", e.what());
        return json_response(500, R"({"error":"Internal server error"})");
    }
  });

}

void Server::insertChatMemberRoute()
{
  CROW_ROUTE(app, "/chats/<int>/add_user").methods(crow::HTTPMethod::POST)([this](const crow::request& req, int chatId){
    if (!authorize(req))
      return json_response(401, R"({"error":"not valid token"})");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    auto body_json = crow::json::load(req.body);
    if (!body_json || !body_json.has("user_id"))
      return json_response(400, R"({"error":"invalid_json"})");

    int insertUserId = body_json["user_id"].i();

    ConnectionGuard DB(dbHandle);

    try {
      pqxx::work W(DB.get());
      pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
      int userId = R_request_userId[0]["id"].as<int>();

      pqxx::result R = W.exec_prepared("check_user_in_chat", chatId, userId);

      if (R.empty())
        return json_response(403, R"({"error":"your_user_not_in_the_chat"})");

      W.exec_prepared("insert_chat_member", chatId, insertUserId);
      W.commit();

      return json_response(200, R"({"status":"user added"})");
    } catch (const std::exception& e) {
      spdlog::info("DB error: {}", e.what());
      return json_response(500, R"({"error":"Internal server error"})");
    }

  });

}

void Server::chatsRoute()
{
  CROW_ROUTE(app, "/chats").methods(crow::HTTPMethod::GET)([this](const crow::request& req){
    if (!authorize(req))
      return json_response(401, R"({"error":"not valid token"})");
    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

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

void Server::chatMessagesRoute()
{
  CROW_ROUTE(app, "/chats/<int>/messages").methods(crow::HTTPMethod::GET)([this](const crow::request& req, int chatId){
    if (!authorize(req))
      return json_response(403, R"({"error":"not valid token"})");
    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    ConnectionGuard DB(dbHandle);

    pqxx::work W(DB.get());
    pqxx::result R_request_userId = W.exec_prepared("find_user_by_username", username);
    int userId = R_request_userId[0]["id"].as<int>();

    nlohmann::json res_json = nlohmann::json::array();

    try {
      pqxx::result check = W.exec_prepared("check_user_in_chat", chatId, userId);
      if (check.empty())
        return json_response(403, R"({"error":"user_not_in_chat"})"); 

      pqxx::result R = W.exec_prepared("get_chat_messages", chatId);
      for (auto row : R)
      {
        pqxx::result R = W.exec_prepared("get_username_by_id", userId);
        res_json.push_back({
          {"message_id", row["id"].as<int>()},
          {"sender_id", row["sender_id"].as<int>()},
          {"sender_name", row["sender_name"].as<std::string>()},
          {"content", row["content"].c_str()},
        });
      }

      return json_response(200, res_json);
    } catch (...) {
      spdlog::error("get_chat_messages error");
      return json_response(500, R"({"error":"server_error"})");
    }
  });
}

void Server::userInfoRoute() {
  CROW_ROUTE(app, "/user/<int>").methods(crow::HTTPMethod::GET)([this](const crow::request& req, int userId){
    if (!authorize(req))
      return json_response(403, R"({"error":"not valid token"})");

    std::string token = req.get_header_value("Authorization").substr(7);
    std::string username = jwt_utils::getUsernameFromToken(token);

    ConnectionGuard DB(dbHandle);
    pqxx::work W(DB.get());

    try {
      pqxx::result R = W.exec_prepared("get_username_by_id", userId);
      return json_response(200, fmt::format(R"({{"username":"{}","user_id":"{}"}})", R[0][0].as<std::string>(), userId));
    } catch (...) {
      spdlog::error("get_user_info error");
      return json_response(500, R"({"error":"server_error"})");
    }
  });
}
