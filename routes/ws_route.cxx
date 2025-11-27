#include "ws_route.hxx"
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

WSRoute::WSRoute(crow::App<crow::CORSHandler>& app, WebsocketController& ws, AuthService& auth, Database& db) : WsAccessRoute(app, ws, auth, db) {}

void WSRoute::setup()
{
   CROW_ROUTE(app, "/ws")
    .websocket(&this->app)
    .onopen([](crow::websocket::connection& conn) {
    })
    .onclose([this](crow::websocket::connection& conn, const std::string& reason, uint16_t code) {
        std::lock_guard<std::mutex> lock(wsController.mtx);
        for (auto it = wsController.wsClients.begin(); it != wsController.wsClients.end(); ) {
            if ((*it)->conn == &conn) {
                it = wsController.wsClients.erase(it);
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
                std::string username = auth.getUsernameFromToken(token);
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

                auto client = std::make_shared<WebsocketController::WsClient>(WebsocketController::WsClient{&conn, userId, chatIds});
                {
                    std::lock_guard<std::mutex> lock(wsController.mtx);
                    wsController.wsClients.insert(client);
                }

                conn.send_text(R"({"status":"ws_auth_ok"})");
            }
        } catch (...) {
            conn.send_text(R"({"error":"ws_auth_failed"})");
            conn.close("auth failed");
        }
    });

}
