#include "crow.h"
#include <spdlog/spdlog.h>

int main() {
    spdlog::info("Server starting...");
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([](){
        spdlog::info("Request received");
        return "Hello Crow + spdlog!";
    });

    app.port(8080).multithreaded().run();
}

