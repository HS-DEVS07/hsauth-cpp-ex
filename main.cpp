#include "hsauth.hpp"
#include <iostream>

// Replace with your credentials from https://hsauth.mujahid.xyz/dashboard
HSAUTH::api HSAuthApp(
    "MyApp",
    "your_app_identifier_here",
    "1.0",
    "https://hsauth.mujahid.xyz/api/1.3/"
);

int main() {
    std::cout << "[*] Connecting to HS DEVS AUTH..." << std::endl;
    HSAuthApp.init();

    if (!HSAuthApp.last_response_success) {
        std::cerr << "[!] Init failed: " << HSAuthApp.last_response_message << std::endl;
        return 1;
    }

    std::cout << "[+] Connected! Version: " << HSAuthApp.app_data.version << std::endl;

    // Optional Live In-App Broadcast / Killswitch handler
    HSAuthApp.on_message = [](const HSAUTH::ActiveMessage& msg) {
        std::cout << "\n[BROADCAST RECEIVED]: " << msg.title << " - " << msg.content << std::endl;
        if (msg.type == "killswitch") {
            std::cerr << "[!] Emergency killswitch activated. Exiting." << std::endl;
            exit(0);
        }
    };

    std::cout << "\n[1] Login (Username & Password)" << std::endl;
    std::cout << "[2] Register (Username, Password & License Key)" << std::endl;
    std::cout << "[3] License Key Only" << std::endl;
    std::cout << "\nChoose option: ";

    int choice;
    std::cin >> choice;

    if (choice == 1) {
        std::string u, p;
        std::cout << "Username: "; std::cin >> u;
        std::cout << "Password: "; std::cin >> p;
        HSAuthApp.login(u, p);
    } else if (choice == 2) {
        std::string u, p, k;
        std::cout << "Username: "; std::cin >> u;
        std::cout << "Password: "; std::cin >> p;
        std::cout << "License: "; std::cin >> k;
        HSAuthApp.registerUser(u, p, k);
    } else if (choice == 3) {
        std::string k;
        std::cout << "License Key: "; std::cin >> k;
        HSAuthApp.license(k);
    }

    if (HSAuthApp.last_response_success) {
        std::cout << "\n[+] Authenticated! Welcome, " << HSAuthApp.user_data.username << std::endl;
        std::cout << "[+] HWID: " << HSAuthApp.user_data.hwid << std::endl;

        // Fetch Remote Variable demo
        std::string secret = HSAuthApp.var("secret_key");
        std::cout << "[+] Remote Variable: " << secret << std::endl;
    } else {
        std::cerr << "[!] Authentication failed: " << HSAuthApp.last_response_message << std::endl;
    }

    return 0;
}
