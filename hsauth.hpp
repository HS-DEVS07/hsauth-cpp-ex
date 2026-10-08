#pragma once

/**
 * Official HS DEVS AUTH C++ Client SDK
 * Zero external libraries required on Windows (uses native WinINet).
 * Compatible with C++14, C++17, C++20.
 */

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <functional>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#endif

namespace HSAUTH {

    struct UserData {
        std::string username;
        std::string ip;
        std::string hwid;
        std::string createdate;
        std::string lastlogin;
    };

    struct AppData {
        std::string numUsers;
        std::string numOnlineUsers;
        std::string numKeys;
        std::string version;
    };

    struct ActiveMessage {
        std::string id;
        std::string type;
        std::string title;
        std::string content;
    };

    class api {
    public:
        std::string name;
        std::string ownerid;
        std::string version;
        std::string apiUrl;
        std::string sessionid;
        bool initialized = false;

        UserData user_data;
        AppData app_data;
        ActiveMessage active_message;

        std::string last_response_message;
        bool last_response_success = false;

        std::function<void(const ActiveMessage&)> on_message;

        api(std::string name, std::string ownerid, std::string version, std::string apiUrl = "https://hsauth.mujahid.xyz/api/1.3/")
            : name(name), ownerid(ownerid), version(version), apiUrl(apiUrl) {}

        static std::string get_hwid() {
#ifdef _WIN32
            // Read Windows Cryptography MachineGuid
            HKEY hKey;
            char guid[256] = { 0 };
            DWORD size = sizeof(guid);
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)guid, &size) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    return std::string(guid);
                }
                RegCloseKey(hKey);
            }
            // Fallback ComputerName
            char compName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
            DWORD cSize = sizeof(compName);
            GetComputerNameA(compName, &cSize);
            return std::string("HWID-WIN-") + compName;
#else
            return "HWID-NON-WINDOWS";
#endif
        }

        void init() {
            std::string post_data = "type=init&ver=" + urlEncode(version) +
                "&name=" + urlEncode(name) +
                "&ownerid=" + urlEncode(ownerid);

            std::string resp = makeRequest(post_data);
            last_response_success = parseBool(resp, "success");
            last_response_message = parseString(resp, "message");

            if (last_response_success) {
                sessionid = parseString(resp, "sessionid");
                app_data.version = parseString(resp, "version");
                app_data.numUsers = parseString(resp, "numUsers");
                app_data.numOnlineUsers = parseString(resp, "numOnlineUsers");
                app_data.numKeys = parseString(resp, "numKeys");
                initialized = true;
            }
        }

        void login(std::string username, std::string password) {
            checkInit();
            std::string post_data = "type=login&username=" + urlEncode(username) +
                "&pass=" + urlEncode(password) +
                "&hwid=" + urlEncode(get_hwid()) +
                "&sessionid=" + urlEncode(sessionid) +
                "&name=" + urlEncode(name) +
                "&ownerid=" + urlEncode(ownerid);

            std::string resp = makeRequest(post_data);
            last_response_success = parseBool(resp, "success");
            last_response_message = parseString(resp, "message");

            if (last_response_success) {
                user_data.username = parseString(resp, "username");
                user_data.ip = parseString(resp, "ip");
                user_data.hwid = parseString(resp, "hwid");
                sessionid = parseString(resp, "sessionid");
                handleActiveMessage(resp);
            }
        }

        void registerUser(std::string username, std::string password, std::string key, std::string email = "") {
            checkInit();
            std::string post_data = "type=register&username=" + urlEncode(username) +
                "&pass=" + urlEncode(password) +
                "&key=" + urlEncode(key) +
                "&email=" + urlEncode(email) +
                "&hwid=" + urlEncode(get_hwid()) +
                "&sessionid=" + urlEncode(sessionid) +
                "&name=" + urlEncode(name) +
                "&ownerid=" + urlEncode(ownerid);

            std::string resp = makeRequest(post_data);
            last_response_success = parseBool(resp, "success");
            last_response_message = parseString(resp, "message");

            if (last_response_success) {
                user_data.username = parseString(resp, "username");
                user_data.ip = parseString(resp, "ip");
                user_data.hwid = parseString(resp, "hwid");
                sessionid = parseString(resp, "sessionid");
                handleActiveMessage(resp);
            }
        }

        void regstr(std::string username, std::string password, std::string key, std::string email = "") {
            registerUser(username, password, key, email);
        }

        void license(std::string key) {
            checkInit();
            std::string post_data = "type=license&key=" + urlEncode(key) +
                "&hwid=" + urlEncode(get_hwid()) +
                "&sessionid=" + urlEncode(sessionid) +
                "&name=" + urlEncode(name) +
                "&ownerid=" + urlEncode(ownerid);

            std::string resp = makeRequest(post_data);
            last_response_success = parseBool(resp, "success");
            last_response_message = parseString(resp, "message");

            if (last_response_success) {
                user_data.username = parseString(resp, "username");
                user_data.ip = parseString(resp, "ip");
                user_data.hwid = parseString(resp, "hwid");
                sessionid = parseString(resp, "sessionid");
                handleActiveMessage(resp);
            }
        }

        void check() {
            checkInit();
            std::string post_data = "type=check&sessionid=" + urlEncode(sessionid) +
                "&name=" + urlEncode(name) +
                "&ownerid=" + urlEncode(ownerid);

            std::string resp = makeRequest(post_data);
            last_response_success = parseBool(resp, "success");
            last_response_message = parseString(resp, "message");
            handleActiveMessage(resp);
        }

        std::string var(std::string varid) {
            checkInit();
            std::string post_data = "type=var&varid=" + urlEncode(varid) +
                "&sessionid=" + urlEncode(sessionid) +
                "&name=" + urlEncode(name) +
                "&ownerid=" + urlEncode(ownerid);

            std::string resp = makeRequest(post_data);
            if (parseBool(resp, "success")) {
                std::string msg = parseString(resp, "message");
                return msg.empty() ? parseString(resp, "response") : msg;
            }
            return "";
        }

        std::string getvar(std::string varid) { return var(varid); }

        void log(std::string message) {
            checkInit();
            std::string post_data = "type=log&message=" + urlEncode(message) +
                "&sessionid=" + urlEncode(sessionid) +
                "&name=" + urlEncode(name) +
                "&ownerid=" + urlEncode(ownerid);
            makeRequest(post_data);
        }

        void logout() {
            checkInit();
            std::string post_data = "type=logout&sessionid=" + urlEncode(sessionid) +
                "&name=" + urlEncode(name) +
                "&ownerid=" + urlEncode(ownerid);
            makeRequest(post_data);
            sessionid = "";
        }

    private:
        void checkInit() {
            if (!initialized) {
                std::cerr << "[HS DEVS AUTH ERROR] You must call init() before authenticating." << std::endl;
            }
        }

        void handleActiveMessage(const std::string& json) {
            std::string title = parseString(json, "title");
            if (!title.empty()) {
                active_message.title = title;
                active_message.type = parseString(json, "type");
                active_message.content = parseString(json, "content");
                active_message.id = parseString(json, "id");

                if (on_message) {
                    on_message(active_message);
                } else {
                    std::cout << "\n[LIVE IN-APP BROADCAST] " << active_message.title << ": " << active_message.content << "\n" << std::endl;
                }

                if (active_message.type == "killswitch") {
                    std::cerr << "[!] KILLSWITCH TRIGGERED BY DEVELOPER. EXITING." << std::endl;
#ifdef _WIN32
                    Sleep(2000);
#endif
                    exit(0);
                }
            }
        }

        std::string makeRequest(const std::string& postData) {
#ifdef _WIN32
            HINTERNET hInternet = InternetOpenA("HSAuth-CPP/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
            if (!hInternet) return "";

            URL_COMPONENTSA urlComp = { 0 };
            urlComp.dwStructSize = sizeof(urlComp);
            char hostName[256] = { 0 };
            char urlPath[1024] = { 0 };
            urlComp.lpszHostName = hostName;
            urlComp.dwHostNameLength = sizeof(hostName);
            urlComp.lpszUrlPath = urlPath;
            urlComp.dwUrlPathLength = sizeof(urlPath);

            InternetCrackUrlA(apiUrl.c_str(), (DWORD)apiUrl.length(), 0, &urlComp);

            INTERNET_PORT port = urlComp.nPort ? urlComp.nPort : (urlComp.nScheme == INTERNET_SCHEME_HTTPS ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT);
            DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? (INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD) : INTERNET_FLAG_RELOAD;

            HINTERNET hConnect = InternetConnectA(hInternet, hostName, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
            if (!hConnect) {
                InternetCloseHandle(hInternet);
                return "";
            }

            HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, NULL, NULL, NULL, flags, 0);
            if (!hRequest) {
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return "";
            }

            // Ignore self-signed cert issues if any
            DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

            const char* headers = "Content-Type: application/x-www-form-urlencoded\r\n";
            HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers), (LPVOID)postData.c_str(), (DWORD)postData.length());

            std::string response;
            char buffer[4096];
            DWORD bytesRead = 0;
            while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                response += buffer;
            }

            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return response;
#else
            return "{\"success\":false,\"message\":\"Platform requires curl backend\"}";
#endif
        }

        std::string parseString(const std::string& json, const std::string& key) {
            std::string search = "\"" + key + "\":\"";
            size_t pos = json.find(search);
            if (pos == std::string::npos) return "";
            pos += search.length();
            size_t endPos = json.find("\"", pos);
            if (endPos == std::string::npos) return "";
            return json.substr(pos, endPos - pos);
        }

        bool parseBool(const std::string& json, const std::string& key) {
            std::string search = "\"" + key + "\":";
            size_t pos = json.find(search);
            if (pos == std::string::npos) return false;
            pos += search.length();
            return (json.substr(pos, 4) == "true");
        }

        std::string urlEncode(const std::string& str) {
            std::ostringstream escaped;
            escaped.fill('0');
            escaped << std::hex;
            for (char c : str) {
                if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
                    escaped << c;
                } else {
                    escaped << '%' << (int)(unsigned char)c;
                }
            }
            return escaped.str();
        }
    };
}

// HSAuth alias
namespace HSAuth {
    using api = HSAUTH::api;
}
