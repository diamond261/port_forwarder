/*
 * IP转发工具 - C++版本
 * 适用于游戏服务器转发（如MCBE）
 * 支持 UDP 和 TCP 协议
 * 
 * 编译方法:
 * Linux/macOS: g++ -std=c++17 -pthread -o ip_forward ip_forward.cpp
 * Windows: g++ -std=c++17 -o ip_forward.exe ip_forward.cpp -lws2_32
 */

#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstring>
#include <csignal>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
    #define CLOSE_SOCKET closesocket
    #define SOCKET_ERROR_CODE WSAGetLastError()
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define CLOSE_SOCKET close
    #define SOCKET_ERROR_CODE errno
#endif

// ==================== 日志工具 ====================

enum class LogLevel { INFO, WARNING, ERROR_LOG };

class Logger {
public:
    static void log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        const char* level_str;
        switch (level) {
            case LogLevel::INFO: level_str = "INFO"; break;
            case LogLevel::WARNING: level_str = "WARN"; break;
            case LogLevel::ERROR_LOG: level_str = "ERROR"; break;
            default: level_str = "UNKNOWN";
        }
        
        char time_buf[64];
        std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
        
        std::cout << "[" << time_buf << "] [" << level_str << "] " << message << std::endl;
    }
    
    static void info(const std::string& msg) { log(LogLevel::INFO, msg); }
    static void warning(const std::string& msg) { log(LogLevel::WARNING, msg); }
    static void error(const std::string& msg) { log(LogLevel::ERROR_LOG, msg); }

private:
    static std::mutex mutex_;
};

std::mutex Logger::mutex_;

// ==================== 配置管理 ====================

struct Config {
    std::string listen_host = "0.0.0.0";
    int listen_port = 54321;
    std::string target_host = "127.0.0.1";
    int target_port = 19132;
    std::string protocol = "both";  // "udp", "tcp", "both"
    int buffer_size = 65535;
    int udp_timeout = 300;          // UDP客户端超时（秒）
    int tcp_timeout = 60;           // TCP连接超时（秒）
    int max_connections = 100;
    
    bool load(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            Logger::warning("配置文件不存在，使用默认配置并创建新文件");
            save(filename);
            return true;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            // 跳过空行和注释
            if (line.empty() || line[0] == '#' || line[0] == '/') continue;
            
            size_t pos = line.find('=');
            if (pos == std::string::npos) continue;
            
            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 1));
            
            if (key == "listen_host") listen_host = value;
            else if (key == "listen_port") listen_port = std::stoi(value);
            else if (key == "target_host") target_host = value;
            else if (key == "target_port") target_port = std::stoi(value);
            else if (key == "protocol") protocol = value;
            else if (key == "buffer_size") buffer_size = std::stoi(value);
            else if (key == "udp_timeout") udp_timeout = std::stoi(value);
            else if (key == "tcp_timeout") tcp_timeout = std::stoi(value);
            else if (key == "max_connections") max_connections = std::stoi(value);
        }
        
        Logger::info("配置文件已加载: " + filename);
        return true;
    }
    
    void save(const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            Logger::error("无法创建配置文件: " + filename);
            return;
        }
        
        file << "# IP转发工具配置文件\n";
        file << "# 适用于游戏服务器转发（如MCBE）\n\n";
        file << "# 监听地址\n";
        file << "listen_host=" << listen_host << "\n";
        file << "listen_port=" << listen_port << "\n\n";
        file << "# 目标服务器地址\n";
        file << "target_host=" << target_host << "\n";
        file << "target_port=" << target_port << "\n\n";
        file << "# 协议: udp, tcp, both\n";
        file << "protocol=" << protocol << "\n\n";
        file << "# 其他设置\n";
        file << "buffer_size=" << buffer_size << "\n";
        file << "udp_timeout=" << udp_timeout << "\n";
        file << "tcp_timeout=" << tcp_timeout << "\n";
        file << "max_connections=" << max_connections << "\n";
        
        Logger::info("配置文件已保存: " + filename);
    }
    
    void print() {
        std::cout << "\n========== 当前配置 ==========\n";
        std::cout << "监听地址: " << listen_host << ":" << listen_port << "\n";
        std::cout << "目标地址: " << target_host << ":" << target_port << "\n";
        std::cout << "协议: " << protocol << "\n";
        std::cout << "缓冲区大小: " << buffer_size << "\n";
        std::cout << "UDP超时: " << udp_timeout << "秒\n";
        std::cout << "TCP超时: " << tcp_timeout << "秒\n";
        std::cout << "最大连接数: " << max_connections << "\n";
        std::cout << "================================\n\n";
    }

private:
    std::string trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        size_t end = str.find_last_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        return str.substr(start, end - start + 1);
    }
};

// ==================== 网络工具 ====================

class NetworkUtils {
public:
    static bool initNetwork() {
#ifdef _WIN32
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            Logger::error("WSAStartup 失败: " + std::to_string(result));
            return false;
        }
#endif
        return true;
    }
    
    static void cleanupNetwork() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    static bool setNonBlocking(SOCKET sock) {
#ifdef _WIN32
        u_long mode = 1;
        return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
        int flags = fcntl(sock, F_GETFL, 0);
        return fcntl(sock, F_SETFL, flags | O_NONBLOCK) != -1;
#endif
    }
    
    static bool setSocketTimeout(SOCKET sock, int seconds) {
#ifdef _WIN32
        DWORD timeout = seconds * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = seconds;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
        return true;
    }
    
    static std::string addrToString(const sockaddr_in& addr) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
        return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
    }
};

// ==================== UDP 转发器 ====================

class UDPForwarder {
public:
    UDPForwarder(const Config& config) : config_(config), running_(false) {}
    
    ~UDPForwarder() {
        stop();
    }
    
    bool start() {
        running_ = true;
        
        // 创建服务器socket
        server_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (server_socket_ == INVALID_SOCKET) {
            Logger::error("[UDP] 创建socket失败");
            return false;
        }
        
        // 设置socket选项
        int opt = 1;
        setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        
        // 绑定地址
        sockaddr_in listen_addr{};
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_port = htons(config_.listen_port);
        inet_pton(AF_INET, config_.listen_host.c_str(), &listen_addr.sin_addr);
        
        if (bind(server_socket_, (sockaddr*)&listen_addr, sizeof(listen_addr)) == SOCKET_ERROR) {
            Logger::error("[UDP] 绑定地址失败: " + std::to_string(SOCKET_ERROR_CODE));
            CLOSE_SOCKET(server_socket_);
            return false;
        }
        
        // 设置目标地址
        target_addr_.sin_family = AF_INET;
        target_addr_.sin_port = htons(config_.target_port);
        inet_pton(AF_INET, config_.target_host.c_str(), &target_addr_.sin_addr);
        
        Logger::info("[UDP] 转发器已启动: " + config_.listen_host + ":" + 
                     std::to_string(config_.listen_port) + " -> " +
                     config_.target_host + ":" + std::to_string(config_.target_port));
        
        // 启动清理线程
        cleanup_thread_ = std::thread(&UDPForwarder::cleanupClients, this);
        
        // 启动接收线程
        receive_thread_ = std::thread(&UDPForwarder::receiveLoop, this);
        
        return true;
    }
    
    void stop() {
        if (!running_) return;
        
        running_ = false;
        
        if (server_socket_ != INVALID_SOCKET) {
            CLOSE_SOCKET(server_socket_);
            server_socket_ = INVALID_SOCKET;
        }
        
        if (receive_thread_.joinable()) {
            receive_thread_.join();
        }
        
        if (cleanup_thread_.joinable()) {
            cleanup_thread_.join();
        }
        
        // 关闭所有客户端socket
        std::lock_guard<std::mutex> lock(clients_mutex_);
        for (auto& pair : clients_) {
            CLOSE_SOCKET(pair.second.socket);
        }
        clients_.clear();
        
        Logger::info("[UDP] 转发器已停止");
    }
    
    bool isRunning() const { return running_; }

private:
    struct ClientInfo {
        SOCKET socket;
        std::chrono::steady_clock::time_point last_active;
        std::thread response_thread;
    };
    
    // 地址转为字符串作为key
    static std::string makeKey(const sockaddr_in& addr) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
        return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
    }
    
    void receiveLoop() {
        std::vector<char> buffer(config_.buffer_size);
        
        while (running_) {
            sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(client_addr);
            
            int recv_len = recvfrom(server_socket_, buffer.data(), buffer.size(), 0,
                                    (sockaddr*)&client_addr, &addr_len);
            
            if (recv_len <= 0) {
                if (running_) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                continue;
            }
            
            std::string client_key = makeKey(client_addr);
            
            std::lock_guard<std::mutex> lock(clients_mutex_);
            
            // 检查是否是新客户端
            if (clients_.find(client_key) == clients_.end()) {
                // 创建新的目标socket
                SOCKET target_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (target_socket == INVALID_SOCKET) {
                    Logger::error("[UDP] 创建目标socket失败");
                    continue;
                }
                
                // 设置超时
                NetworkUtils::setSocketTimeout(target_socket, 1);
                
                ClientInfo info;
                info.socket = target_socket;
                info.last_active = std::chrono::steady_clock::now();
                
                // 存储客户端地址用于响应
                sockaddr_in stored_client_addr = client_addr;
                
                // 启动响应接收线程
                info.response_thread = std::thread([this, target_socket, stored_client_addr, client_key]() {
                    handleTargetResponse(target_socket, stored_client_addr, client_key);
                });
                info.response_thread.detach();
                
                clients_[client_key] = std::move(info);
                Logger::info("[UDP] 新客户端连接: " + client_key);
            }
            
            // 更新活跃时间
            clients_[client_key].last_active = std::chrono::steady_clock::now();
            
            // 转发数据到目标服务器
            sendto(clients_[client_key].socket, buffer.data(), recv_len, 0,
                   (sockaddr*)&target_addr_, sizeof(target_addr_));
        }
    }
    
    void handleTargetResponse(SOCKET target_socket, sockaddr_in client_addr, std::string client_key) {
        std::vector<char> buffer(config_.buffer_size);
        
        while (running_) {
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                if (clients_.find(client_key) == clients_.end()) {
                    break;
                }
            }
            
            sockaddr_in from_addr{};
            socklen_t addr_len = sizeof(from_addr);
            
            int recv_len = recvfrom(target_socket, buffer.data(), buffer.size(), 0,
                                    (sockaddr*)&from_addr, &addr_len);
            
            if (recv_len <= 0) {
                continue;
            }
            
            // 发送响应给客户端
            sendto(server_socket_, buffer.data(), recv_len, 0,
                   (sockaddr*)&client_addr, sizeof(client_addr));
            
            // 更新活跃时间
            std::lock_guard<std::mutex> lock(clients_mutex_);
            if (clients_.find(client_key) != clients_.end()) {
                clients_[client_key].last_active = std::chrono::steady_clock::now();
            }
        }
    }
    
    void cleanupClients() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            
            auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(clients_mutex_);
            
            std::vector<std::string> expired;
            
            for (auto& pair : clients_) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - pair.second.last_active).count();
                
                if (elapsed > config_.udp_timeout) {
                    expired.push_back(pair.first);
                }
            }
            
            for (const auto& key : expired) {
                CLOSE_SOCKET(clients_[key].socket);
                clients_.erase(key);
                Logger::info("[UDP] 客户端超时断开: " + key);
            }
        }
    }

private:
    Config config_;
    std::atomic<bool> running_;
    SOCKET server_socket_ = INVALID_SOCKET;
    sockaddr_in target_addr_{};
    
    std::map<std::string, ClientInfo> clients_;
    std::mutex clients_mutex_;
    
    std::thread receive_thread_;
    std::thread cleanup_thread_;
};

// ==================== TCP 转发器 ====================

class TCPForwarder {
public:
    TCPForwarder(const Config& config) : config_(config), running_(false) {}
    
    ~TCPForwarder() {
        stop();
    }
    
    bool start() {
        running_ = true;
        
        // 创建服务器socket
        server_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_socket_ == INVALID_SOCKET) {
            Logger::error("[TCP] 创建socket失败");
            return false;
        }
        
        // 设置socket选项
        int opt = 1;
        setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        
        // 绑定地址
        sockaddr_in listen_addr{};
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_port = htons(config_.listen_port);
        inet_pton(AF_INET, config_.listen_host.c_str(), &listen_addr.sin_addr);
        
        if (bind(server_socket_, (sockaddr*)&listen_addr, sizeof(listen_addr)) == SOCKET_ERROR) {
            Logger::error("[TCP] 绑定地址失败: " + std::to_string(SOCKET_ERROR_CODE));
            CLOSE_SOCKET(server_socket_);
            return false;
        }
        
        if (listen(server_socket_, config_.max_connections) == SOCKET_ERROR) {
            Logger::error("[TCP] 监听失败");
            CLOSE_SOCKET(server_socket_);
            return false;
        }
        
        Logger::info("[TCP] 转发器已启动: " + config_.listen_host + ":" + 
                     std::to_string(config_.listen_port) + " -> " +
                     config_.target_host + ":" + std::to_string(config_.target_port));
        
        // 启动接受连接线程
        accept_thread_ = std::thread(&TCPForwarder::acceptLoop, this);
        
        return true;
    }
    
    void stop() {
        if (!running_) return;
        
        running_ = false;
        
        if (server_socket_ != INVALID_SOCKET) {
            CLOSE_SOCKET(server_socket_);
            server_socket_ = INVALID_SOCKET;
        }
        
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
        
        // 关闭所有连接
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& conn : connections_) {
            if (conn.client_socket != INVALID_SOCKET) {
                CLOSE_SOCKET(conn.client_socket);
            }
            if (conn.target_socket != INVALID_SOCKET) {
                CLOSE_SOCKET(conn.target_socket);
            }
        }
        connections_.clear();
        
        Logger::info("[TCP] 转发器已停止");
    }
    
    bool isRunning() const { return running_; }

private:
    struct Connection {
        SOCKET client_socket;
        SOCKET target_socket;
        std::string client_addr_str;
    };
    
    void acceptLoop() {
        while (running_) {
            sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(client_addr);
            
            SOCKET client_socket = accept(server_socket_, (sockaddr*)&client_addr, &addr_len);
            
            if (client_socket == INVALID_SOCKET) {
                if (running_) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                continue;
            }
            
            // 检查连接数限制
            {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                if (connections_.size() >= static_cast<size_t>(config_.max_connections)) {
                    CLOSE_SOCKET(client_socket);
                    Logger::warning("[TCP] 连接数已达上限，拒绝连接");
                    continue;
                }
            }
            
            std::string client_addr_str = NetworkUtils::addrToString(client_addr);
            
            // 在新线程中处理连接
            std::thread([this, client_socket, client_addr_str]() {
                handleConnection(client_socket, client_addr_str);
            }).detach();
        }
    }
    
    void handleConnection(SOCKET client_socket, const std::string& client_addr_str) {
        // 连接目标服务器
        SOCKET target_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (target_socket == INVALID_SOCKET) {
            Logger::error("[TCP] 创建目标socket失败");
            CLOSE_SOCKET(client_socket);
            return;
        }
        
        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(config_.target_port);
        inet_pton(AF_INET, config_.target_host.c_str(), &target_addr.sin_addr);
        
        if (connect(target_socket, (sockaddr*)&target_addr, sizeof(target_addr)) == SOCKET_ERROR) {
            Logger::error("[TCP] 连接目标服务器失败: " + client_addr_str);
            CLOSE_SOCKET(client_socket);
            CLOSE_SOCKET(target_socket);
            return;
        }
        
        // 设置超时
        NetworkUtils::setSocketTimeout(client_socket, config_.tcp_timeout);
        NetworkUtils::setSocketTimeout(target_socket, config_.tcp_timeout);
        
        Connection conn{client_socket, target_socket, client_addr_str};
        
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            connections_.push_back(conn);
        }
        
        Logger::info("[TCP] 新连接建立: " + client_addr_str);
        
        // 双向转发
        std::atomic<bool> connection_active(true);
        
        std::thread forward_thread1([&]() {
            forwardData(client_socket, target_socket, connection_active, "客户端->服务器");
        });
        
        std::thread forward_thread2([&]() {
            forwardData(target_socket, client_socket, connection_active, "服务器->客户端");
        });
        
        forward_thread1.join();
        forward_thread2.join();
        
        // 清理连接
        CLOSE_SOCKET(client_socket);
        CLOSE_SOCKET(target_socket);
        
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            connections_.erase(
                std::remove_if(connections_.begin(), connections_.end(),
                    [client_socket](const Connection& c) { 
                        return c.client_socket == client_socket; 
                    }),
                connections_.end());
        }
        
        Logger::info("[TCP] 连接已关闭: " + client_addr_str);
    }
    
    void forwardData(SOCKET src, SOCKET dst, std::atomic<bool>& active, const std::string& direction) {
        std::vector<char> buffer(config_.buffer_size);
        
        while (running_ && active) {
            int recv_len = recv(src, buffer.data(), buffer.size(), 0);
            
            if (recv_len <= 0) {
                active = false;
                break;
            }
            
            int sent = 0;
            while (sent < recv_len && running_ && active) {
                int result = send(dst, buffer.data() + sent, recv_len - sent, 0);
                if (result <= 0) {
                    active = false;
                    break;
                }
                sent += result;
            }
        }
    }

private:
    Config config_;
    std::atomic<bool> running_;
    SOCKET server_socket_ = INVALID_SOCKET;
    
    std::vector<Connection> connections_;
    std::mutex connections_mutex_;
    
    std::thread accept_thread_;
};

// ==================== 主程序 ====================

std::atomic<bool> g_running(true);

void signalHandler(int signal) {
    std::cout << "\n收到停止信号，正在关闭...\n";
    g_running = false;
}

void printBanner() {
    std::cout << R"(
    ╔══════════════════════════════════════════════╗
    ║          IP 转发工具 v1.0 (C++)               ║
    ║     适用于游戏服务器转发（MCBE等）             ║
    ╚══════════════════════════════════════════════╝
    )" << std::endl;
}

int main(int argc, char* argv[]) {
    printBanner();
    
    // 设置信号处理
    signal(SIGINT, signalHandler);
#ifndef _WIN32
    signal(SIGTERM, signalHandler);
#endif
    
    // 初始化网络
    if (!NetworkUtils::initNetwork()) {
        return 1;
    }
    
    // 加载配置
    std::string config_file = "forward_config.ini";
    if (argc > 1) {
        config_file = argv[1];
    }
    
    Config config;
    config.load(config_file);
    config.print();
    
    // 创建转发器
    std::unique_ptr<UDPForwarder> udp_forwarder;
    std::unique_ptr<TCPForwarder> tcp_forwarder;
    
    if (config.protocol == "udp" || config.protocol == "both") {
        udp_forwarder = std::make_unique<UDPForwarder>(config);
        if (!udp_forwarder->start()) {
            Logger::error("UDP转发器启动失败");
        }
    }
    
    if (config.protocol == "tcp" || config.protocol == "both") {
        tcp_forwarder = std::make_unique<TCPForwarder>(config);
        if (!tcp_forwarder->start()) {
            Logger::error("TCP转发器启动失败");
        }
    }
    
    Logger::info("按 Ctrl+C 停止程序");
    
    // 主循环
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // 停止转发器
    if (udp_forwarder) {
        udp_forwarder->stop();
    }
    if (tcp_forwarder) {
        tcp_forwarder->stop();
    }
    
    // 清理网络
    NetworkUtils::cleanupNetwork();
    
    Logger::info("程序已退出");
    return 0;
}