/*
 * IP Forward - Game Server Proxy
 * Version: 1.3
 *
 * Features:
 *   - Multiple forward rules support
 *   - Multi-player support per forward
 *   - UDP/TCP forwarding
 *   - Dynamic DNS resolution (hourly refresh)
 *   - Existing sessions not disconnected on IP change
 *   - Daemon mode
 *   - File logging
 */

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <list>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <cstring>
#include <csignal>
#include <memory>
#include <iomanip>
#include <condition_variable>
#include <queue>
#include <functional>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#define VERSION "1.3"

// ==================== Log Level ====================
enum LogLevel
{
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
};

// ==================== Global Variables ====================
std::atomic<bool> g_running(true);
std::atomic<uint64_t> g_total_packets_in(0);
std::atomic<uint64_t> g_total_packets_out(0);
std::atomic<uint64_t> g_total_bytes_in(0);
std::atomic<uint64_t> g_total_bytes_out(0);
std::string g_working_dir;
std::string g_exe_path;

// ==================== Get Absolute Path ====================
std::string get_absolute_path(const std::string &path)
{
    if (path.empty() || path[0] == '/')
        return path;
    if (!g_working_dir.empty())
        return g_working_dir + "/" + path;
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)))
        return std::string(cwd) + "/" + path;
    return path;
}

// ==================== JSON Parser ====================
class JsonValue
{
public:
    enum Type
    {
        NUL,
        BOOL,
        NUMBER,
        STRING,
        ARRAY,
        OBJECT
    };
    Type type = NUL;
    bool bool_val = false;
    double num_val = 0;
    std::string str_val;
    std::vector<JsonValue> arr_val;
    std::map<std::string, JsonValue> obj_val;

    JsonValue() : type(NUL) {}
    JsonValue(bool v) : type(BOOL), bool_val(v) {}
    JsonValue(double v) : type(NUMBER), num_val(v) {}
    JsonValue(int v) : type(NUMBER), num_val(v) {}
    JsonValue(const std::string &v) : type(STRING), str_val(v) {}
    JsonValue(const char *v) : type(STRING), str_val(v) {}

    bool as_bool(bool def = false) const { return type == BOOL ? bool_val : def; }
    int as_int(int def = 0) const { return type == NUMBER ? (int)num_val : def; }
    std::string as_string(const std::string &def = "") const { return type == STRING ? str_val : def; }

    const JsonValue &operator[](const std::string &key) const
    {
        static JsonValue null_val;
        if (type != OBJECT)
            return null_val;
        auto it = obj_val.find(key);
        return it != obj_val.end() ? it->second : null_val;
    }

    const JsonValue &operator[](size_t idx) const
    {
        static JsonValue null_val;
        if (type != ARRAY || idx >= arr_val.size())
            return null_val;
        return arr_val[idx];
    }

    size_t size() const
    {
        if (type == ARRAY)
            return arr_val.size();
        if (type == OBJECT)
            return obj_val.size();
        return 0;
    }

    bool has(const std::string &key) const
    {
        return type == OBJECT && obj_val.find(key) != obj_val.end();
    }

    bool is_array() const { return type == ARRAY; }
    bool is_object() const { return type == OBJECT; }
};

class JsonParser
{
public:
    static JsonValue parse(const std::string &json)
    {
        size_t pos = 0;
        return parse_value(json, pos);
    }

    static JsonValue parse_file(const std::string &filename)
    {
        std::ifstream file(filename);
        if (!file.is_open())
            throw std::runtime_error("Cannot open: " + filename);
        std::stringstream ss;
        ss << file.rdbuf();
        return parse(ss.str());
    }

private:
    static void skip_ws(const std::string &s, size_t &p)
    {
        while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' || s[p] == '\r'))
            p++;
    }

    static JsonValue parse_value(const std::string &s, size_t &p)
    {
        skip_ws(s, p);
        if (p >= s.size())
            return JsonValue();
        char c = s[p];
        if (c == '{')
            return parse_object(s, p);
        if (c == '[')
            return parse_array(s, p);
        if (c == '"')
            return parse_string(s, p);
        if (c == 't' || c == 'f')
            return parse_bool(s, p);
        if (c == 'n')
        {
            p += 4;
            return JsonValue();
        }
        if (c == '-' || (c >= '0' && c <= '9'))
            return parse_number(s, p);
        return JsonValue();
    }

    static JsonValue parse_object(const std::string &s, size_t &p)
    {
        JsonValue obj;
        obj.type = JsonValue::OBJECT;
        p++;
        skip_ws(s, p);
        if (p < s.size() && s[p] == '}')
        {
            p++;
            return obj;
        }
        while (p < s.size())
        {
            skip_ws(s, p);
            if (s[p] != '"')
                break;
            std::string key = parse_string(s, p).str_val;
            skip_ws(s, p);
            if (p >= s.size() || s[p] != ':')
                break;
            p++;
            obj.obj_val[key] = parse_value(s, p);
            skip_ws(s, p);
            if (p >= s.size())
                break;
            if (s[p] == '}')
            {
                p++;
                break;
            }
            if (s[p] == ',')
            {
                p++;
                continue;
            }
            break;
        }
        return obj;
    }

    static JsonValue parse_array(const std::string &s, size_t &p)
    {
        JsonValue arr;
        arr.type = JsonValue::ARRAY;
        p++;
        skip_ws(s, p);
        if (p < s.size() && s[p] == ']')
        {
            p++;
            return arr;
        }
        while (p < s.size())
        {
            arr.arr_val.push_back(parse_value(s, p));
            skip_ws(s, p);
            if (p >= s.size())
                break;
            if (s[p] == ']')
            {
                p++;
                break;
            }
            if (s[p] == ',')
            {
                p++;
                continue;
            }
            break;
        }
        return arr;
    }

    static JsonValue parse_string(const std::string &s, size_t &p)
    {
        p++;
        std::string r;
        while (p < s.size() && s[p] != '"')
        {
            if (s[p] == '\\' && p + 1 < s.size())
            {
                p++;
                switch (s[p])
                {
                case 'n':
                    r += '\n';
                    break;
                case 't':
                    r += '\t';
                    break;
                case 'r':
                    r += '\r';
                    break;
                default:
                    r += s[p];
                    break;
                }
            }
            else
                r += s[p];
            p++;
        }
        if (p < s.size())
            p++;
        return JsonValue(r);
    }

    static JsonValue parse_number(const std::string &s, size_t &p)
    {
        size_t start = p;
        if (s[p] == '-')
            p++;
        while (p < s.size() && s[p] >= '0' && s[p] <= '9')
            p++;
        if (p < s.size() && s[p] == '.')
        {
            p++;
            while (p < s.size() && s[p] >= '0' && s[p] <= '9')
                p++;
        }
        return JsonValue(std::stod(s.substr(start, p - start)));
    }

    static JsonValue parse_bool(const std::string &s, size_t &p)
    {
        if (s.substr(p, 4) == "true")
        {
            p += 4;
            return JsonValue(true);
        }
        if (s.substr(p, 5) == "false")
        {
            p += 5;
            return JsonValue(false);
        }
        return JsonValue();
    }
};

// ==================== Forward Rule ====================
struct ForwardRule
{
    std::string name;
    std::string listen_host = "0.0.0.0";
    int listen_port = 54321;
    std::string target_host = "127.0.0.1";
    int target_port = 19132;

    std::atomic<int> sessions{0};
    std::atomic<uint64_t> bytes_in{0};
    std::atomic<uint64_t> bytes_out{0};
    std::atomic<uint64_t> packets_in{0};
    std::atomic<uint64_t> packets_out{0};

    ForwardRule() = default;
    ForwardRule(const ForwardRule &o)
        : name(o.name), listen_host(o.listen_host), listen_port(o.listen_port),
          target_host(o.target_host), target_port(o.target_port)
    {
        sessions = o.sessions.load();
        bytes_in = o.bytes_in.load();
        bytes_out = o.bytes_out.load();
        packets_in = o.packets_in.load();
        packets_out = o.packets_out.load();
    }
};

// ==================== Configuration ====================
class Config
{
public:
    // Forward rules
    std::vector<ForwardRule> forwards;

    // Protocol options
    bool enable_tcp = false;
    bool enable_udp = true;
    int buffer_size = 65535;
    int udp_timeout = 120;
    int dns_refresh_interval = 3600;
    int max_sessions = 100;

    // Logging options (all optional with defaults)
    std::string log_level = "INFO";
    std::string log_file = "forward.log";
    bool log_to_file = true;
    bool log_to_console = true;

    // Daemon options (all optional with defaults)
    bool daemon_mode = false;
    std::string pid_file = "mcbe_forward.pid";
    std::string work_dir = "";

    // Computed paths
    std::string abs_log_file;
    std::string abs_pid_file;
    std::string abs_config_file;

    LogLevel get_log_level() const
    {
        if (log_level == "DEBUG")
            return LOG_DEBUG;
        if (log_level == "WARN")
            return LOG_WARN;
        if (log_level == "ERROR")
            return LOG_ERROR;
        return LOG_INFO;
    }

    bool load(const std::string &filename)
    {
        try
        {
            abs_config_file = get_absolute_path(filename);
            JsonValue json = JsonParser::parse_file(filename);

            // Parse forwards array
            if (json.has("forwards") && json["forwards"].is_array())
            {
                const auto &fwds = json["forwards"];
                for (size_t i = 0; i < fwds.size(); i++)
                {
                    const auto &f = fwds[i];
                    ForwardRule rule;
                    rule.name = f["name"].as_string("Forward" + std::to_string(i + 1));
                    rule.listen_host = f["listen_host"].as_string("0.0.0.0");
                    rule.listen_port = f["listen_port"].as_int(54321 + i);
                    rule.target_host = f["target_host"].as_string("127.0.0.1");
                    rule.target_port = f["target_port"].as_int(19132);
                    forwards.push_back(rule);
                }
            }

            // Default forward if none defined
            if (forwards.empty())
            {
                ForwardRule rule;
                rule.name = "Default";
                rule.listen_host = json["listen_host"].as_string("0.0.0.0");
                rule.listen_port = json["listen_port"].as_int(54321);
                rule.target_host = json["target_host"].as_string("127.0.0.1");
                rule.target_port = json["target_port"].as_int(19132);
                forwards.push_back(rule);
            }

            // Protocol options
            enable_tcp = json["enable_tcp"].as_bool(false);
            enable_udp = json["enable_udp"].as_bool(true);
            buffer_size = json["buffer_size"].as_int(65535);
            udp_timeout = json["udp_timeout"].as_int(120);
            dns_refresh_interval = json["dns_refresh_interval"].as_int(3600);
            max_sessions = json["max_sessions"].as_int(100);

            // Logging options (optional with defaults)
            log_level = json["log_level"].as_string("INFO");
            log_file = json["log_file"].as_string("forward.log");
            log_to_file = json["log_to_file"].as_bool(true);
            log_to_console = json["log_to_console"].as_bool(true);

            // Daemon options (optional with defaults)
            daemon_mode = json["daemon_mode"].as_bool(false);
            pid_file = json["pid_file"].as_string("mcbe_forward.pid");
            work_dir = json["work_dir"].as_string("");

            // Compute absolute paths
            abs_log_file = get_absolute_path(log_file);
            abs_pid_file = get_absolute_path(pid_file);

            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] Config parse failed: " << e.what() << std::endl;
            return false;
        }
    }

    void create_default(const std::string &filename)
    {
        std::ofstream file(filename);
        file << R"({
    "forwards": [
        {
            "name": "Server1",
            "listen_host": "0.0.0.0",
            "listen_port": 54321,
            "target_host": "127.0.0.1",
            "target_port": 19132
        },
        {
            "name": "Server2",
            "listen_host": "0.0.0.0",
            "listen_port": 54322,
            "target_host": "127.0.0.1",
            "target_port": 19132
        }
    ],
    "enable_tcp": false,
    "enable_udp": true,
    "buffer_size": 65535,
    "udp_timeout": 120,
    "dns_refresh_interval": 3600,
    "max_sessions": 100,
    "log_level": "INFO",
    "log_file": "forward.log",
    "log_to_file": true,
    "log_to_console": true,
    "daemon_mode": false,
    "pid_file": "mcbe_forward.pid",
    "work_dir": ""
})";
        file.close();
    }

    void print() const
    {
        std::cout << "\n";
        std::cout << "+======================================================+\n";
        std::cout << "|                    CONFIGURATION                     |\n";
        std::cout << "+======================================================+\n";
        std::cout << "| Protocol:     UDP=" << (enable_udp ? "ON" : "OFF");
        std::cout << "  TCP=" << (enable_tcp ? "ON" : "OFF") << "\n";
        std::cout << "| Buffer:       " << buffer_size << " bytes\n";
        std::cout << "| UDP Timeout:  " << udp_timeout << " seconds\n";
        std::cout << "| DNS Refresh:  " << dns_refresh_interval << " seconds\n";
        std::cout << "| Max Sessions: " << max_sessions << " per forward\n";
        std::cout << "+------------------------------------------------------+\n";
        std::cout << "| Log Level:    " << log_level << "\n";
        std::cout << "| Log File:     " << (log_to_file ? abs_log_file : "(disabled)") << "\n";
        std::cout << "| Log Console:  " << (log_to_console ? "ON" : "OFF") << "\n";
        std::cout << "| Daemon Mode:  " << (daemon_mode ? "ON" : "OFF") << "\n";
        std::cout << "| PID File:     " << abs_pid_file << "\n";
        if (!work_dir.empty())
        {
            std::cout << "| Work Dir:     " << work_dir << "\n";
        }
        std::cout << "+------------------------------------------------------+\n";
        std::cout << "|                   FORWARD RULES (" << forwards.size() << ")                   |\n";
        std::cout << "+------------------------------------------------------+\n";

        for (size_t i = 0; i < forwards.size(); i++)
        {
            const auto &f = forwards[i];
            std::cout << "| [" << (i + 1) << "] " << f.name << "\n";
            std::cout << "|     " << f.listen_host << ":" << f.listen_port
                      << " -> " << f.target_host << ":" << f.target_port << "\n";
        }

        std::cout << "+======================================================+\n";
    }
};

Config g_config;

// ==================== Logger ====================
class Logger
{
public:
    static Logger &instance()
    {
        static Logger inst;
        return inst;
    }

    void init(const std::string &filename, bool to_file, bool to_console, LogLevel level)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        level_ = level;
        to_file_ = to_file;
        to_console_ = to_console;
        filename_ = filename;

        if (to_file_ && !filename_.empty())
        {
            file_.open(filename_, std::ios::app);
            if (!file_.is_open())
            {
                if (to_console_)
                    std::cerr << "[WARN] Cannot open log: " << filename_ << std::endl;
                to_file_ = false;
            }
        }
    }

    void reopen()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open())
            file_.close();
        if (to_file_ && !filename_.empty())
            file_.open(filename_, std::ios::app);
    }

    void close()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open())
            file_.close();
    }

    void log(LogLevel level, const std::string &msg)
    {
        if (level < level_)
            return;

        std::string ts = timestamp();
        const char *prefix[] = {"[DEBUG]", "[INFO] ", "[WARN] ", "[ERROR]"};

        std::lock_guard<std::mutex> lock(mutex_);

        std::stringstream ss;
        ss << ts << " " << prefix[level] << " " << msg;
        std::string line = ss.str();

        if (to_console_)
            std::cout << line << std::endl;
        if (to_file_ && file_.is_open())
        {
            file_ << line << std::endl;
            file_.flush();
        }
    }

    static void debug(const std::string &msg) { instance().log(LOG_DEBUG, msg); }
    static void info(const std::string &msg) { instance().log(LOG_INFO, msg); }
    static void warn(const std::string &msg) { instance().log(LOG_WARN, msg); }
    static void error(const std::string &msg) { instance().log(LOG_ERROR, msg); }

private:
    Logger() : level_(LOG_INFO), to_file_(false), to_console_(true) {}
    ~Logger() { close(); }

    std::string timestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&time));
        std::stringstream ss;
        ss << buf << "." << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    std::mutex mutex_;
    std::ofstream file_;
    std::string filename_;
    LogLevel level_;
    bool to_file_;
    bool to_console_;
};

// ==================== DNS Resolver ====================
class DnsResolver
{
public:
    DnsResolver() : running_(false), is_domain_(false), port_(0) {}
    ~DnsResolver() { stop(); }

    bool init(const std::string &host, int port, const std::string &name)
    {
        hostname_ = host;
        port_ = port;
        name_ = name;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1)
        {
            is_domain_ = false;
            current_ip_ = host;
            std::lock_guard<std::shared_mutex> lock(addr_mutex_);
            target_addr_ = addr;
            return true;
        }

        is_domain_ = true;
        return resolve_now();
    }

    void start()
    {
        if (!is_domain_)
            return;
        running_ = true;
        resolver_thread_ = std::thread(&DnsResolver::resolver_loop, this);
    }

    void stop()
    {
        running_ = false;
        if (resolver_thread_.joinable() &&
            resolver_thread_.get_id() != std::this_thread::get_id())
        {
            resolver_thread_.join();
        }
    }

    sockaddr_in get_target_addr() const
    {
        std::shared_lock<std::shared_mutex> lock(addr_mutex_);
        return target_addr_;
    }

    std::string get_current_ip() const
    {
        std::shared_lock<std::shared_mutex> lock(addr_mutex_);
        return current_ip_;
    }

    bool is_domain() const { return is_domain_; }
    const std::string &get_hostname() const { return hostname_; }

private:
    std::string hostname_, name_, current_ip_;
    int port_;
    sockaddr_in target_addr_;
    mutable std::shared_mutex addr_mutex_;
    std::atomic<bool> running_, is_domain_;
    std::thread resolver_thread_;

    bool resolve_now()
    {
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        int ret = getaddrinfo(hostname_.c_str(), nullptr, &hints, &res);
        if (ret != 0 || !res)
        {
            Logger::error("[" + name_ + "] DNS failed: " + hostname_);
            return false;
        }

        sockaddr_in *addr_in = (sockaddr_in *)res->ai_addr;
        std::string new_ip = inet_ntoa(addr_in->sin_addr);

        {
            std::lock_guard<std::shared_mutex> lock(addr_mutex_);
            bool changed = (!current_ip_.empty() && current_ip_ != new_ip);
            current_ip_ = new_ip;
            target_addr_.sin_family = AF_INET;
            target_addr_.sin_port = htons(port_);
            target_addr_.sin_addr = addr_in->sin_addr;

            if (changed)
            {
                Logger::info("[" + name_ + "] DNS: " + hostname_ + " -> " + new_ip + " (changed)");
            }
            else
            {
                Logger::debug("[" + name_ + "] DNS: " + hostname_ + " -> " + new_ip);
            }
        }

        freeaddrinfo(res);
        return true;
    }

    void resolver_loop()
    {
        int elapsed = 0;
        while (running_ && g_running)
        {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            elapsed += 10;
            if (!running_ || !g_running)
                break;
            if (elapsed >= g_config.dns_refresh_interval)
            {
                elapsed = 0;
                resolve_now();
            }
        }
    }
};

// ==================== Utility Functions ====================
void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

std::string addr_to_string(const sockaddr_in &addr)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    return std::string(buf);
}

std::string format_bytes(uint64_t bytes)
{
    const char *units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = bytes;
    while (size >= 1024 && unit < 3)
    {
        size /= 1024;
        unit++;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f %s", size, units[unit]);
    return std::string(buf);
}

bool resolve_host(const std::string &host, sockaddr_in &addr)
{
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1)
        return true;
    struct hostent *he = gethostbyname(host.c_str());
    if (he && he->h_addr_list[0])
    {
        memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));
        return true;
    }
    return false;
}

void signal_handler(int sig)
{
    if (sig == SIGHUP)
    {
        Logger::instance().reopen();
        Logger::info("Log file reopened");
        return;
    }
    g_running = false;
}

// ==================== Daemonize ====================
bool daemonize()
{
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid > 0)
    {
        int s;
        waitpid(pid, &s, 0);
        exit(WIFEXITED(s) ? WEXITSTATUS(s) : 1);
    }

    if (setsid() < 0)
        _exit(1);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0)
        _exit(1);
    if (pid > 0)
    {
        std::cout << "Daemon PID: " << pid << std::endl;
        _exit(0);
    }

    umask(022);
    if (!g_config.work_dir.empty())
        chdir(g_config.work_dir.c_str());
    else if (!g_working_dir.empty())
        chdir(g_working_dir.c_str());

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0)
    {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2)
            close(fd);
    }

    return true;
}

bool write_pid_file(const std::string &f)
{
    std::ofstream file(f);
    if (!file.is_open())
        return false;
    file << getpid();
    return true;
}

void remove_pid_file(const std::string &f) { unlink(f.c_str()); }

bool is_already_running(const std::string &pf)
{
    std::ifstream file(pf);
    if (!file.is_open())
        return false;
    pid_t pid;
    file >> pid;
    file.close();
    if (pid <= 0)
        return false;
    if (kill(pid, 0) == 0)
        return true;
    unlink(pf.c_str());
    return false;
}

void generate_service_file()
{
    std::string svc = "[Unit]\nDescription=IP Forward v" VERSION "\nAfter=network.target\n\n"
                      "[Service]\nType=forking\nPIDFile=" +
                      g_config.abs_pid_file + "\n"
                                              "ExecStart=" +
                      g_exe_path + " -c " + g_config.abs_config_file + " -d\n"
                                                                       "ExecReload=/bin/kill -HUP $MAINPID\nRestart=always\nRestartSec=5\n\n"
                                                                       "[Install]\nWantedBy=multi-user.target\n";

    std::ofstream file("ip_forward.service");
    if (file.is_open())
    {
        file << svc;
        file.close();
        std::cout << "Generated: ip_forward.service\n";
    }
}

// ==================== Thread Pool ====================
class ThreadPool
{
public:
    ThreadPool(size_t n = 4) : stop_(false)
    {
        for (size_t i = 0; i < n; ++i)
            workers_.emplace_back([this]
                                  {
                while (true) {
                    std::function<void()> task;
                    { std::unique_lock<std::mutex> lk(mtx_); cv_.wait(lk, [this]{ return stop_ || !q_.empty(); });
                      if (stop_ && q_.empty()) return; task = std::move(q_.front()); q_.pop(); }
                    try { task(); } catch (...) {}
                } });
    }
    ~ThreadPool()
    {
        {
            std::unique_lock<std::mutex> lk(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto &w : workers_)
            if (w.joinable())
                w.join();
    }
    template <class F>
    void enqueue(F &&f)
    {
        {
            std::unique_lock<std::mutex> lk(mtx_);
            if (stop_)
                return;
            q_.emplace(std::forward<F>(f));
        }
        cv_.notify_one();
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> q_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool stop_;
};

// ==================== UDP Session ====================
struct UdpSession
{
    int server_socket = -1;
    sockaddr_in client_addr{};
    sockaddr_in connected_server{};
    std::string connected_ip;
    std::chrono::steady_clock::time_point last_active;
    std::atomic<uint64_t> pkts_sent{0}, pkts_recv{0}, bytes_sent{0}, bytes_recv{0};

    UdpSession() { update(); }
    ~UdpSession()
    {
        if (server_socket >= 0)
            close(server_socket);
    }
    UdpSession(const UdpSession &) = delete;
    UdpSession &operator=(const UdpSession &) = delete;

    void update() { last_active = std::chrono::steady_clock::now(); }
    int inactive() const
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::steady_clock::now() - last_active)
            .count();
    }
};

// ==================== UDP Forwarder ====================
class UdpForwarder
{
public:
    UdpForwarder(ForwardRule &r) : rule_(r), sock_(-1), running_(false) {}
    ~UdpForwarder() { stop(); }

    bool start()
    {
        if (!dns_.init(rule_.target_host, rule_.target_port, rule_.name))
        {
            Logger::error("[" + rule_.name + "] DNS init failed: " + rule_.target_host);
            return false;
        }

        sock_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_ < 0)
        {
            Logger::error("[" + rule_.name + "] socket() failed");
            return false;
        }

        int opt = 1;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &g_config.buffer_size, sizeof(g_config.buffer_size));
        setsockopt(sock_, SOL_SOCKET, SO_SNDBUF, &g_config.buffer_size, sizeof(g_config.buffer_size));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(rule_.listen_port);
        if (!resolve_host(rule_.listen_host, addr))
        {
            Logger::error("[" + rule_.name + "] Cannot resolve: " + rule_.listen_host);
            close(sock_);
            sock_ = -1;
            return false;
        }

        if (bind(sock_, (sockaddr *)&addr, sizeof(addr)) < 0)
        {
            Logger::error("[" + rule_.name + "] bind() failed: " + std::string(strerror(errno)));
            close(sock_);
            sock_ = -1;
            return false;
        }

        set_nonblocking(sock_);
        running_ = true;
        dns_.start();

        fwd_thread_ = std::thread(&UdpForwarder::forward_loop, this);
        cleanup_thread_ = std::thread(&UdpForwarder::cleanup_loop, this);

        std::string tgt = rule_.target_host;
        if (dns_.is_domain())
            tgt += " (" + dns_.get_current_ip() + ")";
        Logger::info("[" + rule_.name + "] UDP started :" + std::to_string(rule_.listen_port) +
                     " -> " + tgt + ":" + std::to_string(rule_.target_port));
        return true;
    }

    void stop()
    {
        running_ = false;
        dns_.stop();
        if (sock_ >= 0)
        {
            shutdown(sock_, SHUT_RDWR);
            close(sock_);
            sock_ = -1;
        }
        if (fwd_thread_.joinable() && fwd_thread_.get_id() != std::this_thread::get_id())
            fwd_thread_.join();
        if (cleanup_thread_.joinable() && cleanup_thread_.get_id() != std::this_thread::get_id())
            cleanup_thread_.join();
        {
            std::lock_guard<std::mutex> lk(sess_mtx_);
            sessions_.clear();
            rule_.sessions = 0;
        }
        Logger::info("[" + rule_.name + "] UDP stopped");
    }

    const DnsResolver &dns() const { return dns_; }

private:
    ForwardRule &rule_;
    DnsResolver dns_;
    int sock_;
    std::atomic<bool> running_;
    std::thread fwd_thread_, cleanup_thread_;
    std::mutex sess_mtx_;
    std::map<std::string, std::unique_ptr<UdpSession>> sessions_;

    UdpSession *get_session(const sockaddr_in &client)
    {
        std::string key = addr_to_string(client);
        std::lock_guard<std::mutex> lk(sess_mtx_);

        auto it = sessions_.find(key);
        if (it != sessions_.end())
            return it->second.get();

        if ((int)sessions_.size() >= g_config.max_sessions)
        {
            Logger::warn("[" + rule_.name + "] Max sessions reached");
            return nullptr;
        }

        auto sess = std::make_unique<UdpSession>();
        sess->client_addr = client;
        sess->connected_server = dns_.get_target_addr();
        sess->connected_ip = dns_.get_current_ip();

        sess->server_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (sess->server_socket < 0)
        {
            Logger::error("[" + rule_.name + "] socket() failed");
            return nullptr;
        }

        if (connect(sess->server_socket, (sockaddr *)&sess->connected_server, sizeof(sess->connected_server)) < 0)
        {
            Logger::error("[" + rule_.name + "] connect() failed: " + sess->connected_ip);
            close(sess->server_socket);
            return nullptr;
        }

        set_nonblocking(sess->server_socket);
        UdpSession *ptr = sess.get();
        sessions_[key] = std::move(sess);
        rule_.sessions++;

        Logger::info("[" + rule_.name + "] New: " + key + " -> " + ptr->connected_ip +
                     " (online: " + std::to_string(sessions_.size()) + ")");
        return ptr;
    }

    void forward_loop()
    {
        std::vector<char> buf(g_config.buffer_size);

        while (running_ && g_running)
        {
            fd_set fds;
            FD_ZERO(&fds);
            if (sock_ < 0)
                break;
            FD_SET(sock_, &fds);
            int maxfd = sock_;

            std::vector<std::pair<std::string, UdpSession *>> active;
            {
                std::lock_guard<std::mutex> lk(sess_mtx_);
                for (auto &p : sessions_)
                    if (p.second && p.second->server_socket >= 0)
                    {
                        FD_SET(p.second->server_socket, &fds);
                        maxfd = std::max(maxfd, p.second->server_socket);
                        active.emplace_back(p.first, p.second.get());
                    }
            }

            timeval tv{0, 50000};
            int ret = select(maxfd + 1, &fds, nullptr, nullptr, &tv);
            if (ret < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (ret == 0)
                continue;

            // Client -> Server
            if (sock_ >= 0 && FD_ISSET(sock_, &fds))
            {
                sockaddr_in client{};
                socklen_t len = sizeof(client);
                ssize_t n = recvfrom(sock_, buf.data(), buf.size(), 0, (sockaddr *)&client, &len);
                if (n > 0)
                {
                    rule_.packets_in++;
                    rule_.bytes_in += n;
                    g_total_packets_in++;
                    g_total_bytes_in += n;

                    UdpSession *s = get_session(client);
                    if (s && s->server_socket >= 0)
                    {
                        ssize_t sent = send(s->server_socket, buf.data(), n, 0);
                        if (sent > 0)
                        {
                            rule_.packets_out++;
                            rule_.bytes_out += sent;
                            g_total_packets_out++;
                            g_total_bytes_out += sent;
                            s->pkts_sent++;
                            s->bytes_sent += sent;
                            s->update();
                        }
                    }
                }
            }

            // Server -> Client
            for (auto &p : active)
            {
                if (p.second && p.second->server_socket >= 0 && FD_ISSET(p.second->server_socket, &fds))
                {
                    ssize_t n = recv(p.second->server_socket, buf.data(), buf.size(), 0);
                    if (n > 0)
                    {
                        rule_.packets_in++;
                        rule_.bytes_in += n;
                        g_total_packets_in++;
                        g_total_bytes_in += n;

                        if (sock_ >= 0)
                        {
                            ssize_t sent = sendto(sock_, buf.data(), n, 0,
                                                  (sockaddr *)&p.second->client_addr, sizeof(p.second->client_addr));
                            if (sent > 0)
                            {
                                rule_.packets_out++;
                                rule_.bytes_out += sent;
                                g_total_packets_out++;
                                g_total_bytes_out += sent;
                                p.second->pkts_recv++;
                                p.second->bytes_recv += sent;
                                p.second->update();
                            }
                        }
                    }
                }
            }
        }
    }

    void cleanup_loop()
    {
        while (running_ && g_running)
        {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (!running_)
                break;

            std::vector<std::string> expired;
            {
                std::lock_guard<std::mutex> lk(sess_mtx_);
                for (auto &p : sessions_)
                    if (p.second && p.second->inactive() > g_config.udp_timeout)
                        expired.push_back(p.first);
                for (auto &k : expired)
                {
                    Logger::info("[" + rule_.name + "] Timeout: " + k);
                    sessions_.erase(k);
                    rule_.sessions--;
                }
            }
        }
    }
};

// ==================== TCP Connection ====================
class TcpConnection
{
public:
    TcpConnection(int cfd, const sockaddr_in &caddr, ForwardRule &r, DnsResolver &d)
        : cfd_(cfd), sfd_(-1), caddr_(caddr), rule_(r), dns_(d), running_(false) {}
    ~TcpConnection() { stop(); }
    TcpConnection(const TcpConnection &) = delete;
    TcpConnection &operator=(const TcpConnection &) = delete;

    bool start()
    {
        sfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sfd_ < 0)
        {
            Logger::error("[" + rule_.name + "] socket() failed");
            return false;
        }

        sockaddr_in target = dns_.get_target_addr();
        connected_ip_ = dns_.get_current_ip();

        timeval tv{10, 0};
        setsockopt(sfd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sfd_, (sockaddr *)&target, sizeof(target)) < 0)
        {
            Logger::error("[" + rule_.name + "] connect() failed: " + connected_ip_);
            close(sfd_);
            sfd_ = -1;
            return false;
        }

        running_ = true;
        rule_.sessions++;
        Logger::info("[" + rule_.name + "] TCP: " + addr_to_string(caddr_) + " -> " + connected_ip_ +
                     " (online: " + std::to_string(rule_.sessions.load()) + ")");
        return true;
    }

    void run()
    {
        std::vector<char> buf(g_config.buffer_size);
        while (running_ && g_running)
        {
            fd_set fds;
            FD_ZERO(&fds);
            if (cfd_ < 0 || sfd_ < 0)
                break;
            FD_SET(cfd_, &fds);
            FD_SET(sfd_, &fds);
            int maxfd = std::max(cfd_, sfd_);

            timeval tv{1, 0};
            int ret = select(maxfd + 1, &fds, nullptr, nullptr, &tv);
            if (ret < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (ret == 0)
                continue;

            if (cfd_ >= 0 && FD_ISSET(cfd_, &fds))
            {
                ssize_t n = recv(cfd_, buf.data(), buf.size(), 0);
                if (n <= 0)
                    break;
                rule_.packets_in++;
                rule_.bytes_in += n;
                g_total_packets_in++;
                g_total_bytes_in += n;
                ssize_t s = send(sfd_, buf.data(), n, 0);
                if (s <= 0)
                    break;
                rule_.packets_out++;
                rule_.bytes_out += s;
                g_total_packets_out++;
                g_total_bytes_out += s;
            }

            if (sfd_ >= 0 && FD_ISSET(sfd_, &fds))
            {
                ssize_t n = recv(sfd_, buf.data(), buf.size(), 0);
                if (n <= 0)
                    break;
                rule_.packets_in++;
                rule_.bytes_in += n;
                g_total_packets_in++;
                g_total_bytes_in += n;
                ssize_t s = send(cfd_, buf.data(), n, 0);
                if (s <= 0)
                    break;
                rule_.packets_out++;
                rule_.bytes_out += s;
                g_total_packets_out++;
                g_total_bytes_out += s;
            }
        }
        stop();
    }

    void stop()
    {
        if (!running_.exchange(false))
            return;
        if (cfd_ >= 0)
        {
            shutdown(cfd_, SHUT_RDWR);
            close(cfd_);
            cfd_ = -1;
        }
        if (sfd_ >= 0)
        {
            shutdown(sfd_, SHUT_RDWR);
            close(sfd_);
            sfd_ = -1;
        }
        rule_.sessions--;
        Logger::info("[" + rule_.name + "] TCP closed: " + addr_to_string(caddr_));
    }

private:
    int cfd_, sfd_;
    sockaddr_in caddr_;
    ForwardRule &rule_;
    DnsResolver &dns_;
    std::string connected_ip_;
    std::atomic<bool> running_;
};

// ==================== TCP Forwarder ====================
class TcpForwarder
{
public:
    TcpForwarder(ForwardRule &r) : rule_(r), sock_(-1), running_(false), pool_(4) {}
    ~TcpForwarder() { stop(); }

    bool start()
    {
        if (!dns_.init(rule_.target_host, rule_.target_port, rule_.name))
        {
            Logger::error("[" + rule_.name + "] DNS init failed");
            return false;
        }

        sock_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ < 0)
        {
            Logger::error("[" + rule_.name + "] socket() failed");
            return false;
        }

        int opt = 1;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(rule_.listen_port);
        if (!resolve_host(rule_.listen_host, addr))
        {
            close(sock_);
            sock_ = -1;
            return false;
        }

        if (bind(sock_, (sockaddr *)&addr, sizeof(addr)) < 0)
        {
            Logger::error("[" + rule_.name + "] bind() failed");
            close(sock_);
            sock_ = -1;
            return false;
        }

        if (listen(sock_, 128) < 0)
        {
            close(sock_);
            sock_ = -1;
            return false;
        }

        set_nonblocking(sock_);
        running_ = true;
        dns_.start();
        accept_thread_ = std::thread(&TcpForwarder::accept_loop, this);

        Logger::info("[" + rule_.name + "] TCP started :" + std::to_string(rule_.listen_port));
        return true;
    }

    void stop()
    {
        running_ = false;
        dns_.stop();
        if (sock_ >= 0)
        {
            shutdown(sock_, SHUT_RDWR);
            close(sock_);
            sock_ = -1;
        }
        if (accept_thread_.joinable() && accept_thread_.get_id() != std::this_thread::get_id())
            accept_thread_.join();
        {
            std::lock_guard<std::mutex> lk(conns_mtx_);
            for (auto &c : conns_)
                if (c)
                    c->stop();
            conns_.clear();
        }
        Logger::info("[" + rule_.name + "] TCP stopped");
    }

private:
    ForwardRule &rule_;
    DnsResolver dns_;
    int sock_;
    std::atomic<bool> running_;
    std::thread accept_thread_;
    ThreadPool pool_;
    std::mutex conns_mtx_;
    std::list<std::shared_ptr<TcpConnection>> conns_;

    void accept_loop()
    {
        while (running_ && g_running)
        {
            fd_set fds;
            FD_ZERO(&fds);
            if (sock_ < 0)
                break;
            FD_SET(sock_, &fds);
            timeval tv{1, 0};
            if (select(sock_ + 1, &fds, nullptr, nullptr, &tv) <= 0)
                continue;

            sockaddr_in client{};
            socklen_t len = sizeof(client);
            int cfd = accept(sock_, (sockaddr *)&client, &len);
            if (cfd < 0)
                continue;

            if (rule_.sessions >= g_config.max_sessions)
            {
                Logger::warn("[" + rule_.name + "] Max sessions");
                close(cfd);
                continue;
            }

            auto conn = std::make_shared<TcpConnection>(cfd, client, rule_, dns_);
            if (conn->start())
            {
                {
                    std::lock_guard<std::mutex> lk(conns_mtx_);
                    conns_.remove_if([](auto &c)
                                     { return !c || c.use_count() == 1; });
                    conns_.push_back(conn);
                }
                pool_.enqueue([conn]()
                              { conn->run(); });
            }
            else
                close(cfd);
        }
    }
};

// ==================== Forward Manager ====================
class ForwardManager
{
public:
    bool start()
    {
        for (auto &r : g_config.forwards)
        {
            if (g_config.enable_udp)
            {
                auto f = std::make_unique<UdpForwarder>(r);
                if (!f->start())
                    return false;
                udp_.push_back(std::move(f));
            }
            if (g_config.enable_tcp)
            {
                auto f = std::make_unique<TcpForwarder>(r);
                if (!f->start())
                    return false;
                tcp_.push_back(std::move(f));
            }
        }
        return true;
    }

    void stop()
    {
        for (auto &f : udp_)
            if (f)
                f->stop();
        for (auto &f : tcp_)
            if (f)
                f->stop();
        udp_.clear();
        tcp_.clear();
    }

    void print_status()
    {
        std::stringstream ss;
        ss << "=== Status ===\n";

        int total = 0;
        for (auto &r : g_config.forwards)
        {
            total += r.sessions.load();
            ss << "[" << r.name << "] Sessions: " << r.sessions.load()
               << " | In: " << format_bytes(r.bytes_in.load())
               << " | Out: " << format_bytes(r.bytes_out.load());

            for (auto &u : udp_)
            {
                if (u && u->dns().get_hostname() == r.target_host && u->dns().is_domain())
                {
                    ss << " | IP: " << u->dns().get_current_ip();
                    break;
                }
            }
            ss << "\n";
        }

        ss << "Total: " << total << " sessions | "
           << format_bytes(g_total_bytes_in.load()) << " in | "
           << format_bytes(g_total_bytes_out.load()) << " out";

        Logger::info(ss.str());
    }

private:
    std::vector<std::unique_ptr<UdpForwarder>> udp_;
    std::vector<std::unique_ptr<TcpForwarder>> tcp_;
};

// ==================== Status Monitor ====================
void status_monitor(ForwardManager &mgr)
{
    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        if (!g_running)
            break;
        mgr.print_status();
    }
}

// ==================== Main ====================
void print_banner()
{
    std::cout << R"(
  ___ ____    _____                                _
 |_ _|  _ \  |  ___|__  _ ____      ____ _ _ __ __| |
  | || |_) | | |_ / _ \| '__\ \ /\ / / _` | '__/ _` |
  | ||  __/  |  _| (_) | |   \ V  V / (_| | | | (_| |
 |___|_|     |_|  \___/|_|    \_/\_/ \__,_|_|  \__,_|
                                              v)" VERSION R"(
)" << std::endl;
}

void print_usage(const char *p)
{
    std::cout << "Usage: " << p << " [options]\n\n"
              << "Options:\n"
              << "  -c, --config <file>     Config file (default: config.json)\n"
              << "  -d, --daemon            Run as daemon\n"
              << "  -g, --generate-service  Generate systemd service\n"
              << "  -s, --stop              Stop daemon\n"
              << "  -h, --help              Show help\n\n";
}

int main(int argc, char *argv[])
{
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)))
        g_working_dir = cwd;

    char exe[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len > 0)
    {
        exe[len] = '\0';
        g_exe_path = exe;
    }

    std::string config_file = "config.json";
    bool force_daemon = false, gen_svc = false, stop_daemon = false;

    for (int i = 1; i < argc; i++)
    {
        std::string a = argv[i];
        if ((a == "-c" || a == "--config") && i + 1 < argc)
            config_file = argv[++i];
        else if (a == "-d" || a == "--daemon")
            force_daemon = true;
        else if (a == "-g" || a == "--generate-service")
            gen_svc = true;
        else if (a == "-s" || a == "--stop")
            stop_daemon = true;
        else if (a == "-h" || a == "--help")
        {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Load config
    std::ifstream chk(config_file);
    if (!chk.good())
    {
        std::cout << "[INFO] Creating default config: " << config_file << std::endl;
        g_config.create_default(config_file);
    }
    chk.close();

    if (!g_config.load(config_file))
    {
        std::cout << "[WARN] Using defaults" << std::endl;
    }

    // Stop daemon
    if (stop_daemon)
    {
        if (is_already_running(g_config.abs_pid_file))
        {
            std::ifstream pf(g_config.abs_pid_file);
            pid_t pid;
            pf >> pid;
            pf.close();
            std::cout << "Stopping PID " << pid << "..." << std::endl;
            kill(pid, SIGTERM);
            for (int i = 0; i < 30; i++)
            {
                usleep(100000);
                if (kill(pid, 0) != 0)
                {
                    std::cout << "Stopped.\n";
                    return 0;
                }
            }
            kill(pid, SIGKILL);
            return 0;
        }
        std::cout << "Not running.\n";
        return 0;
    }

    // Generate service
    if (gen_svc)
    {
        print_banner();
        generate_service_file();
        return 0;
    }

    // Check running
    if (is_already_running(g_config.abs_pid_file))
    {
        std::cerr << "[ERROR] Already running. Use -s to stop.\n";
        return 1;
    }

    print_banner();

    // Daemonize
    if (force_daemon || g_config.daemon_mode)
    {
        std::cout << "[INFO] Daemon mode\n";
        std::cout << "[INFO] " << g_config.forwards.size() << " forward rules\n";
        std::cout << "[INFO] Log: " << g_config.abs_log_file << "\n";
        std::cout << "[INFO] PID: " << g_config.abs_pid_file << "\n";

        if (!daemonize())
        {
            std::cerr << "[ERROR] daemonize() failed\n";
            return 1;
        }

        Logger::instance().init(g_config.abs_log_file, g_config.log_to_file, false, g_config.get_log_level());
        write_pid_file(g_config.abs_pid_file);

        Logger::info("========================================");
        Logger::info("IP Forward v" VERSION " started (PID: " + std::to_string(getpid()) + ")");
        Logger::info(std::to_string(g_config.forwards.size()) + " forward rules");
        Logger::info("========================================");
    }
    else
    {
        g_config.print();
        Logger::instance().init(g_config.abs_log_file, g_config.log_to_file,
                                g_config.log_to_console, g_config.get_log_level());
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, signal_handler);

    ForwardManager mgr;
    if (!mgr.start())
    {
        Logger::error("Failed to start");
        remove_pid_file(g_config.abs_pid_file);
        return 1;
    }

    std::thread monitor(status_monitor, std::ref(mgr));

    Logger::info("All forwards started");

    while (g_running)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Logger::info("Shutting down...");
    mgr.stop();
    if (monitor.joinable())
        monitor.join();

    Logger::info("=== Final Stats ===");
    Logger::info("Packets: " + std::to_string(g_total_packets_in.load()) + " in / " +
                 std::to_string(g_total_packets_out.load()) + " out");
    Logger::info("Bytes: " + format_bytes(g_total_bytes_in.load()) + " in / " +
                 format_bytes(g_total_bytes_out.load()) + " out");
    Logger::info("Goodbye!");

    Logger::instance().close();
    remove_pid_file(g_config.abs_pid_file);

    return 0;
}