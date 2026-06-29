#include "optimize.h"

#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <cerrno>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <atomic>
#include <random>
#include <iomanip>
#include <regex>
#include <string_view>
#include <memory>
#include <unordered_map>

using FeatureVec = std::vector<float>;

static constexpr size_t INPUT_SIZE = 32;
static constexpr size_t HIDDEN_SIZE = 16;
static constexpr size_t NUM_CLASSES = 12;

static const char* SERVICE_NAMES[NUM_CLASSES] = {
    "HTTP", "HTTPS", "SSH", "FTP", "SMTP",
    "MySQL", "PostgreSQL", "Redis", "MongoDB",
    "DNS", "POP3_IMAP", "Unknown"
};

struct DetectionResult {
    int port;
    std::string service;
    float confidence;
    FeatureVec raw_output;
};

static std::mutex g_output_mutex;
static std::atomic<size_t> g_processed{0};

FORCE_INLINE static float sigmoidf(float x) noexcept {
    return 1.0f / (1.0f + std::exp(-x));
}

FORCE_INLINE static void mat_vec_mul(
    const float* w, const float* v, float* out,
    size_t rows, size_t cols) noexcept
{
    for (size_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        for (size_t c = 0; c < cols; ++c)
            sum += w[r * cols + c] * v[c];
        out[r] = sum;
    }
}

FORCE_INLINE static void vec_add(float* a, const float* b, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i) a[i] += b[i];
}

FORCE_INLINE static void vec_sigmoid(float* a, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i) a[i] = sigmoidf(a[i]);
}

class NeuralNetwork {
    struct Weights {
        std::vector<float> w1, b1;
        std::vector<float> w2, b2;
        std::vector<float> w3, b3;
    } w_;

    void init_weights_heuristic() noexcept {
        w_.w1.assign(INPUT_SIZE * HIDDEN_SIZE, 0.0f);
        w_.b1.assign(HIDDEN_SIZE, -2.0f);

        constexpr float STRONG = 5.0f, MODERATE = 3.0f, WEAK = 2.0f;

        auto set_w1 = [&](size_t neuron, size_t feat, float val) {
            w_.w1[neuron * INPUT_SIZE + feat] = val;
        };

        set_w1(0, 4, MODERATE);   set_w1(0, 10, STRONG);   set_w1(0, 21, WEAK);    set_w1(0, 24, STRONG);
        set_w1(1, 5, MODERATE);   set_w1(1, 20, STRONG);
        set_w1(2, 2, MODERATE);   set_w1(2, 11, STRONG);
        set_w1(3, 1, MODERATE);   set_w1(3, 12, STRONG);   set_w1(3, 19, MODERATE);
        set_w1(4, 3, MODERATE);   set_w1(4, 13, STRONG);   set_w1(4, 19, MODERATE);
        set_w1(5, 6, MODERATE);   set_w1(5, 14, STRONG);
        set_w1(6, 7, MODERATE);   set_w1(6, 15, STRONG);
        set_w1(7, 8, MODERATE);   set_w1(7, 16, STRONG);
        set_w1(8, 17, STRONG);
        set_w1(9, 18, STRONG);
        set_w1(10, 27, STRONG);   set_w1(10, 28, STRONG);  set_w1(10, 30, WEAK);    set_w1(10, 31, WEAK);
        set_w1(11, 9, WEAK);      set_w1(11, 26, WEAK);
        set_w1(12, 22, STRONG);   set_w1(12, 23, STRONG);
        set_w1(13, 25, STRONG);
        set_w1(14, 0, WEAK);      set_w1(14, 9, WEAK);
        w_.b1[15] = 0.0f;

        w_.w2.assign(HIDDEN_SIZE * HIDDEN_SIZE, 0.0f);
        w_.b2.assign(HIDDEN_SIZE, -2.0f);

        auto set_w2 = [&](size_t dst, size_t src, float val) {
            w_.w2[dst * HIDDEN_SIZE + src] = val;
        };

        set_w2(0, 0, MODERATE);   set_w2(0, 1, WEAK);
        set_w2(1, 1, MODERATE);
        set_w2(2, 2, MODERATE);
        set_w2(3, 3, MODERATE);
        set_w2(4, 4, MODERATE);
        set_w2(5, 5, MODERATE);
        set_w2(6, 6, MODERATE);
        set_w2(7, 7, MODERATE);
        set_w2(8, 8, MODERATE);
        set_w2(9, 9, MODERATE);
        set_w2(10, 10, MODERATE); set_w2(10, 14, WEAK);
        set_w2(11, 11, MODERATE); set_w2(11, 15, WEAK);
        set_w2(12, 12, MODERATE);
        set_w2(13, 13, MODERATE); set_w2(13, 15, WEAK);
        set_w2(14, 14, MODERATE);
        w_.b2[15] = 0.0f;

        w_.w3.assign(NUM_CLASSES * HIDDEN_SIZE, 0.0f);
        w_.b3.assign(NUM_CLASSES, -2.0f);

        auto set_w3 = [&](size_t cls, size_t hid, float val) {
            w_.w3[cls * HIDDEN_SIZE + hid] = val;
        };

        set_w3(0, 0, STRONG);
        set_w3(1, 1, STRONG);
        set_w3(2, 2, STRONG);
        set_w3(3, 3, STRONG);
        set_w3(4, 4, STRONG);
        set_w3(5, 5, STRONG);
        set_w3(6, 6, STRONG);
        set_w3(7, 7, STRONG);
        set_w3(8, 8, STRONG);
        set_w3(9, 9, STRONG);
        set_w3(10, 10, STRONG);
        set_w3(11, 11, WEAK);    set_w3(11, 13, WEAK);    set_w3(11, 14, WEAK);    set_w3(11, 15, WEAK);
    }

public:
    NeuralNetwork() { init_weights_heuristic(); }

    FeatureVec forward(const FeatureVec& input) const noexcept {
        std::vector<float> h1(HIDDEN_SIZE), h2(HIDDEN_SIZE), out(NUM_CLASSES);

        mat_vec_mul(w_.w1.data(), input.data(), h1.data(), HIDDEN_SIZE, INPUT_SIZE);
        vec_add(h1.data(), w_.b1.data(), HIDDEN_SIZE);
        vec_sigmoid(h1.data(), HIDDEN_SIZE);

        mat_vec_mul(w_.w2.data(), h1.data(), h2.data(), HIDDEN_SIZE, HIDDEN_SIZE);
        vec_add(h2.data(), w_.b2.data(), HIDDEN_SIZE);
        vec_sigmoid(h2.data(), HIDDEN_SIZE);

        mat_vec_mul(w_.w3.data(), h2.data(), out.data(), NUM_CLASSES, HIDDEN_SIZE);
        vec_add(out.data(), w_.b3.data(), NUM_CLASSES);
        vec_sigmoid(out.data(), NUM_CLASSES);

        return out;
    }

    bool load(std::string_view path) noexcept {
        std::ifstream file(std::string(path), std::ios::binary);
        if (!file) return false;
        auto rd = [&](std::vector<float>& v, size_t n) {
            v.resize(n);
            file.read(reinterpret_cast<char*>(v.data()), static_cast<std::streamsize>(n * sizeof(float)));
        };
        rd(w_.w1, INPUT_SIZE * HIDDEN_SIZE);
        rd(w_.b1, HIDDEN_SIZE);
        rd(w_.w2, HIDDEN_SIZE * HIDDEN_SIZE);
        rd(w_.b2, HIDDEN_SIZE);
        rd(w_.w3, NUM_CLASSES * HIDDEN_SIZE);
        rd(w_.b3, NUM_CLASSES);
        return !file.fail();
    }

    bool save(std::string_view path) const noexcept {
        std::ofstream f(std::string(path), std::ios::binary);
        if (!f) return false;
        auto wr = [&](const std::vector<float>& v) {
            f.write(reinterpret_cast<const char*>(v.data()), static_cast<std::streamsize>(v.size() * sizeof(float)));
        };
        wr(w_.w1); wr(w_.b1); wr(w_.w2); wr(w_.b2); wr(w_.w3); wr(w_.b3);
        return bool(f);
    }
};

static FeatureVec extract_features(int port, std::string_view banner) noexcept {
    FeatureVec fv(INPUT_SIZE, 0.0f);
    fv[0] = std::min(port / 65535.0f, 1.0f);

    switch (port) {
        case 21:   fv[1] = 1.0f; break;
        case 22:   fv[2] = 1.0f; break;
        case 25:   fv[3] = 1.0f; break;
        case 80:   fv[4] = 1.0f; break;
        case 443:  fv[5] = 1.0f; break;
        case 3306: fv[6] = 1.0f; break;
        case 5432: fv[7] = 1.0f; break;
        case 6379: fv[8] = 1.0f; break;
    }

    fv[9] = std::min(banner.size() / 4096.0f, 1.0f);

    auto contains_ci = [&](std::string_view kw) -> bool {
        return std::search(banner.begin(), banner.end(),
            kw.begin(), kw.end(),
            [](char c1, char c2) { return std::tolower(static_cast<unsigned char>(c1)) == std::tolower(static_cast<unsigned char>(c2)); }
        ) != banner.end();
    };

    if (contains_ci("http"))      fv[10] = 1.0f;
    if (contains_ci("ssh"))       fv[11] = 1.0f;
    if (contains_ci("ftp"))       fv[12] = 1.0f;
    if (contains_ci("smtp") || contains_ci("esmtp")) fv[13] = 1.0f;
    if (contains_ci("mysql"))     fv[14] = 1.0f;
    if (contains_ci("postgresql") || contains_ci("postgres")) fv[15] = 1.0f;
    if (contains_ci("redis"))     fv[16] = 1.0f;
    if (contains_ci("mongodb") || contains_ci("mongo")) fv[17] = 1.0f;
    if (contains_ci("dns"))       fv[18] = 1.0f;

    if (banner.size() >= 3 && banner.compare(0, 3, "220") == 0) fv[19] = 1.0f;
    if (contains_ci("ssl") || contains_ci("tls")) fv[20] = 1.0f;
    if (banner.find("Server:") != std::string::npos) fv[21] = 1.0f;
    if (banner.find("WWW-Authenticate") != std::string::npos) fv[22] = 1.0f;
    if (banner.find("Set-Cookie") != std::string::npos) fv[23] = 1.0f;
    if (banner.find("HTTP/") != std::string::npos) fv[24] = 1.0f;
    if (contains_ci("error"))     fv[25] = 1.0f;

    if (std::regex_search(std::string(banner), std::regex(R"(\d+\.\d+(\.\d+)?)"))) fv[26] = 1.0f;

    if (contains_ci("pop3"))      fv[27] = 1.0f;
    if (contains_ci("imap"))      fv[28] = 1.0f;
    if (contains_ci("ldap"))      fv[29] = 1.0f;
    if (port == 110)              fv[30] = 1.0f;
    if (port == 143 || port == 993) fv[31] = 1.0f;

    return fv;
}

class ThreadPool {
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool stop_{false};

public:
    explicit ThreadPool(size_t count) {
        workers_.reserve(count);
        for (size_t i = 0; i < count; ++i)
            workers_.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(mtx_);
                        cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                }
            });
    }

    template<typename F>
    void enqueue(F&& f) noexcept {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            tasks_.emplace(std::forward<F>(f));
        }
        cv_.notify_one();
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& t : workers_)
            if (t.joinable()) t.join();
    }
};

static int tcp_connect_banner(std::string_view target, int port, int timeout_sec, std::string& out_banner) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (LIKELY(fd < 0)) return -1;

    fcntl(fd, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr;
    std::string target_s(target);
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, target_s.c_str(), &addr.sin_addr) != 1) {
        struct hostent* he = gethostbyname(target_s.c_str());
        if (UNLIKELY(!he)) { close(fd); return -1; }
        std::memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (UNLIKELY(rc < 0 && errno != EINPROGRESS)) { close(fd); return -1; }

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    fd_set wfds, rfds;
    FD_ZERO(&wfds); FD_ZERO(&rfds);
    FD_SET(fd, &wfds); FD_SET(fd, &rfds);

    if (UNLIKELY(select(fd + 1, &rfds, &wfds, nullptr, &tv) <= 0)) {
        close(fd);
        return -1;
    }

    char buf[8192];
    int n = 0;

    struct timeval rt;
    rt.tv_sec = 2; rt.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    if (select(fd + 1, &rfds, nullptr, nullptr, &rt) > 0) {
        n = static_cast<int>(read(fd, buf, sizeof(buf) - 1));
        if (n > 0) { buf[n] = 0; out_banner.assign(buf, static_cast<size_t>(n)); }
    }

    if (out_banner.empty()) {
        const char* probes[] = {
            "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            "HELO localhost\r\n",
            "\r\n",
            nullptr
        };
        for (int pi = 0; probes[pi]; ++pi) {
            write(fd, probes[pi], std::strlen(probes[pi]));
            usleep(150000);
            FD_ZERO(&rfds); FD_SET(fd, &rfds);
            rt.tv_sec = 2; rt.tv_usec = 0;
            if (select(fd + 1, &rfds, nullptr, nullptr, &rt) > 0) {
                n = static_cast<int>(read(fd, buf, sizeof(buf) - 1));
                if (n > 0) { buf[n] = 0; out_banner.assign(buf, static_cast<size_t>(n)); break; }
            }
        }
    }

    close(fd);
    return out_banner.empty() ? -1 : 0;
}

static std::string json_escape(std::string_view s) {
    std::string r;
    r.reserve(s.size() + 4);
    for (unsigned char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    r += buf;
                } else {
                    r += c;
                }
        }
    }
    return r;
}

static void emit_result(const DetectionResult& dr) noexcept {
    std::lock_guard<std::mutex> lock(g_output_mutex);
    std::cout << "RESULT:{\"port\":" << dr.port
              << ",\"service\":\"" << dr.service
              << "\",\"confidence\":"
              << std::fixed << std::setprecision(4) << dr.confidence
              << ",\"raw_outputs\":[";
    for (size_t i = 0; i < dr.raw_output.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << std::fixed << std::setprecision(4) << dr.raw_output[i];
    }
    std::cout << "]}\n" << std::flush;
}

static void emit_final(size_t total) noexcept {
    std::cout << "FINAL:{\"engine\":\"deep_learning_analyzer\",\"scanned\":" << total << "}\n" << std::flush;
}

struct CliArgs {
    std::string target = "127.0.0.1";
    std::vector<int> ports;
    std::string model_file;
    int timeout = 5;
    int threads = 0;
};

static CliArgs parse_args(int argc, char** argv) {
    CliArgs args;
    args.threads = static_cast<int>(std::thread::hardware_concurrency());
    if (args.threads < 1) args.threads = 4;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--target" && i + 1 < argc) {
            args.target = argv[++i];
        } else if (arg == "--ports" && i + 1 < argc) {
            std::string ps(argv[++i]);
            size_t pos = 0;
            while (pos < ps.size()) {
                size_t comma = ps.find(',', pos);
                std::string tok = ps.substr(pos, comma - pos);
                if (!tok.empty()) {
                    auto dash = tok.find('-');
                    if (dash != std::string::npos) {
                        int lo = std::stoi(tok.substr(0, dash));
                        int hi = std::stoi(tok.substr(dash + 1));
                        for (int p = lo; p <= hi; ++p) args.ports.emplace_back(p);
                    } else {
                        args.ports.emplace_back(std::stoi(tok));
                    }
                }
                if (comma == std::string::npos) break;
                pos = comma + 1;
            }
        } else if (arg == "--model" && i + 1 < argc) {
            args.model_file = argv[++i];
        } else if (arg == "--timeout" && i + 1 < argc) {
            args.timeout = std::atoi(argv[++i]);
            if (args.timeout < 1) args.timeout = 5;
        } else if (arg == "--threads" && i + 1 < argc) {
            args.threads = std::atoi(argv[++i]);
            if (args.threads < 1) args.threads = 1;
            if (args.threads > 64) args.threads = 64;
        } else if (arg == "--help" || arg == "-h") {
            std::cerr << "Usage: " << argv[0]
                      << " --target <IP> --ports <port,list> [--model <file>] [--timeout <sec>] [--threads <N>]\n";
            std::exit(0);
        }
    }
    if (args.ports.empty()) args.ports.emplace_back(80);
    return args;
}

int main(int argc, char** argv) {
    auto args = parse_args(argc, argv);
    NeuralNetwork nn;

    if (!args.model_file.empty()) {
        if (LIKELY(nn.load(args.model_file))) {
            std::cerr << "[*] Loaded model from " << args.model_file << "\n";
        } else {
            std::cerr << "[*] Model file not found, using heuristic weights. Training with --model <file> to save.\n";
        }
    } else {
        std::string default_model = "dl_model.bin";
        if (nn.load(default_model)) {
            std::cerr << "[*] Loaded default model " << default_model << "\n";
        } else {
            std::cerr << "[*] No model file, using heuristic weights.\n";
        }
    }

    std::cerr << "[*] Scanning " << args.target << " on " << args.ports.size() << " ports with "
              << args.threads << " threads\n";

    ThreadPool pool(static_cast<size_t>(args.threads));
    std::vector<DetectionResult> results(args.ports.size());
    std::atomic<size_t> idx{0};

    auto worker = [&](int port_idx) {
        int port = args.ports[port_idx];
        std::string banner;
        tcp_connect_banner(args.target, port, args.timeout, banner);

        auto fv = extract_features(port, banner);
        auto out = nn.forward(fv);

        float max_val = 0.0f;
        int max_idx = static_cast<int>(NUM_CLASSES - 1);
        for (int k = 0; k < static_cast<int>(NUM_CLASSES); ++k) {
            if (out[static_cast<size_t>(k)] > max_val) {
                max_val = out[static_cast<size_t>(k)];
                max_idx = k;
            }
        }

        DetectionResult dr;
        dr.port = port;
        dr.service = SERVICE_NAMES[max_idx];
        dr.confidence = max_val;
        dr.raw_output = std::move(out);

        {
            std::lock_guard<std::mutex> lock(g_output_mutex);
            results[port_idx] = std::move(dr);
        }

        g_processed.fetch_add(1, std::memory_order_relaxed);
    };

    for (size_t i = 0; i < args.ports.size(); ++i)
        pool.enqueue([&worker, i] { worker(static_cast<int>(i)); });

    {
        while (g_processed.load(std::memory_order_acquire) < args.ports.size()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    for (auto& r : results) emit_result(r);
    emit_final(results.size());

    return 0;
}
