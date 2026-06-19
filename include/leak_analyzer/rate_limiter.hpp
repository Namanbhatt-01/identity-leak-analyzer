#ifndef RATE_LIMITER_HPP
#define RATE_LIMITER_HPP

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <thread>

namespace leak_analyzer {

struct DomainLimiter {
    std::chrono::steady_clock::time_point last_request;
    uint64_t min_delay_ms;
};

class RateLimiter {
private:
    std::unordered_map<std::string, DomainLimiter> limiters;
    mutable std::mutex limiter_mutex;

public:
    RateLimiter() = default;

    void acquire(const std::string& platform) {
        std::lock_guard<std::mutex> lock(limiter_mutex);

        uint64_t min_delay_ms = 300;
        if (platform == "Instagram" || platform == "LinkedIn") {
            min_delay_ms = 1000;
        }

        auto now = std::chrono::steady_clock::now();
        auto it = limiters.find(platform);
        if (it == limiters.end()) {
            DomainLimiter dl;
            dl.last_request = now;
            dl.min_delay_ms = min_delay_ms;
            limiters[platform] = dl;
            return;
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.last_request).count();
        if (elapsed < static_cast<long long>(it->second.min_delay_ms)) {
            long long wait_time = it->second.min_delay_ms - elapsed;
            std::this_thread::sleep_for(std::chrono::milliseconds(wait_time));
        }

        limiters[platform].last_request = std::chrono::steady_clock::now();
    }

    void set_limit(const std::string& platform, uint64_t min_delay_ms) {
        std::lock_guard<std::mutex> lock(limiter_mutex);
        limiters[platform].min_delay_ms = min_delay_ms;
        limiters[platform].last_request = std::chrono::steady_clock::now() - std::chrono::seconds(10);
    }
};

} // namespace leak_analyzer

#endif // RATE_LIMITER_HPP
