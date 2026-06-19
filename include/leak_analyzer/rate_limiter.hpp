#ifndef RATE_LIMITER_HPP
#define RATE_LIMITER_HPP

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <thread>
#include <algorithm>

namespace leak_analyzer {

struct TokenBucket {
    double capacity;
    double tokens;
    double refill_rate_per_ms; // Tokens added per millisecond
    std::chrono::steady_clock::time_point last_update;
};

class RateLimiter {
private:
    std::unordered_map<std::string, TokenBucket> limiters;
    mutable std::mutex limiter_mutex;

public:
    RateLimiter() = default;

    void acquire(const std::string& platform) {
        std::unique_lock<std::mutex> lock(limiter_mutex);

        // Default Token Bucket configuration: Capacity of 5.0, refills 1 token per 200ms (0.005 tokens/ms)
        double capacity = 5.0;
        double refill_rate_per_ms = 0.005;

        // Custom rate limits for critical / slower platforms to prevent simulated DDoS
        if (platform == "Instagram" || platform == "LinkedIn" || platform == "Modbus_TCP" || platform == "DNP3" || platform == "IEC_104") {
            capacity = 2.0;
            refill_rate_per_ms = 0.001; // Refills 1 token per 1000ms (0.001 tokens/ms)
        }

        auto now = std::chrono::steady_clock::now();
        auto it = limiters.find(platform);
        if (it == limiters.end()) {
            TokenBucket tb;
            tb.capacity = capacity;
            tb.tokens = capacity - 1.0; // Consume 1 token immediately
            tb.refill_rate_per_ms = refill_rate_per_ms;
            tb.last_update = now;
            limiters[platform] = tb;
            return;
        }

        auto& tb = it->second;

        while (true) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - tb.last_update).count();
            tb.tokens = std::min(tb.capacity, tb.tokens + elapsed * tb.refill_rate_per_ms);
            tb.last_update = now;

            if (tb.tokens >= 1.0) {
                tb.tokens -= 1.0;
                break;
            }

            // Calculate wait time until next token is available
            double needed = 1.0 - tb.tokens;
            double wait_ms = needed / tb.refill_rate_per_ms;
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(wait_ms)));
            lock.lock();
            now = std::chrono::steady_clock::now();
        }
    }

    void set_limit(const std::string& platform, uint64_t capacity_val, uint64_t refill_interval_ms) {
        std::lock_guard<std::mutex> lock(limiter_mutex);
        TokenBucket tb;
        tb.capacity = static_cast<double>(capacity_val);
        tb.tokens = tb.capacity;
        tb.refill_rate_per_ms = 1.0 / static_cast<double>(refill_interval_ms);
        tb.last_update = std::chrono::steady_clock::now();
        limiters[platform] = tb;
    }
};

} // namespace leak_analyzer

#endif // RATE_LIMITER_HPP

