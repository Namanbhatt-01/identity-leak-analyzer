#ifndef ANALYZER_ENGINE_HPP
#define ANALYZER_ENGINE_HPP

#include <vector>
#include <string>
#include <utility>
#include <leak_analyzer/profile_parser.hpp>
#include <leak_analyzer/threat_feed.hpp>
#include <leak_analyzer/thread_safe_store.hpp>
#include <leak_analyzer/rate_limiter.hpp>
#include <leak_analyzer/detectors.hpp>
#include <leak_analyzer/logger.hpp>
#include <leak_analyzer/http_client.hpp>

namespace leak_analyzer {

struct AnalysisResult {
    UserProfile profile;
    ProfileStatus status;
    std::vector<LeakRecord> exposures;
};

class AnalyzerEngine {
private:
    ThreadSafeStore<AnalysisResult>& results_store;
    RateLimiter limiter;
    Logger& logger;
    const HttpClient& http_client;

    void worker_job(const std::string& username, const std::string& platform);

public:
    AnalyzerEngine(ThreadSafeStore<AnalysisResult>& store, Logger& log, const HttpClient& cli);

    void run_analysis_parallel(const std::vector<std::pair<std::string, std::string>>& raw_inputs);
};

} // namespace leak_analyzer

#endif // ANALYZER_ENGINE_HPP
