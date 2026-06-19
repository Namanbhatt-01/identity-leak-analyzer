#include <leak_analyzer/analyzer_engine.hpp>
#include <leak_analyzer/security_utils.hpp>
#include <thread>
#include <sstream>
#include <vector>
#include <utility>

namespace leak_analyzer {

AnalyzerEngine::AnalyzerEngine(ThreadSafeStore<AnalysisResult>& store, Logger& log, const HttpClient& cli) 
    : results_store(store), logger(log), http_client(cli) {}

static std::string status_to_string(ProfileStatus status) {
    switch (status) {
        case ProfileStatus::Exists: return "EXISTS";
        case ProfileStatus::Private: return "PRIVATE (PROTECTED)";
        case ProfileStatus::NotFound: return "NOT_FOUND";
        case ProfileStatus::Blocked: return "BLOCKED (CLOUDFLARE/WAF)";
        case ProfileStatus::RateLimited: return "RATE_LIMITED";
        case ProfileStatus::CaptchaTriggered: return "CAPTCHA_TRIGGERED";
    }
    return "UNKNOWN";
}

void AnalyzerEngine::worker_job(const std::string& username, const std::string& platform) {
    std::stringstream thread_id_ss;
    thread_id_ss << std::this_thread::get_id();
    std::string tid = thread_id_ss.str();

    if (!SecurityUtils::validate_input(username)) {
        logger.bad("[Thread " + tid + "] SECURITY WARNING: Aborted processing malformed target: \"" + username + "\"");
        return;
    }

    logger.info("[Thread " + tid + "] Enforcing rate limit policy for platform: " + platform);
    limiter.acquire(platform);

    // Fetch proxy details from the client
    std::string proxy = http_client.get_proxy();
    if (!proxy.empty()) {
        logger.good("[Thread " + tid + "] Routing request via SOCKS5 proxy: socks5h://" + proxy + " (DNS resolved on proxy)");
    } else {
        logger.info("[Thread " + tid + "] Routing request directly (No proxy configured)");
    }

    logger.info("[Thread " + tid + "] Querying HTTP profile structures for user: " + username);
    std::string raw_profile = http_client.fetch_profile_raw(username, platform);

    ProfileStatus status = Detectors::detect_profile_status(raw_profile, platform);
    
    auto parsed_opt = ProfileParser::parse_raw_text(raw_profile, platform);
    if (!parsed_opt.has_value()) {
        logger.warning("[Thread " + tid + "] Failed to parse raw profile on platform: " + platform);
        return;
    }

    UserProfile profile = parsed_opt.value();

    logger.good("[Thread " + tid + "] Platform: " + platform + " | Target: " + profile.email 
                + " | Detected Status: " + status_to_string(status));

    std::vector<LeakRecord> leaks;

    if (status == ProfileStatus::Exists) {
        logger.info("[Thread " + tid + "] Querying simulated threat databases for normalized target: " + profile.email);
        leaks = ThreatFeedSimulator::query_leak_db(profile.email);
    } else {
        logger.warning("[Thread " + tid + "] Defensive bypass: Skipping threat database check for protected/blocked profile: " + profile.email);
    }

    AnalysisResult result;
    result.profile = profile;
    result.status = status;
    result.exposures = leaks;

    results_store.insert(result);
}

void AnalyzerEngine::run_analysis_parallel(const std::vector<std::pair<std::string, std::string>>& raw_inputs) {
    std::vector<std::thread> workers;

    logger.info("Initiating parallel query pool for " + std::to_string(raw_inputs.size()) + " records.");

    for (const auto& input : raw_inputs) {
        workers.emplace_back(&AnalyzerEngine::worker_job, this, input.first, input.second);
    }

    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    logger.good("Thread synchronization complete. Storage container updated.");
}

} // namespace leak_analyzer
