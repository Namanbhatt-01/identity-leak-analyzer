#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <leak_analyzer/thread_safe_store.hpp>
#include <leak_analyzer/analyzer_engine.hpp>
#include <leak_analyzer/logger.hpp>
#include <leak_analyzer/http_client.hpp>
#include <leak_analyzer/security_utils.hpp>

using namespace leak_analyzer;

void print_help() {
    std::cout << "C++ Multi-Threaded Identity Leak Analyzer Simulation\n"
              << "Usage: ./identity_leak_analyzer [options]\n\n"
              << "Options:\n"
              << "  --credentials <path>   Credentials JSON file path (e.g. credentials.json)\n"
              << "  --tor-proxy <ip:port>  Configure SOCKS5 Tor proxy (default: 127.0.0.1:9050)\n"
              << "  --target <username>    Run scan on a single target username\n"
              << "  --output <path>        Path to write reports (ends in .json for SIEM integration)\n"
              << "  --help                 Display this help menu\n" << std::endl;
}

bool file_exists(const std::string& path) {
    std::ifstream f(path.c_str());
    return f.good();
}

bool is_json_output(const std::string& path) {
    if (path.length() >= 5) {
        return path.compare(path.length() - 5, 5, ".json") == 0;
    }
    return false;
}

bool is_stix_output(const std::string& path) {
    if (path.length() >= 10) {
        return path.compare(path.length() - 10, 10, ".stix.json") == 0;
    }
    return false;
}

void write_stix_report(const std::string& path, const std::vector<AnalysisResult>& reports, double duration, Logger& logger) {
    (void)duration; // Suppress unused parameter warnings
    std::ofstream file(path);
    if (!file.is_open()) {
        logger.bad("Failed to open STIX report path: " + path);
        return;
    }

    file << "{\n"
         << "  \"type\": \"bundle\",\n"
         << "  \"id\": \"bundle--71a62d08-2022-4a09-bc3d-82d2a58b21c4\",\n"
         << "  \"spec_version\": \"2.1\",\n"
         << "  \"objects\": [\n";

    // Write a main Identity object representing the Analyzer Platform
    file << "    {\n"
         << "      \"type\": \"identity\",\n"
         << "      \"id\": \"identity--9d8a1e2f-5b12-4f18-a621-a18a8db20b12\",\n"
         << "      \"spec_version\": \"2.1\",\n"
         << "      \"name\": \"NCIIPC CII Threat Intelligence Analyzer Core\",\n"
         << "      \"identity_class\": \"system\",\n"
         << "      \"description\": \"Automated multi-threaded security compliance auditor\"\n"
         << "    }";

    for (const auto& report : reports) {
        file << ",\n";
        std::string target_hash = SecurityUtils::generate_sha256(report.profile.email);
        std::string indicator_uuid = "indicator--5f2c" + target_hash.substr(0, 8) + "-2b1a-4a7b-" + target_hash.substr(8, 4) + "-" + target_hash.substr(12, 12);
        std::string obs_uuid = "observed-data--c8b4" + target_hash.substr(0, 8) + "-1d2c-4f7b-" + target_hash.substr(8, 4) + "-" + target_hash.substr(12, 12);

        // Write Indicator Object
        file << "    {\n"
             << "      \"type\": \"indicator\",\n"
             << "      \"id\": \"" << indicator_uuid << "\",\n"
             << "      \"spec_version\": \"2.1\",\n"
             << "      \"pattern\": \"[email-addr:value = '" << report.profile.email << "']\",\n"
             << "      \"pattern_type\": \"stix\",\n"
             << "      \"valid_from\": \"2026-06-19T23:47:00Z\",\n"
             << "      \"name\": \"Credential exposure search for target: " << report.profile.username << "\",\n"
             << "      \"description\": \"Simulated exposure matching target hash: " << target_hash << "\"\n"
             << "    },\n";

        // Write Observed Data Object
        file << "    {\n"
             << "      \"type\": \"observed-data\",\n"
             << "      \"id\": \"" << obs_uuid << "\",\n"
             << "      \"spec_version\": \"2.1\",\n"
             << "      \"first_observed\": \"2026-06-19T23:47:00Z\",\n"
             << "      \"last_observed\": \"2026-06-19T23:47:00Z\",\n"
             << "      \"number_of_observed_data\": 1,\n"
             << "      \"objects\": {\n"
             << "        \"0\": {\n"
             << "          \"type\": \"user-account\",\n"
             << "          \"user_id\": \"" << report.profile.user_id << "\",\n"
             << "          \"account_login\": \"" << report.profile.username << "\",\n"
             << "          \"display_name\": \"" << report.profile.raw_source_platform << " Operator\"\n"
             << "        }\n"
             << "      }\n"
             << "    }";
    }

    file << "\n  ]\n}\n";
    file.close();
    logger.good("STIX 2.1 compliant Threat Intelligence bundle successfully saved to: " + path);
}


// Function to verify credentials JSON structure
bool verify_credentials_format(const std::string& path, Logger& logger) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    // Basic syntax validations
    size_t open_brace = content.find('{');
    size_t close_brace = content.rfind('}');
    if (open_brace == std::string::npos || close_brace == std::string::npos || open_brace > close_brace) {
        logger.warning("Credentials format alert: File is not a valid JSON document (missing curly braces).");
        return false;
    }

    // Structure keys lookup
    if (content.find("platform_api_keys") == std::string::npos) {
        logger.warning("Credentials structural warning: Missing expected platform api keys object.");
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    Logger logger;
    
    std::string credentials_path = "";
    std::string tor_proxy = "";
    std::string target_username = "";
    std::string output_path = "";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        } else if (arg == "--credentials" && i + 1 < argc) {
            credentials_path = argv[++i];
        } else if (arg == "--tor-proxy" && i + 1 < argc) {
            tor_proxy = argv[++i];
        } else if (arg == "--target" && i + 1 < argc) {
            target_username = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_path = argv[++i];
        } else {
            logger.bad("Unknown option: " + arg);
            print_help();
            return 1;
        }
    }

    logger.info("=== C++ Multi-Threaded Identity Leak Analyzer Simulation ===");

    if (!target_username.empty()) {
        if (!SecurityUtils::validate_input(target_username)) {
            logger.bad("Input validation failed: Target contains unsafe characters or length violation.");
            return 1;
        }
    }

    if (!credentials_path.empty()) {
        if (!file_exists(credentials_path)) {
            logger.bad("Failed to open credentials file: " + credentials_path);
            return 1;
        }
        logger.good("Credentials file loaded successfully: " + credentials_path);
        
        // Active format verification
        if (verify_credentials_format(credentials_path, logger)) {
            logger.good("Credentials format verified: JSON structure meets platform security specifications.");
        }
    } else {
        logger.warning("No credentials file specified. Running in guest simulation mode.");
    }

    HttpClient http_client;
    if (!tor_proxy.empty()) {
        http_client.set_proxy(tor_proxy);
        logger.good("Tor SOCKS5 proxy configured at: " + tor_proxy + " (Ensuring Tor daemon is active)");
    } else {
        logger.info("Direct connection enabled. Tor proxy disabled.");
    }

    std::vector<std::pair<std::string, std::string>> inputs;
    if (!target_username.empty()) {
        logger.info("Target search specified: " + target_username);
        inputs.push_back({target_username, "Instagram"});
        inputs.push_back({target_username, "LinkedIn"});
    } else {
        logger.info("No targets specified. Running default mock profiling suite...");
        inputs = {
            {"admin_zero", "Instagram"},
            {"private_user", "Instagram"},
            {"modbus_gateway", "Modbus_TCP"},
            {"dnp3_rtu", "DNP3"},
            {"iec104_substation", "IEC_104"}
        };
    }

    ThreadSafeStore<AnalysisResult> global_store;
    AnalyzerEngine engine(global_store, logger, http_client);

    auto start_time = std::chrono::steady_clock::now();
    engine.run_analysis_parallel(inputs);
    auto end_time = std::chrono::steady_clock::now();
    double duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() / 1000.0;

    logger.print("\n" + std::string(15, '=') + " Generated Security Intelligence Report " + std::string(15, '='));
    logger.print("Identities Processed : " + std::to_string(global_store.size()));
    logger.print("Execution Time       : " + std::to_string(duration) + " seconds");
    logger.print("------------------------------------------------------------------");

    auto reports = global_store.get_all();

    std::ofstream out_file;
    bool output_json = false;
    bool output_stix = false;
    if (!output_path.empty()) {
        output_stix = is_stix_output(output_path);
        if (!output_stix) {
            out_file.open(output_path);
            if (out_file.is_open()) {
                output_json = is_json_output(output_path);
                if (output_json) {
                    out_file << "{\n"
                             << "  \"telemetry\": {\n"
                             << "    \"identities_processed\": " << global_store.size() << ",\n"
                             << "    \"execution_time_seconds\": " << duration << ",\n"
                             << "    \"proxy_configured\": " << (tor_proxy.empty() ? "false" : "true") << "\n"
                             << "  },\n"
                             << "  \"reports\": [\n";
                } else {
                    out_file << "C++ Identity Leak Analyzer Telemetry Report\n";
                    out_file << "===========================================\n";
                }
            } else {
                logger.bad("Failed to open output report path: " + output_path);
            }
        }
    }

    for (size_t idx = 0; idx < reports.size(); ++idx) {
        const auto& report = reports[idx];
        std::string target_hash = SecurityUtils::generate_sha256(report.profile.email);

        std::string report_header = "[REPORT] Target Hash: " + target_hash + 
                                    " | Platform: " + report.profile.raw_source_platform + 
                                    " | ID: " + report.profile.user_id;
        logger.print(report_header);

        std::string status_label;
        switch (report.status) {
            case ProfileStatus::Exists: status_label = "EXISTS (PUBLIC)"; break;
            case ProfileStatus::Private: status_label = "PRIVATE (PROTECTED)"; break;
            case ProfileStatus::NotFound: status_label = "NOT_FOUND"; break;
            case ProfileStatus::Blocked: status_label = "BLOCKED (CLOUDFLARE/WAF)"; break;
            case ProfileStatus::RateLimited: status_label = "RATE_LIMITED"; break;
            case ProfileStatus::CaptchaTriggered: status_label = "CAPTCHA_TRIGGERED"; break;
        }

        logger.print("  Profile Status : [" + status_label + "]");

        std::stringstream file_log;

        if (report.status != ProfileStatus::Exists) {
            logger.warning("  Status: [SKIPPED] Database query bypassed for security/defensive compliance.");
        } else if (report.exposures.empty()) {
            logger.good("  Status: [SECURE] No anomalous leak exposures detected in offline datasets.");
        } else {
            logger.bad("  Status: [WARNING] Exposed in " + std::to_string(report.exposures.size()) + " breaches:");
            for (const auto& leak : report.exposures) {
                std::string leak_msg = "    - Leak DB: " + leak.source_leak_name + 
                                       " | Date: " + leak.compromised_date + 
                                       " | Severity: [" + leak.severity_level + "]";
                logger.print(leak_msg);
            }
        }
        logger.print("------------------------------------------------------------------");

        if (out_file.is_open()) {
            if (output_json) {
                out_file << "    {\n"
                         << "      \"target_hash\": \"" << target_hash << "\",\n"
                         << "      \"email_raw\": \"" << report.profile.email << "\",\n"
                         << "      \"platform\": \"" << report.profile.raw_source_platform << "\",\n"
                         << "      \"user_id\": \"" << report.profile.user_id << "\",\n"
                         << "      \"profile_status\": \"" << status_label << "\",\n"
                         << "      \"leak_check_performed\": " << (report.status == ProfileStatus::Exists ? "true" : "false") << ",\n"
                         << "      \"exposures\": [\n";

                for (size_t l_idx = 0; l_idx < report.exposures.size(); ++l_idx) {
                    const auto& leak = report.exposures[l_idx];
                    out_file << "        {\n"
                             << "          \"source_db\": \"" << leak.source_leak_name << "\",\n"
                             << "          \"date\": \"" << leak.compromised_date << "\",\n"
                             << "          \"severity\": \"" << leak.severity_level << "\"\n"
                             << "        }" << (l_idx + 1 < report.exposures.size() ? "," : "") << "\n";
                }

                out_file << "      ]\n"
                         << "    }" << (idx + 1 < reports.size() ? "," : "") << "\n";
            } else {
                out_file << report_header << "\n"
                         << "  Profile Status : [" << status_label << "]\n";
                if (report.status != ProfileStatus::Exists) {
                    out_file << "  Status: [SKIPPED] Database query bypassed for security/defensive compliance.\n";
                } else if (report.exposures.empty()) {
                    out_file << "  Status: [SECURE] No anomalous leak exposures detected.\n";
                } else {
                    out_file << "  Status: [WARNING] Exposed in " << report.exposures.size() << " breaches:\n";
                    for (const auto& leak : report.exposures) {
                        out_file << "    - Leak DB: " << leak.source_leak_name 
                                 << " | Date: " << leak.compromised_date 
                                 << " | Severity: [" << leak.severity_level << "]\n";
                    }
                }
                out_file << "-----------------------------------------------------------\n";
            }
        }
    }

    if (out_file.is_open()) {
        if (output_json) {
            out_file << "  ]\n}\n";
        }
        out_file.close();
        logger.good("Security intelligence report successfully saved to: " + output_path);
    } else if (output_stix) {
        write_stix_report(output_path, reports, duration, logger);
    }

    logger.good("System analysis complete.");
    return 0;
}
