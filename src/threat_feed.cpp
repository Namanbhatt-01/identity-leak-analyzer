#include <leak_analyzer/threat_feed.hpp>
#include <chrono>
#include <thread>
#include <algorithm>

namespace leak_analyzer {

std::vector<LeakRecord> ThreatFeedSimulator::query_leak_db(const std::string& target_identity) {
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    std::vector<LeakRecord> results;

    if (target_identity.find("admin") != std::string::npos || target_identity.find("leak") != std::string::npos) {
        LeakRecord rec1;
        rec1.identity = target_identity;
        rec1.source_leak_name = "MegaDump2024_Database";
        rec1.compromised_date = "2024-03-12";
        rec1.severity_level = "CRITICAL";
        rec1.is_verified = true;
        results.push_back(rec1);

        LeakRecord rec2;
        rec2.identity = target_identity;
        rec2.source_leak_name = "E-Commerce_Shop_Breach";
        rec2.compromised_date = "2022-09-18";
        rec2.severity_level = "HIGH";
        rec2.is_verified = false;
        results.push_back(rec2);
    } 
    else if (target_identity.find("external") != std::string::npos) {
        LeakRecord rec;
        rec.identity = target_identity;
        rec.source_leak_name = "Forum_Boards_Leak";
        rec.compromised_date = "2023-11-05";
        rec.severity_level = "MEDIUM";
        rec.is_verified = true;
        results.push_back(rec);
    }

    return results;
}

} // namespace leak_analyzer
