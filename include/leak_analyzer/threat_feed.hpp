#ifndef THREAT_FEED_HPP
#define THREAT_FEED_HPP

#include <string>
#include <vector>

namespace leak_analyzer {

struct LeakRecord {
    std::string identity;
    std::string source_leak_name;
    std::string compromised_date;
    std::string severity_level;
    bool is_verified;
};

class ThreatFeedSimulator {
public:
    static std::vector<LeakRecord> query_leak_db(const std::string& target_identity);
};

} // namespace leak_analyzer

#endif // THREAT_FEED_HPP
