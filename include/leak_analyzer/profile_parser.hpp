#ifndef PROFILE_PARSER_HPP
#define PROFILE_PARSER_HPP

#include <string>
#include <vector>
#include <optional>

namespace leak_analyzer {

struct UserProfile {
    std::string username;
    std::string user_id;
    std::string email;
    std::string raw_source_platform;
    std::vector<std::string> metadata_tags;
};

class ProfileParser {
public:
    static std::optional<UserProfile> parse_raw_text(const std::string& raw_content, const std::string& platform);
    static std::string normalize_email(const std::string& raw_email);
};

} // namespace leak_analyzer

#endif // PROFILE_PARSER_HPP
