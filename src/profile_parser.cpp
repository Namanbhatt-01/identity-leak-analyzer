#include <leak_analyzer/profile_parser.hpp>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <cctype>

namespace leak_analyzer {

std::optional<UserProfile> ProfileParser::parse_raw_text(const std::string& raw_content, const std::string& platform) {
    std::string username = "unknown";
    std::string user_id = "0";
    std::string email = "";
    std::vector<std::string> tags;

    std::stringstream ss(raw_content);
    std::string item;
    
    while (std::getline(ss, item, ';')) {
        size_t delimiter_pos = item.find(':');
        if (delimiter_pos != std::string::npos) {
            std::string key = item.substr(0, delimiter_pos);
            std::string val = item.substr(delimiter_pos + 1);

            key.erase(std::remove_if(key.begin(), key.end(), [](unsigned char c) { return std::isspace(c); }), key.end());
            val.erase(std::remove_if(val.begin(), val.end(), [](unsigned char c) { return std::isspace(c); }), val.end());

            if (key == "user" || key == "username") {
                username = val;
            } else if (key == "id" || key == "uid") {
                user_id = val;
            } else if (key == "email" || key == "mail") {
                email = normalize_email(val);
            } else if (key == "tag") {
                tags.push_back(val);
            }
        }
    }

    if (email.empty()) {
        return std::nullopt;
    }

    UserProfile profile;
    profile.username = username;
    profile.user_id = user_id;
    profile.email = email;
    profile.raw_source_platform = platform;
    profile.metadata_tags = tags;
    
    return profile;
}

std::string ProfileParser::normalize_email(const std::string& raw_email) {
    std::string normalized = raw_email;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return normalized;
}

} // namespace leak_analyzer
