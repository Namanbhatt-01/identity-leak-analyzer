#ifndef DETECTORS_HPP
#define DETECTORS_HPP

#include <string>
#include <algorithm>
#include <cctype>

namespace leak_analyzer {

enum class ProfileStatus {
    Exists,
    Private,
    NotFound,
    Blocked,
    RateLimited,
    CaptchaTriggered
};

class Detectors {
public:
    Detectors() = default;

    static bool detect_blocking(const std::string& body) {
        std::string lower = to_lowercase(body);
        return lower.find("cloudflare") != std::string::npos ||
               lower.find("forbidden") != std::string::npos ||
               lower.find("access denied") != std::string::npos ||
               lower.find("status:403") != std::string::npos;
    }

    static ProfileStatus detect_profile_status(const std::string& body, const std::string& platform) {
        std::string lower = to_lowercase(body);

        if (detect_blocking(body)) {
            return ProfileStatus::Blocked;
        }

        if (lower.find("status:429") != std::string::npos || lower.find("rate limited") != std::string::npos) {
            return ProfileStatus::RateLimited;
        }

        if (lower.find("captcha") != std::string::npos || lower.find("challenge") != std::string::npos) {
            return ProfileStatus::CaptchaTriggered;
        }

        if (platform == "Instagram") {
            if (lower.find("sorry, this page isn't available") != std::string::npos || lower.find("user not found") != std::string::npos) {
                return ProfileStatus::NotFound;
            }
            if (lower.find("this account is private") != std::string::npos || lower.find("is_private:true") != std::string::npos) {
                return ProfileStatus::Private;
            }
        } 
        else if (platform == "LinkedIn") {
            if (lower.find("member not found") != std::string::npos || lower.find("profile not found") != std::string::npos) {
                return ProfileStatus::NotFound;
            }
            if (lower.find("sign in to view") != std::string::npos || lower.find("private profile") != std::string::npos) {
                return ProfileStatus::Private;
            }
        } 
        else if (platform == "Twitter") {
            if (lower.find("this account doesn't exist") != std::string::npos || lower.find("page doesn't exist") != std::string::npos) {
                return ProfileStatus::NotFound;
            }
            if (lower.find("these tweets are protected") != std::string::npos || lower.find("account is private") != std::string::npos) {
                return ProfileStatus::Private;
            }
        }

        return ProfileStatus::Exists;
    }

private:
    static std::string to_lowercase(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
            return std::tolower(c);
        });
        return lower;
    }
};

} // namespace leak_analyzer

#endif // DETECTORS_HPP
