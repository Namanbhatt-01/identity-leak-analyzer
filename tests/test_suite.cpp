#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <cassert>
#include <chrono>
#include <leak_analyzer/thread_safe_store.hpp>
#include <leak_analyzer/security_utils.hpp>
#include <leak_analyzer/rate_limiter.hpp>
#include <leak_analyzer/detectors.hpp>
#include <leak_analyzer/profile_parser.hpp>

using namespace leak_analyzer;

// Simple testing runner macros
#define RUN_TEST(test_func) \
    do { \
        std::cout << "\033[1;34m[RUNNING]\033[0m " << #test_func << "..." << std::endl; \
        try { \
            test_func(); \
            std::cout << "\033[1;32m[PASSED]\033[0m  " << #test_func << std::endl; \
        } catch (const std::exception& e) { \
            std::cerr << "\033[1;31m[FAILED]\033[0m  " << #test_func << " (Exception: " << e.what() << ")" << std::endl; \
            std::exit(1); \
        } catch (...) { \
            std::cerr << "\033[1;31m[FAILED]\033[0m  " << #test_func << " (Unknown Exception)" << std::endl; \
            std::exit(1); \
        } \
    } while (0)

// Test 1: SecurityUtils input validation and SHA-256 generation
void test_security_utils() {
    // Input validation
    assert(SecurityUtils::validate_input("valid_user123"));
    assert(SecurityUtils::validate_input("test.user@domain.com"));
    assert(SecurityUtils::validate_input("user_name-here"));
    
    assert(!SecurityUtils::validate_input("")); // Empty input
    assert(!SecurityUtils::validate_input("user; rm -rf")); // Shell injection character
    assert(!SecurityUtils::validate_input("user|grep admin")); // Pipe character
    assert(!SecurityUtils::validate_input("user space")); // Spaces rejected
    assert(!SecurityUtils::validate_input(std::string(101, 'a'))); // Too long (>100 characters)

    // SHA-256 output verification for empty string and "hello"
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::string hash_empty = SecurityUtils::generate_sha256("");
    assert(hash_empty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    std::string hash_hello = SecurityUtils::generate_sha256("hello");
    assert(hash_hello == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

// Test 2: ProfileParser semicolon format parsing and normalization
void test_profile_parser() {
    std::string raw = "user:john_doe; id: 8901; email: John.Doe@Email.COM; tag: active; tag: verified";
    auto parsed_opt = ProfileParser::parse_raw_text(raw, "Instagram");
    
    assert(parsed_opt.has_value());
    UserProfile profile = parsed_opt.value();
    
    assert(profile.username == "john_doe");
    assert(profile.user_id == "8901");
    assert(profile.email == "john.doe@email.com"); // Email should be lowercased (normalized)
    assert(profile.raw_source_platform == "Instagram");
    assert(profile.metadata_tags.size() == 2);
    assert(profile.metadata_tags[0] == "active");
    assert(profile.metadata_tags[1] == "verified");

    // Test missing email (should fail parsing)
    std::string invalid_raw = "user:bad_user; id: 1111; tag: active";
    auto parsed_invalid = ProfileParser::parse_raw_text(invalid_raw, "Instagram");
    assert(!parsed_invalid.has_value());
}

// Test 3: Detectors profile statuses signatures
void test_detectors() {
    // Blocked Cloudflare check
    std::string cloudflare_body = "Error 1020: Access Denied. Cloudflare protection active.";
    assert(Detectors::detect_blocking(cloudflare_body));
    assert(Detectors::detect_profile_status(cloudflare_body, "Instagram") == ProfileStatus::Blocked);

    // Private profile check
    std::string private_body_ig = "this account is private to followers only";
    assert(Detectors::detect_profile_status(private_body_ig, "Instagram") == ProfileStatus::Private);

    std::string private_body_li = "sign in to view the full profile details";
    assert(Detectors::detect_profile_status(private_body_li, "LinkedIn") == ProfileStatus::Private);

    // Not Found status check
    std::string notfound_ig = "sorry, this page isn't available";
    assert(Detectors::detect_profile_status(notfound_ig, "Instagram") == ProfileStatus::NotFound);

    // Default status Exists
    std::string regular_body = "user:normal; id:12; email:normal@test.com;";
    assert(Detectors::detect_profile_status(regular_body, "Twitter") == ProfileStatus::Exists);
}

// Test 4: ThreadSafeStore concurrent insertions validation
void test_thread_safe_store() {
    ThreadSafeStore<int> store;
    
    std::vector<std::thread> threads;
    const int thread_count = 10;
    const int insertions_per_thread = 100;

    for (int i = 0; i < thread_count; ++i) {
        threads.emplace_back([&store]() {
            for (int j = 0; j < insertions_per_thread; ++j) {
                store.insert(j);
            }
        });
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    assert(store.size() == static_cast<size_t>(thread_count * insertions_per_thread));
    
    auto items = store.get_all();
    assert(items.size() == static_cast<size_t>(thread_count * insertions_per_thread));
    
    store.clear();
    assert(store.size() == 0);
}

// Test 5: RateLimiter acquire delays enforcement
void test_rate_limiter() {
    RateLimiter limiter;
    
    // Set a very short rate limit for test speed (capacity 1, refill 1 token per 50ms)
    limiter.set_limit("TestPlatform", 1, 50);
    
    auto start = std::chrono::steady_clock::now();
    limiter.acquire("TestPlatform"); // First request registers timestamp
    limiter.acquire("TestPlatform"); // Second request triggers at least 50ms wait
    auto end = std::chrono::steady_clock::now();
    
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    assert(elapsed >= 50);
}

int main() {
    std::cout << "\033[1;36m==================================================\033[0m" << std::endl;
    std::cout << "\033[1;36m   STARTING LEAK ANALYZER LIBRARY TEST SUITE      \033[0m" << std::endl;
    std::cout << "\033[1;36m==================================================\033[0m" << std::endl;

    RUN_TEST(test_security_utils);
    RUN_TEST(test_profile_parser);
    RUN_TEST(test_detectors);
    RUN_TEST(test_thread_safe_store);
    RUN_TEST(test_rate_limiter);

    std::cout << "\033[1;36m==================================================\033[0m" << std::endl;
    std::cout << "\033[1;32m      ALL TESTS COMPLETED SUCCESSFULLY!           \033[0m" << std::endl;
    std::cout << "\033[1;36m==================================================\033[0m" << std::endl;

    return 0;
}
