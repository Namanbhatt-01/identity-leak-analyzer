#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <string>
#include <mutex>

namespace leak_analyzer {

class Logger {
private:
    std::mutex print_mutex;

    const std::string RESET = "\033[0m";
    const std::string GREEN = "\033[1;32m";
    const std::string RED = "\033[1;31m";
    const std::string YELLOW = "\033[1;33m";
    const std::string BLUE = "\033[1;34m";

public:
    Logger() = default;

    void info(const std::string& msg) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << BLUE << "[*] INFO: " << RESET << msg << std::endl;
    }

    void good(const std::string& msg) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << GREEN << "[+] SUCCESS: " << RESET << msg << std::endl;
    }

    void bad(const std::string& msg) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << RED << "[-] ERROR: " << RESET << msg << std::endl;
    }

    void warning(const std::string& msg) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << YELLOW << "[!] WARNING: " << RESET << msg << std::endl;
    }

    void print(const std::string& msg) {
        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << msg << std::endl;
    }
};

} // namespace leak_analyzer

#endif // LOGGER_HPP
