#ifndef HTTP_CLIENT_HPP
#define HTTP_CLIENT_HPP

#include <sstream>
#include <string>

    namespace leak_analyzer {

  class HttpClient {
  private:
    std::string proxy_address;

  public:
    HttpClient() = default;
    explicit HttpClient(std::string proxy) : proxy_address(std::move(proxy)) {}

    void set_proxy(const std::string &proxy) { proxy_address = proxy; }

    std::string get_proxy() const { return proxy_address; }

    std::string fetch_profile_raw(const std::string &username,
                                  const std::string &platform) const {
      std::stringstream ss;
      (void)platform; // Suppress unused compiler warning flags

      if (username == "admin_zero") {
        ss << "user:admin_zero; id:1092; email:admin_zero@company.com; "
              "tag:critical";
      } else if (username == "private_user") {
        ss << "user:private_user; id:4409; email:private_user@email.net; "
              "tag:standard; tag:this account is private";
      } else if (username == "blocked_session") {
        ss << "user:blocked_session; id:9098; email:blocked_user@domain.org; "
              "tag:flagged; tag:cloudflare";
      } else if (username == "notfound_user") {
        ss << "user:notfound_user; id:2291; "
              "email:notfound_user@safe_server.com; tag:external; tag:member "
              "not found";
      } else if (username == "captcha_session") {
        ss << "user:captcha_session; id:3302; "
              "email:captcha_user@developer.net; tag:api; tag:captcha";
      } else if (username == "modbus_gateway") {
        ss << "user:modbus_gateway; id:9001; email:operator@powertrans.gov.in; tag:critical; tag:unauthorized_write; fc:5; register:40001";
      } else if (username == "dnp3_rtu") {
        ss << "user:dnp3_rtu; id:9002; email:telecom_admin@bsnl.nic.in; tag:critical; tag:analog_change; outstation:10";
      } else if (username == "iec104_substation") {
        ss << "user:iec104_substation; id:9003; email:sysadmin@gridcontrol.in; tag:critical; tag:spurious_command; asdu:36";
      } else {
        ss << "user:" << username << "; id:7701; email:" << username
           << "@generic_domain.net; tag:external";
      }

      return ss.str();
    }
  };

} // namespace leak_analyzer

#endif // HTTP_CLIENT_HPP
