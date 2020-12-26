#pragma once

#ifndef SMTP_HPP_
#define SMTP_HPP_

#include "smtp.h"

#include <istream>
#include <stdexcept>
#include <string>

namespace smtp_cpp {
class exception : public std::exception {
public:
  exception(enum smtp_status_code status_code) : status_code_(status_code) {}

  const char *what() const throw() {
    return smtp_status_code_errstr(status_code_);
  }

private:
  enum smtp_status_code status_code_;
};

class client {
private:
  class headers {
  public:
    headers(client &client) : client_(client) {}

    void add(const std::string &key, const std::string &value) {
      client_.status_code_ =
          smtp_header_add(client_.smtp_, key.c_str(), value.c_str());
      client_.throw_bad_status_code();
    }

    void clear() { smtp_header_clear_all(client_.smtp_); }

  private:
    client &client_;
  };

  class addresses {
  public:
    addresses(client &client) : client_(client) {}

    void add(smtp_address_type type, const std::string &email,
             const std::string &name) {
      client_.status_code_ =
          smtp_address_add(client_.smtp_, type, email.c_str(), name.c_str());
      client_.throw_bad_status_code();
    }

    void clear() { smtp_address_clear_all(client_.smtp_); }

  private:
    client &client_;
  };

  class attachments {
  public:
    attachments(client &client) : client_(client) {}

    void add(const std::string &name, const std::string &path) {
      client_.status_code_ =
          smtp_attachment_add_path(client_.smtp_, name.c_str(), path.c_str());
      client_.throw_bad_status_code();
    }

    void add(const std::string &name, std::istream &stream) {
#ifdef __cpp_rvalue_references
      add(name, std::forward<std::istream>(stream));
    }

    void add(const std::string &name, std::istream &&stream) {
#endif
      stream.seekg(0, std::ios_base::end);
      auto size = stream.tellg();
      stream.seekg(0);
      std::string buffer(static_cast<size_t>(size), '\0');
      stream.read(&buffer[0], static_cast<std::streamsize>(size));
      client_.status_code_ = smtp_attachment_add_mem(
          client_.smtp_, name.c_str(), &buffer[0], size);
      client_.throw_bad_status_code();
    }

    void add(const std::string &name, FILE *fp) {
      client_.status_code_ =
          smtp_attachment_add_fp(client_.smtp_, name.c_str(), fp);
      client_.throw_bad_status_code();
    }

    void add(const std::string &name, const void *data, size_t size) {
      client_.status_code_ =
          smtp_attachment_add_mem(client_.smtp_, name.c_str(), data, size);
      client_.throw_bad_status_code();
    }

    void clear() { smtp_attachment_clear_all(client_.smtp_); }

  private:
    client &client_;
  };

public:
  friend class headers;

  client()
      : headers(*this), addresses(*this), attachments(*this), smtp_(nullptr) {}
  ~client() {
    if (smtp_)
      smtp_close(smtp_);
  }

  void open(const std::string &server, const std::string &port,
            enum smtp_connection_security connection_security,
            enum smtp_flag flags, const std::string &cafile = std::string()) {
    status_code_ =
        smtp_open(server.c_str(), port.c_str(), connection_security, flags,
                  cafile.empty() ? nullptr : cafile.c_str(), &smtp_);
    throw_bad_status_code();
  }

  void auth(enum smtp_authentication_method auth_method,
            const std::string &user, const std::string &password) {
    status_code_ =
        smtp_auth(smtp_, auth_method, user.c_str(), password.c_str());
    throw_bad_status_code();
  }

  void mail(const std::string &body) {
    status_code_ = smtp_mail(smtp_, body.c_str());
    throw_bad_status_code();
  }

  void close() {
    status_code_ = smtp_close(smtp_);
    throw_bad_status_code();
    smtp_ = nullptr;
  }

  int status_code_get() { return smtp_status_code_get(smtp_); }

  void status_code_set(enum smtp_status_code new_status_code) {
    status_code_ = smtp_status_code_set(smtp_, new_status_code);
    throw_bad_status_code();
  }

  void throw_bad_status_code() {
    if (this->status_code_ != SMTP_STATUS_OK)
      throw exception(status_code_);
  }

  class headers headers;
  class addresses addresses;
  class attachments attachments;

private:
  smtp_status_code status_code_;
  struct smtp *smtp_;
};
} // namespace smtp_cpp

#endif // SMTP_HPP_
