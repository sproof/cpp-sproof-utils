#ifndef _SPROOF_CREDENTIALS_H
#define _SPROOF_CREDENTIALS_H


#include <string>

#include <jsoncpp/json/json.h>

namespace sproof
{

class Credentials
{
public:
    Credentials() = default;
    Credentials(std::string  priv, std::string  pub, std::string  address, std::string  seed);
    ~Credentials() = default;


  std::string get_private_key() const;
  std::string get_public_key() const;
  std::string get_address() const;
  std::string get_seed() const;

  void set_seed(const std::string& seed);

  bool operator==(const Credentials& other);

private:
  std::string m_private;
  std::string m_public;
  std::string m_address;
  std::string m_seed;
};

}

#endif
