

#include <utility>

#include <string>

#include "credentials.h"


namespace sproof {

    Credentials::Credentials(std::string priv, std::string pub, std::string address, std::string seed)
            : m_private{std::move(priv)}, m_public{std::move(pub)}, m_address{std::move(address)},
              m_seed{std::move(seed)} {
    }

    std::string Credentials::get_public_key() const {
        return m_public;
    }

    std::string Credentials::get_private_key() const {
        return m_private;
    }

    std::string Credentials::get_address() const {
        return m_address;
    }

    std::string Credentials::get_seed() const {
        return m_seed;
    }

    void Credentials::set_seed(const std::string &seed) {
        m_seed = seed;
    }

    bool Credentials::operator==(const Credentials& other) {
        return m_seed == other.m_seed &&
                m_address == other.m_address &&
                m_public == other.m_public &&
                m_private == other.m_private;
    }

}
