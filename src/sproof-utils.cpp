
#include <sstream>
#include <iomanip>
#include <random>
#include <string>

#include <boost/algorithm/string.hpp>
#include <bitcoin/system/wallet/mnemonic.hpp>
#include <bitcoin/system/wallet/hd_private.hpp>
#include <bitcoin/system/wallet/hd_public.hpp>
#include <bitcoin/system/formats/base_16.hpp>
#include <bitcoin/system/utility/string.hpp>
#include <cryptopp/keccak.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/ecp.h>
#include <sodium.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include "sproof-utils.h"

struct ECDSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
};

typedef struct ECDSA_SIG_st ECDSA_SIG;


namespace sproof {
    namespace utils {

        namespace {

//private functions for this file
            void sha3(const uint8_t *input, size_t input_length, uint8_t *output,
                      uint8_t output_length) {
                if (output_length < CryptoPP::Keccak_256::DIGESTSIZE)
                    return; //throw something?

                CryptoPP::Keccak_256 digest;
                digest.Update(input, input_length);
                digest.Final(output);
            }

            std::vector<uint8_t> sha3(const std::vector<uint8_t> &input) {
                CryptoPP::Keccak_256 digest;
                uint8_t buffer[CryptoPP::Keccak_256::DIGESTSIZE];
                digest.Update(input.data(), input.size());
                digest.Final(buffer);
                return std::vector<uint8_t>(std::begin(buffer), std::end(buffer));
            }

            std::vector<uint8_t> sha3(const std::string &input) {
                return sha3(std::vector<uint8_t>(input.begin(), input.end()));
            }

            sproof::Credentials credentials_from_seed(const std::string &mnemonic) {
                using namespace libbitcoin::system;
                using namespace libbitcoin::system::wallet;

                auto word_list = libbitcoin::system::split(mnemonic, " ", true);
                auto hd_seed = decode_mnemonic(word_list);

                data_chunk seed_chunk(to_chunk(hd_seed));
                hd_private m(seed_chunk, hd_private::testnet);

                hd_private p44h = m.derive_private(44 + hd_first_hardened_key);
                hd_private p60h = p44h.derive_private(60 + hd_first_hardened_key);
                hd_private p0h = p60h.derive_private(0 + hd_first_hardened_key);
                hd_private p01 = p0h.derive_private(0);
                hd_private p02 = p01.derive_private(0);

                //hd_key hd = p02.to_hd_key();
                auto ec_secret = p02.secret();

                ec_scalar scalar{ec_secret};
                ec_compressed public_key_comp;
                ec_uncompressed public_key;
                bool success = secret_to_public(public_key_comp, scalar);
                success = decompress(public_key, public_key_comp);

                std::vector<uint8_t> public_vector{std::begin(public_key) + 1, std::end(public_key)};
                std::string address = public_key_to_address(public_vector);

                std::vector<uint8_t> private_vector{std::begin(ec_secret), std::end(ec_secret)};
                return sproof::Credentials{as_hex_with_prefix(private_vector), as_hex_with_prefix(public_vector),
                                           address, mnemonic};
            }

            template<int amount>
            void get_random_bytes(std::vector<uint8_t> &target) {
                uint8_t buffer[amount];
                randombytes_buf(buffer, amount);
                for (int i = 0; i < amount; i++)
                    target.push_back(buffer[i]);
            }

        }

        void hex_to_bytes(const std::string hex_str, std::vector<uint8_t>& result_vector)
        {
            const std::string hex_string = remove_hex_prefix(hex_str);
            for (unsigned int i = 0; i < hex_string.length(); i += 2) {
                std::string byteString = hex_string.substr(i, 2);
                unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
                result_vector.push_back(byte);
            }
        }

        std::string recover_from_signature(int recid, const Signature& sig, const std::vector<uint8_t>& message)
        {
            EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
            ECDSA_SIG *ecsig = ECDSA_SIG_new();


            BIGNUM *bnr = BN_new();
            BIGNUM *bns = BN_new();

            BN_hex2bn(&bnr, sig.r.c_str());
            BN_hex2bn(&bns, sig.s.c_str());

            ECDSA_SIG_set0(ecsig, bnr, bns);

            BIGNUM *xc = BN_new();
            BIGNUM *yc = BN_new();

            BIGNUM *xxc = BN_new();
            BIGNUM *yyc = BN_new();



            char* bnr_hex = BN_bn2hex(ecsig->r);
            std::cout << "r: " << bnr_hex << std::endl;

            if (!eckey) return 0;

            int ret = 0;
            BN_CTX *ctx = NULL;

            BIGNUM *x = NULL;
            BIGNUM *e = NULL;
            BIGNUM *order = NULL;
            BIGNUM *sor = NULL;
            BIGNUM *eor = NULL;
            BIGNUM *field = NULL;
            EC_POINT *R = NULL;
            EC_POINT *O = NULL;
            EC_POINT *Q = NULL;
            BIGNUM *rr = NULL;
            BIGNUM *zero = NULL;
            int n = 0;
            int i = recid / 2;
            std::string keybuffer(500, 0);
            unsigned char* chrs;
            char* coord_hex;

            const EC_GROUP *group = EC_KEY_get0_group(eckey);
            if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
            BN_CTX_start(ctx);
            order = BN_CTX_get(ctx);
            if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
            x = BN_CTX_get(ctx);
            if (!BN_copy(x, order)) { ret=-1; goto err; }
            if (!BN_mul_word(x, i)) { ret=-1; goto err; }
            if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }

            coord_hex = BN_bn2hex(x);
            std::cout << "x: " << coord_hex << std::endl;

            field = BN_CTX_get(ctx);
            if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
            if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
            if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
            if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
//            if (check)
//            {
//                if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
//                if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
//                if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
//            }
            if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
            n = EC_GROUP_get_degree(group);
            e = BN_CTX_get(ctx);
            if (!BN_bin2bn(message.data(), message.size(), e)) { ret=-1; goto err; }
            if (8*message.size() > n) BN_rshift(e, e, 8-(n & 7));
            zero = BN_CTX_get(ctx);
            if (!BN_zero(zero)) { ret=-1; goto err; }
            if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
            rr = BN_CTX_get(ctx);
            if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
            sor = BN_CTX_get(ctx);
            if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
            eor = BN_CTX_get(ctx);
            if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
            if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }

            EC_POINT_get_affine_coordinates(group, R, xc, yc, ctx);

            if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

            ret = 1;

            chrs = (unsigned char*)keybuffer.data();
            EC_KEY_key2buf(eckey, POINT_CONVERSION_COMPRESSED, &chrs, ctx);
            //EC_POINT_

            std::cout << as_hex(keybuffer) << std::endl;

            EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(eckey), xxc, yyc, ctx);

            coord_hex = BN_bn2hex(xxc);
            std::cout << "QQx: " << coord_hex << std::endl;

            coord_hex = BN_bn2hex(yyc);
            std::cout << "QQy: " << coord_hex << std::endl;

            err:
            if (ctx) {
                BN_CTX_end(ctx);
                BN_CTX_free(ctx);
            }
            if (R != NULL) EC_POINT_free(R);
            if (O != NULL) EC_POINT_free(O);
            if (Q != NULL) EC_POINT_free(Q);

            coord_hex = BN_bn2hex(eor);
            std::string public_key{coord_hex};
            std::cout << "eor: " << coord_hex << std::endl;

            coord_hex = BN_bn2hex(sor);
            public_key += coord_hex;
            std::cout << "sor: " << coord_hex << std::endl;

            return public_key;

        }

//public functions defined in the header file

        bool is_hash(const std::string &input) {
            std::string str = remove_hex_prefix(input);
            const char *cstr = str.c_str();
            while (*cstr != '\0') {
                if ((*cstr >= '0' && *cstr <= '9') || (*cstr >= 'A' && *cstr <= 'F') || (*cstr >= 'a' && *cstr <= 'f')) {
                    cstr++;
                    continue;
                }
                else
                    return false;
            }
            return true;
        }

        std::string as_hex(const std::vector<uint8_t> &bytes) {
            std::ostringstream result;
            result << std::hex;

            for (const auto &byte : bytes)
                result << std::setw(2) << std::setfill('0') << (int) byte;
            return result.str();
        }

        std::string as_hex(const std::string& data) {
            std::vector<uint8_t> vec{data.begin(), data.end()};
            return as_hex(vec);
        }

        std::string as_hex_with_prefix(const std::vector<uint8_t> &bytes) {
            return "0x" + as_hex(bytes);
        }

        std::string remove_hex_prefix(const std::string &hash) {
            if (hash.compare(0, 2, "0x") == 0)
                return hash.substr(2);
            return hash;
        }


        std::string get_hash(const std::vector<uint8_t> &bytes) {
            return as_hex_with_prefix(sha3(bytes));
        }

        std::string get_hash(const std::string &str) {
            return as_hex_with_prefix(sha3(str));
        }

        std::chrono::seconds unix_time() {
            return std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch());
        }

        bool is_time_in_range(std::chrono::seconds valid_from, std::chrono::seconds valid_until) {
            std::chrono::seconds now = unix_time();
            return valid_from < now && valid_until > now;
        }

        std::string get_salt() {
            std::vector<uint8_t> salt(256);
            get_random_bytes<256>(salt);
            return get_hash(salt);
        }


        std::string public_key_to_address(const std::vector<uint8_t> &public_key) {
            auto public_hash = sha3(public_key);
            std::vector<uint8_t> address_vector{public_hash.begin() + 12, public_hash.end()};
            return as_hex_with_prefix(address_vector);
        }


        sproof::Credentials get_credentials() {
            std::vector<uint8_t> buffer(16);
            get_random_bytes<16>(buffer);

            using namespace libbitcoin::system;
            using namespace libbitcoin::system::wallet;

            const data_slice entropy{buffer.data(), buffer.data() + 16};
            const word_list mnemonic_list = create_mnemonic(entropy);
            const std::string mnemonic = boost::algorithm::join(mnemonic_list, " ");

            return credentials_from_seed(mnemonic);
        }

        sproof::Credentials restore_credentials(const std::string &mnemonic) {
            return credentials_from_seed(mnemonic);
        }

        std::string base64_encode(const std::string &in) {

            std::string out;

            int val=0, valb=-6;
            for (uint8_t c : in) {
                val = (val<<8) + c;
                valb += 8;
                while (valb>=0) {
                    out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val>>valb)&0x3F]);
                    valb-=6;
                }
            }
            if (valb>-6) out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val<<8)>>(valb+8))&0x3F]);
            while (out.size()%4) out.push_back('=');
            return out;
        }

        std::string base64_decode(const std::string &in) {

            std::string out;

            std::vector<int> T(256,-1);
            for (int i=0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

            int val=0, valb=-8;
            for (uint8_t c : in) {
                if (T[c] == -1) break;
                val = (val<<6) + T[c];
                valb += 6;
                if (valb>=0) {
                    out.push_back(char((val>>valb)&0xFF));
                    valb-=8;
                }
            }
            return out;
        }

        Signature sign(const std::string &message, const Credentials& credentials) {
            using namespace CryptoPP;

            std::vector<uint8_t> key_vector{};
            hex_to_bytes(credentials.get_private_key(), key_vector);

            ECDSA<ECP, SHA256>::PrivateKey private_key;
            const Integer x{key_vector.data(), key_vector.size()};

            private_key.Initialize( ASN1::secp256k1(), x );

            ArraySource key_source{key_vector.data(), key_vector.size(), true};
            ECDSA<ECP,SHA256>::Signer signer( private_key );

            size_t siglen = signer.MaxSignatureLength();
            std::vector<uint8_t> signature(siglen, 0x00);

            AutoSeededRandomPool prng;
            std::vector<uint8_t> hashed_msg = sha3(message);
            siglen = signer.SignMessage( prng, hashed_msg.data(), hashed_msg.size(), (byte*)&signature[0] );
            signature.resize(siglen);

            std::string sig_hex = as_hex(signature);
            std::cout << sig_hex << " - " << sig_hex.length() << std::endl;

            Signature sig{};
            sig.r = sig_hex.substr(0, 64);
            sig.s = sig_hex.substr(64, 128);
            return sig;
        }

        bool verify(const std::string &message, const Signature &signature, const std::string &public_key_hex) {
            using namespace CryptoPP;

            std::vector<uint8_t> key_vector{};
            hex_to_bytes(public_key_hex, key_vector);

            std::cout << key_vector.size() << std::endl;

            ECP::Point q;
            q.identity = false;
            q.x = Integer{key_vector.data(), key_vector.size() / 2};
            q.y = Integer{key_vector.data() + key_vector.size() / 2, key_vector.size() / 2};


            ECDSA<ECP, SHA256>::PublicKey public_key;
            public_key.Initialize( ASN1::secp256k1(), q );

            ECDSA<ECP, SHA256>::Verifier verifier(public_key);

            std::string sig = signature.r + signature.s;
            std::vector<uint8_t> signature_bytes{};
            hex_to_bytes(sig, signature_bytes);

            std::vector<uint8_t> hashed_msg = sha3(message);

//            for( int i = 0; i < 4; i++ ) {
//                std::string address = recover_from_signature(i, signature, hashed_msg);
//                std::vector<uint8_t> address_vec(address.data(), address.data() + address.length());
//                std::vector<uint8_t> h = sha3(address_vec);
//                std::string s = as_hex_with_prefix(h);
//                std::cout << s << std::endl;
//            }
            return verifier.VerifyMessage( hashed_msg.data(), hashed_msg.size(), signature_bytes.data(), signature_bytes.size() );
        }

        std::string encrypt(const std::string& public_key_hex, const std::string& data) {
            using namespace CryptoPP;

            std::vector<uint8_t> key_vector{};
            hex_to_bytes(public_key_hex, key_vector);

            std::cout << key_vector.size() << std::endl;

            ECP::Point q;
            q.identity = false;
            q.x = Integer{key_vector.data(), key_vector.size() / 2};
            q.y = Integer{key_vector.data() + key_vector.size() / 2, key_vector.size() / 2};

            ECDSA<ECP, SHA256>::PublicKey public_key;
            public_key.Initialize( ASN1::secp256k1(), q );

            ECIES<ECP>::Encryptor encryptor{public_key};

            AutoSeededRandomPool prng;
            std::string es; // encrypted message
            StringSource ss1 (data, true, new PK_EncryptorFilter(prng, encryptor, new StringSink(es) ) );

            std::cout << as_hex(es) << std::endl;

            return base64_encode(es);
        }

        std::string decrypt(const std::string &private_key_hex, const std::string &data) {
            using namespace CryptoPP;

            std::vector<uint8_t> key_vector{};
            hex_to_bytes(private_key_hex, key_vector);

            ECDSA<ECP, SHA256>::PrivateKey private_key;
            const Integer x{key_vector.data(), key_vector.size()};

            private_key.Initialize( ASN1::secp256k1(), x );
            ECIES<ECP>::Decryptor decryptor{private_key};

            std::string base64_decoded = base64_decode(data);

            AutoSeededRandomPool prng;
            std::string decrypted_msg;
            StringSource ss4 (base64_decoded, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(decrypted_msg) ) );

            return decrypted_msg;
        }

        std::pair<std::string, std::string>
        sign_transaction(RawTransaction &transaction, const Credentials &credentials) {
            transaction.sign(credentials.get_private_key());
            std::vector<uint8_t> encoded = transaction.encoded();
            std::string encoded_hash = get_hash(encoded);

            return std::pair<std::string, std::string>(as_hex_with_prefix(encoded), encoded_hash);
        }

    }
}
