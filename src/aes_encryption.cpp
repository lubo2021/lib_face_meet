#include "aes_encryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <iomanip>
#include <sstream>
#include <cstring>



namespace face {
    namespace meet {
        //字符串MD5加密并转16进制字符串
        std::string AesEncryption::str_md5_to_ox_str(const std::string& data) {
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx) {
                throw std::runtime_error("Failed to create MD context");
            }
            
            const EVP_MD* md = EVP_md5();
            
            if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("MD5 initialization failed");
            }
            
            if (EVP_DigestUpdate(ctx, data.c_str(), data.size()) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("MD5 update failed");
            }
            
            unsigned char md_value[EVP_MAX_MD_SIZE];
            unsigned int md_len;
            
            if (EVP_DigestFinal_ex(ctx, md_value, &md_len) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("MD5 finalization failed");
            }

            // 释放上下文
            EVP_MD_CTX_free(ctx);
            
            // 转换为十六进制字符串
            std::stringstream ss;
            for (unsigned int i = 0; i < md_len; ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)md_value[i];
            }
            
            return ss.str();
        }

        int AesEncryption::compute_md5(const char* input, unsigned char* output) 
        {
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                return -1;  // 内存分配失败
            }

            const EVP_MD* md = EVP_get_digestbyname("MD5");
            if (md == nullptr) {
                EVP_MD_CTX_free(ctx);
                return -1;  // 获取MD5算法失败
            }

            int result = EVP_DigestInit_ex(ctx, md, nullptr)
                        && EVP_DigestUpdate(ctx, input, strlen(input))
                        && EVP_DigestFinal_ex(ctx, output, nullptr) ? 0 : -1;
            
            EVP_MD_CTX_free(ctx);
            return result;
        }

        std::string AesEncryption::calculate_md5(const std::string& input) {
            unsigned char digest[MD5_DIGEST_LENGTH];
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                // 内存分配失败，处理错误
                return "";
            }

            const EVP_MD* md = EVP_get_digestbyname("MD5");
            if (md == nullptr) {
                EVP_MD_CTX_free(ctx);
                // 获取MD5算法失败，处理错误
                return "";
            }

            if (!EVP_DigestInit_ex(ctx, md, nullptr)
                || !EVP_DigestUpdate(ctx, input.c_str(), input.length())
                || !EVP_DigestFinal_ex(ctx, digest, nullptr)) {
                EVP_MD_CTX_free(ctx);
                // 哈希计算失败，处理错误
                return "";
            }

            EVP_MD_CTX_free(ctx);

            // 将结果转换为十六进制字符串
            std::ostringstream oss;
            for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
            }

            return oss.str();
        }


        void AesEncryption::handle_errors() {
            ERR_print_errors_fp(stderr);
            abort();
        }
        std::vector<unsigned char> AesEncryption::encrypt(const std::vector<unsigned char>& plaintext) {
            std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

            int len;
            int ciphertext_len;

            if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
                handle_errors();
            }

            if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
                handle_errors();
            }
            ciphertext_len = len;

            if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
                handle_errors();
            }
            ciphertext_len += len;

            EVP_CIPHER_CTX_free(ctx);

            ciphertext.resize(ciphertext_len);
            return ciphertext;
        }

        std::vector<unsigned char> AesEncryption::decrypt(const std::vector<unsigned char>& ciphertext) {
            std::vector<unsigned char> plaintext(ciphertext.size());
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

            int len;
            int plaintext_len;

            if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
                handle_errors();
            }

            if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
                handle_errors();
            }
            plaintext_len = len;

            if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
                handle_errors();
            }
            plaintext_len += len;

            EVP_CIPHER_CTX_free(ctx);

            plaintext.resize(plaintext_len);
            return plaintext;
        }

        std::vector<unsigned char> AesEncryption::set_ciphertext()
        {
            std::vector<unsigned char> ciphertext = {};
            // 256 bit key
            std::vector<unsigned char> key(32);
            // 128 bit IV
            std::vector<unsigned char> iv(16);

            if (!RAND_bytes(key.data(), key.size()) || !RAND_bytes(iv.data(), iv.size())) {
                std::cerr << "Error generating random bytes for key and IV" << std::endl;
                return ciphertext;
            }

            //AesEncryption aes(key, iv);
            this->key = key;
            this->iv = iv;
            std::vector<unsigned char> plaintext = { 'a', '#', '2', '4', '3', 'H', 'j', 'j', 'j' };

            ciphertext = encrypt(plaintext);

            return ciphertext;
        }
    }
}