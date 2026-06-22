#include "aes_encryption.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <sstream>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>
#ifdef _WIN32
#include <direct.h>
#endif


namespace face {
    namespace meet {

        AesEncryption::AesEncryption() 
        {
            key = { 0x12,0x67,0x98,0x02,0x02,0x45,0x28,0x12,
                    0x67,0x98,0x02,0x81,0x19,0x34,0x45,0x02,
                    0x49,0x02,0x45,0x12,0x67,0x98,0x73,0x32,
                    0x02,0x56,0x91,0x02,0x45,0x12,0x67,0x98
                 };

            iv = { 0x98,0x02,0x58,0x45,0x68,0x62,0x81,0x39,
                    0x08,0x35,0x19,0x27,0x01,0x38,0x13,0x57
                };
        }
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
        

        bool AesEncryption::check_authorization()
        {
            std::string config_dir = AesEncryption::get_config_dir();
            std::string first_run_path = config_dir + "first_run.dat";
            std::string last_run_path = config_dir + "last_run.dat";

            std::vector<unsigned char> encrypted_first = AesEncryption::read_binary_file(first_run_path);
            std::vector<unsigned char> encrypted_last = AesEncryption::read_binary_file(last_run_path);
            
           
            std::time_t currentTime = std::time(nullptr);
            std::tm* tm_now = std::localtime(&currentTime);
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm_now);
            std::string currentTimeStr(buf);
#ifdef DISABLE_AUTHORIZATION_CHECK             
            std::string first_plain = "F:" + currentTimeStr;
            std::string last_plain = "L:" + currentTimeStr;
            std::vector<unsigned char> first_data(first_plain.begin(), first_plain.end());
            std::vector<unsigned char> last_data(last_plain.begin(), last_plain.end());
            AesEncryption::write_binary_file(first_run_path, encrypt(first_data));
            AesEncryption::write_binary_file(last_run_path, encrypt(last_data));
            return false;         
#endif
            if (encrypted_first.empty() || encrypted_last.empty())  return false;
            std::vector<unsigned char> decrypted_first = decrypt(encrypted_first);
            std::vector<unsigned char> decrypted_last = decrypt(encrypted_last);

            std::string first_str(decrypted_first.begin(), decrypted_first.end());
            std::string last_str(decrypted_last.begin(), decrypted_last.end());
            if (first_str.size() < 2 || first_str[0] != 'F' || first_str[1] != ':') {
                std::cerr << "Invalid first_run data." << std::endl;
                return false;
            }
            if (last_str.size() < 2 || last_str[0] != 'L' || last_str[1] != ':') {
                std::cerr << "Invalid last_run data." << std::endl;
                return false;
            }
            first_str = first_str.substr(2);  // 去掉 "F:"
            last_str = last_str.substr(2);    // 去掉 "L:"
            std::tm tm_first = {};
            std::tm tm_last = {};
            std::istringstream ss_first(first_str);
            std::istringstream ss_last(last_str);
            ss_first >> std::get_time(&tm_first, "%Y-%m-%dT%H:%M:%S");
            ss_last >> std::get_time(&tm_last, "%Y-%m-%dT%H:%M:%S");

            if (ss_first.fail() || ss_last.fail()) {
                std::cerr << "Failed to parse date strings." << std::endl;
                return false;
            }

            std::time_t firstRun = std::mktime(&tm_first);
            std::time_t lastRun = std::mktime(&tm_last);

            if (currentTime < lastRun) {
                std::cerr << "System time has been rolled back!" << std::endl;
                return false;
            }
 
            if (firstRun == lastRun) {
                double diff_first = std::difftime(currentTime, firstRun);
                long long days_since_first = static_cast<long long>(diff_first) / (60 * 60 * 24);
                if (days_since_first >= 1) {
                    std::cerr << "Trial period has expired." << std::endl;
                    return false;
                }
            }
            double diff_seconds = std::difftime(currentTime, firstRun);
            long long days = static_cast<long long>(diff_seconds) / (60 * 60 * 24);
            if (days > 15) {
                std::cerr << "Trial period has expired." << std::endl;
                return false;
            }
            std::string last_plain_update = "L:" + currentTimeStr;
            std::vector<unsigned char> last_data_update(last_plain_update.begin(), last_plain_update.end());
            AesEncryption::write_binary_file(last_run_path, encrypt(last_data_update));
            return true;

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

        std::string AesEncryption::get_config_dir() {
#ifdef _WIN32
            const char* appdata = std::getenv("APPDATA");
            if (appdata) {
                return std::string(appdata) + "\\mairuide\\";
            }
            return ".\\";
#else
            const char* home = std::getenv("HOME");
            if (home) {
                return std::string(home) + "/.config/mairuide/";
            }
            return "./";
#endif
        }

        std::vector<unsigned char> AesEncryption::read_binary_file(const std::string& path) {
            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                return {};
            }
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            std::vector<unsigned char> buffer(static_cast<size_t>(size));
            if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                return {};
            }
            return buffer;
        }

        bool AesEncryption::write_binary_file(const std::string& path, const std::vector<unsigned char>& data) {
             if (data.empty()) {
                return false;
            }
            std::string dir = path.substr(0, path.find_last_of("/\\"));
            if (!dir.empty()) {
#ifdef _WIN32
                _mkdir(dir.c_str());
#else
                mkdir(dir.c_str(), 0755);
#endif
            }
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!file.is_open()) {
                return false;
            }
            if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
                return false;
            }
            return true;
        }
    }
}