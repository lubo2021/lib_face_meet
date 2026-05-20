#pragma once

#include <iostream>
#include <vector>

namespace face {namespace meet {

        class AesEncryption {
        public:
            AesEncryption() ;

            AesEncryption(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
                : key(key), iv(iv) {}

            std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext);


            std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext);


            std::vector<unsigned char> set_ciphertext();

            std::vector<unsigned char> get_key() { return key; };
            std::vector<unsigned char> get_iv() { return iv; };
            bool check_authorization();
            //字符串MD5加密并转16进制字符串
            static std::string str_md5_to_ox_str(const std::string& data);

            static int compute_md5(const char* input, unsigned char* output);

            static std::string calculate_md5(const std::string& input);
            
        private:
            std::vector<unsigned char> key;
            std::vector<unsigned char> iv;

            void handle_errors();
            static std::string get_config_dir();
            static std::vector<unsigned char> read_binary_file(const std::string& path);
            static bool write_binary_file(const std::string& path, const std::vector<unsigned char>& data);
        };
    }
}
