#include "aes_encryption.h"
#include <random>
#include <algorithm>

using namespace face::meet;


int main() {
    // 256 bit key
    //std::vector<unsigned char> key(32);
    // 128 bit IV
    std::vector<unsigned char> iv(16);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::generate(key.begin(), key.end(), [&]() { return static_cast<unsigned char>(dis(gen)); });
    std::generate(iv.begin(), iv.end(), [&]() { return static_cast<unsigned char>(dis(gen)); });

    AesEncryption aes(key, iv);
    std::string key_str(key.begin(), key.end());
    std::string iv_str(iv.begin(), iv.end());

    std::vector<unsigned char> plaintext = { 'a', '#', '2', '4', '3', 'H', 'j', 'j', 'j' };
    
    std::vector<unsigned char> ciphertext = aes.encrypt(plaintext);
    std::string ciphertext_str(ciphertext.begin(), ciphertext.end());
    std::vector<unsigned char> decrypted = aes.decrypt(ciphertext);

    // 转换 decrypted vector 到 string 以便于显示文本
    std::string decrypted_str(decrypted.begin(), decrypted.end());

    std::cout << "key Text: " << key_str << ",iv Text: " << iv_str << ",ciphertext Text " << ciphertext_str << ",Decrypted Text: " << decrypted_str << std::endl;

    return 0;
}