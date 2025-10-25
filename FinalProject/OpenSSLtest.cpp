#include <iostream>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <string>

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;

    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, input.c_str(), input.size());
    SHA256_Final(hash, &sha256_ctx);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

int main() {
    std::string text = "Hello, OpenSSL on SLURM!";
    std::string hash = sha256(text);

    std::cout << "Input: " << text << std::endl;
    std::cout << "SHA256: " << hash << std::endl;
    return 0;
}