#include <openssl/md5.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip> // For std::hex and std::setw

// Function to compute MD5 hash of a string
std::string calculateMD5(const std::string& input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), digest);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return ss.str();
}

int main() {
    std::string data = "Hello, MD5!";
    std::string md5Hash = calculateMD5(data);
    std::cout << "MD5 hash of \"" << data << "\": " << md5Hash << std::endl;
    return 0;
}