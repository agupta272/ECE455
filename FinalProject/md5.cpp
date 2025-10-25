// md5.hpp — public domain / CC0
// Pure C++17 implementation of MD5 (RFC 1321) with incremental API.

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <cstring>

class MD5 {
public:
    MD5() { reset(); }

    // Reset to initial state (allows reuse of the same object)
    void reset() {
        // Initialization constants (RFC 1321)
        a_ = 0x67452301u;
        b_ = 0xefcdab89u;
        c_ = 0x98badcfeu;
        d_ = 0x10325476u;
        total_len_ = 0;
        buffer_len_ = 0;
    }

    // Feed arbitrary bytes
    void update(const void* data, std::size_t len) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        total_len_ += len;

        // If there's data in the buffer, try to fill to 64 and transform.
        if (buffer_len_ > 0) {
            std::size_t to_copy = (len < (64 - buffer_len_)) ? len : (64 - buffer_len_);
            std::memcpy(buffer_ + buffer_len_, p, to_copy);
            buffer_len_ += to_copy;
            p += to_copy;
            len -= to_copy;
            if (buffer_len_ == 64) {
                transform(buffer_);
                buffer_len_ = 0;
            }
        }

        // Process full 64-byte chunks directly from input
        while (len >= 64) {
            transform(p);
            p += 64;
            len -= 64;
        }

        // Store remainder
        if (len > 0) {
            std::memcpy(buffer_, p, len);
            buffer_len_ = len;
        }
    }

    // Finalize and return 16-byte digest; object is left ready to be reused
    std::array<uint8_t, 16> finalize() {
        // Message length in bits (little-endian 64-bit)
        uint64_t bit_len = static_cast<uint64_t>(total_len_) * 8ULL;

        // Pad: 0x80 then 0x00* until (len % 64) == 56, then append 64-bit bit_len
        uint8_t pad[128]; // enough for at most two blocks
        std::size_t pad_len = 0;
        pad[pad_len++] = 0x80;

        std::size_t cur_mod = (buffer_len_) % 64;
        std::size_t need_zeroes = (cur_mod <= 56) ? (56 - cur_mod) : (56 + 64 - cur_mod);
        std::memset(pad + pad_len, 0, need_zeroes);
        pad_len += need_zeroes;

        // Append length (little-endian)
        for (int i = 0; i < 8; ++i) {
            pad[pad_len++] = static_cast<uint8_t>((bit_len >> (8 * i)) & 0xFFu);
        }

        // Feed padding
        update(pad, pad_len);

        // Produce digest (little-endian of a_, b_, c_, d_)
        std::array<uint8_t, 16> out{};
        write_le32(out.data() + 0,  a_);
        write_le32(out.data() + 4,  b_);
        write_le32(out.data() + 8,  c_);
        write_le32(out.data() + 12, d_);

        // Prepare for reuse
        reset();
        return out;
    }

    // One-shot helpers
    static std::array<uint8_t,16> digest(const void* data, std::size_t len) {
        MD5 m; m.update(data, len); return m.finalize();
    }
    static std::array<uint8_t,16> digest(const std::string& s) {
        return digest(s.data(), s.size());
    }
    static std::string hex(const std::array<uint8_t,16>& d) {
        static const char* hexd = "0123456789abcdef";
        std::string s; s.resize(32);
        for (int i = 0; i < 16; ++i) {
            s[2*i]   = hexd[(d[i] >> 4) & 0xF];
            s[2*i+1] = hexd[d[i] & 0xF];
        }
        return s;
    }

private:
    // Core transformation on one 512-bit block (64 bytes)
    void transform(const uint8_t block[64]) {
        uint32_t M[16];
        for (int i = 0; i < 16; ++i) {
            M[i] = read_le32(block + 4*i);
        }

        uint32_t A = a_, B = b_, C = c_, D = d_;

        auto F = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); };
        auto G = [](uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); };
        auto H = [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; };
        auto I = [](uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); };

        auto rotl = [](uint32_t v, uint32_t s) { return (v << s) | (v >> (32 - s)); };

        // Per-round shift amounts
        static const uint32_t S[64] = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
        };

        // Constants K[i] = floor(2^32 * abs(sin(i+1)))
        static const uint32_t K[64] = {
            0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
            0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
            0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
            0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
            0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
            0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
            0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
            0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
        };

        for (uint32_t i = 0; i < 64; ++i) {
            uint32_t f, g;
            if (i < 16)       { f = F(B, C, D); g = i; }
            else if (i < 32)  { f = G(B, C, D); g = (5*i + 1) & 15u; }
            else if (i < 48)  { f = H(B, C, D); g = (3*i + 5) & 15u; }
            else              { f = I(B, C, D); g = (7*i)      & 15u; }

            uint32_t tmp = D;
            D = C;
            C = B;
            uint32_t sum = A + f + K[i] + M[g];
            B = B + rotl(sum, S[i]);
            A = tmp;
        }

        a_ += A; b_ += B; c_ += C; d_ += D;
    }

    static uint32_t read_le32(const uint8_t* p) {
        return (uint32_t)p[0]
             | ((uint32_t)p[1] << 8)
             | ((uint32_t)p[2] << 16)
             | ((uint32_t)p[3] << 24);
    }
    static void write_le32(uint8_t* p, uint32_t v) {
        p[0] = (uint8_t)(v & 0xFFu);
        p[1] = (uint8_t)((v >> 8) & 0xFFu);
        p[2] = (uint8_t)((v >> 16) & 0xFFu);
        p[3] = (uint8_t)((v >> 24) & 0xFFu);
    }

    // State
    uint32_t a_, b_, c_, d_;
    uint64_t total_len_;    // total input length in bytes (before padding)
    uint8_t  buffer_[64];   // pending bytes
    std::size_t buffer_len_;
};

// ------------------------
// Optional quick test main
// Define MD5_TEST before compiling this file to run self-tests.
// ------------------------
#ifdef MD5_TEST
#include <iostream>
int main() {
    struct V { const char* s; const char* h; } tv[] = {
        {"", "d41d8cd98f00b204e9800998ecf8427e"},
        {"a", "0cc175b9c0f1b6a831c399e269772661"},
        {"abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
        {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
        {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "57edf4a22be3c955ac49da2e2107b67a"}
    };
    bool ok = true;
    for (auto &t : tv) {
        auto d = MD5::digest(t.s, std::strlen(t.s));
        auto hx = MD5::hex(d);
        std::cout << "\"" << t.s << "\" -> " << hx << (hx == t.h ? "  OK" : "  **MISMATCH**") << "\n";
        if (hx != t.h) ok = false;
    }
    return ok ? 0 : 1;
}
#endif
