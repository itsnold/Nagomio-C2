// Known-answer vectors shared with teamserver/src/wire.rs::tests.
// Build: cmake --build ... --target wire_kat && ./wire_kat
//
// Verifies RFC 5869 HKDF-SHA256 + ChaCha20-Poly1305 match the Rust
// teamserver bit-for-bit (Linux OpenSSL path; same source on Windows BCrypt).

#include "wire.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

const char* kPsk = "test-psk-for-wire-vectors";
const char* kPlain = "{\"agent_id\":\"agent-1\",\"hostname\":\"box\"}";
const unsigned char kNonce[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

const char* kKeyAgent =
    "f49485c7a72f33d166b1f56639f35232d3b6c51d36c7f39b79a29436b8f54220";
const char* kKeyServer =
    "de251781fcdaeb2f54088836e77124f6edbe802c19e7bf126c9551ae8c4b7db2";
const char* kCtAgent =
    "a2e08a54a6c8f4c349bb143123855a7b421f6d2e696bca889af377179d43b02b4a7eb1a65a7253";
const char* kTagAgent = "dfdaebf57cdb20a24e950a9d5fdc0327";
const char* kCtServer =
    "189fd8125d10dd6d75902b7cafb5911f0ff8c3f8115bcfa9840031e88d9ed3be025dd8a0231f8d";
const char* kTagServer = "1a2d70a9df0445c5e8d80ff556e3dce4";

std::string to_hex(const std::vector<unsigned char>& v) {
    static const char* hexd = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (auto b : v) {
        out.push_back(hexd[b >> 4]);
        out.push_back(hexd[b & 0xf]);
    }
    return out;
}

int failures = 0;

void expect_eq(const char* name, const std::string& got, const char* want) {
    if (got != want) {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, got.c_str(), want);
        ++failures;
    } else {
        std::printf("ok   %s\n", name);
    }
}

void expect_true(const char* name, bool cond) {
    if (!cond) {
        std::fprintf(stderr, "FAIL %s\n", name);
        ++failures;
    } else {
        std::printf("ok   %s\n", name);
    }
}

} // namespace

int main() {
    std::vector<unsigned char> key;

    expect_true("derive agent key", nagomio_wire::derive_key(kPsk, "nagomio/agent/v1", key));
    expect_eq("hkdf agent", to_hex(key), kKeyAgent);

    expect_true("derive server key", nagomio_wire::derive_key(kPsk, "nagomio/server/v1", key));
    expect_eq("hkdf server", to_hex(key), kKeyServer);

    std::vector<unsigned char> plain(kPlain, kPlain + std::char_traits<char>::length(kPlain));
    std::vector<unsigned char> nonce(kNonce, kNonce + 12);
    std::vector<unsigned char> ct, tag;

    expect_true("seal agent",
                nagomio_wire::seal_with_nonce(kPsk, "nagomio/agent/v1", plain, nonce, ct, tag));
    expect_eq("ct agent", to_hex(ct), kCtAgent);
    expect_eq("tag agent", to_hex(tag), kTagAgent);

    std::vector<unsigned char> opened;
    expect_true("open agent",
                nagomio_wire::open(kPsk, "nagomio/agent/v1", nonce, ct, tag, opened));
    expect_true("plain agent",
                std::string(opened.begin(), opened.end()) == kPlain);

    expect_true("seal server",
                nagomio_wire::seal_with_nonce(kPsk, "nagomio/server/v1", plain, nonce, ct, tag));
    expect_eq("ct server", to_hex(ct), kCtServer);
    expect_eq("tag server", to_hex(tag), kTagServer);

    opened.clear();
    expect_true("open server",
                nagomio_wire::open(kPsk, "nagomio/server/v1", nonce, ct, tag, opened));
    expect_true("plain server",
                std::string(opened.begin(), opened.end()) == kPlain);

    // Mutated ciphertext must fail open without throwing.
    if (!ct.empty()) ct[0] ^= 0x01;
    opened.clear();
    expect_true("reject mutated ct",
                !nagomio_wire::open(kPsk, "nagomio/server/v1", nonce, ct, tag, opened));

    if (failures != 0) {
        std::fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    std::printf("all wire KAT checks passed\n");
    return 0;
}
