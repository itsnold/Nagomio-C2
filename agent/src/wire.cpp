// ChaCha20-Poly1305 wire envelope seal/open (B1).
//
// Used to encrypt the bodies of /beacon and /response HTTP exchanges. The
// cipher is sealed to a 12-byte random nonce, an AAD equal to the directional
// context string ("nagomio/agent/v1" or "nagomio/server/v1"), and produces a
// ciphertext + 16-byte Poly1305 tag.
//
// Linux: uses OpenSSL's EVP_chacha20_poly1305() (libcrypto).
// Windows: uses BCrypt's BCRYPT_CHACHA20_POLY1305_ALGORITHM (Win10+).
//
// Key derivation is RFC 5869 HKDF-SHA256 with salt = HashLen zero bytes
// (equivalent to an empty salt) and info = directional context. This matches
// the teamserver (`hkdf` crate with salt=None) and the Linux OpenSSL path.

#include "wire.h"

#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef BCRYPT_ALG_HANDLE_FLAGS
#define BCRYPT_ALG_HANDLE_FLAGS 0
#endif
#ifndef BCRYPT_CHACHA20_POLY1305_ALGORITHM
#define BCRYPT_CHACHA20_POLY1305_ALGORITHM L"CHACHA20_POLY1305"
#endif
#else
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#endif

namespace nagomio_wire {

namespace {

constexpr size_t kKeyBytes = 32;
constexpr size_t kNonceBytes = 12;
constexpr size_t kTagBytes = 16;
constexpr size_t kSha256Bytes = 32;

#ifdef _WIN32
struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgHandle() {
        if (h) BCryptCloseAlgorithmProvider(h, 0);
    }
};

struct HashHandle {
    BCRYPT_HASH_HANDLE h = nullptr;
    ~HashHandle() {
        if (h) BCryptDestroyHash(h);
    }
};

struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() {
        if (h) BCryptDestroyKey(h);
    }
};

// HMAC-SHA256(key, data) via BCrypt.
bool hmac_sha256(const unsigned char* key, ULONG key_len,
                 const unsigned char* data, ULONG data_len,
                 unsigned char out[kSha256Bytes]) {
    AlgHandle alg;
    NTSTATUS s = BCryptOpenAlgorithmProvider(
        &alg.h, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(s)) return false;

    HashHandle hash;
    s = BCryptCreateHash(alg.h, &hash.h, nullptr, 0,
                         const_cast<unsigned char*>(key), key_len, 0);
    if (!BCRYPT_SUCCESS(s)) return false;

    if (data_len > 0) {
        s = BCryptHashData(hash.h, const_cast<unsigned char*>(data), data_len, 0);
        if (!BCRYPT_SUCCESS(s)) return false;
    }

    s = BCryptFinishHash(hash.h, out, kSha256Bytes, 0);
    return BCRYPT_SUCCESS(s);
}

// RFC 5869 HKDF-SHA256. Salt defaults to HashLen zeros when empty (same as
// Rust `Hkdf::new(None, ikm)` and OpenSSL with a 32-byte zero salt).
bool hkdf_sha256_rfc5869(const unsigned char* ikm, size_t ikm_len,
                         const unsigned char* info, size_t info_len,
                         unsigned char okm[kKeyBytes]) {
    unsigned char salt[kSha256Bytes];
    std::memset(salt, 0, sizeof(salt));

    unsigned char prk[kSha256Bytes];
    if (!hmac_sha256(salt, kSha256Bytes, ikm, (ULONG)ikm_len, prk)) {
        return false;
    }

    // Single block expand: T(1) = HMAC(PRK, info || 0x01), L = 32.
    std::vector<unsigned char> expand_input;
    expand_input.reserve(info_len + 1);
    if (info_len > 0) {
        expand_input.insert(expand_input.end(), info, info + info_len);
    }
    expand_input.push_back(0x01);

    return hmac_sha256(prk, kSha256Bytes, expand_input.data(),
                       (ULONG)expand_input.size(), okm);
}

bool bcrypt_aead(bool encrypt,
                 const unsigned char key[kKeyBytes],
                 const std::string& ctx,
                 const unsigned char* nonce, ULONG nonce_len,
                 const unsigned char* input, ULONG input_len,
                 unsigned char* output, ULONG output_len,
                 unsigned char* tag, ULONG tag_len) {
    AlgHandle alg;
    NTSTATUS s = BCryptOpenAlgorithmProvider(
        &alg.h, BCRYPT_CHACHA20_POLY1305_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_FLAGS);
    if (!BCRYPT_SUCCESS(s)) return false;

    KeyHandle key_h;
    s = BCryptGenerateSymmetricKey(
        alg.h, &key_h.h, nullptr, 0,
        const_cast<unsigned char*>(key), kKeyBytes, 0);
    if (!BCRYPT_SUCCESS(s)) return false;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<unsigned char*>(nonce);
    info.cbNonce = nonce_len;
    info.pbTag = tag;
    info.cbTag = tag_len;
    info.pbAuthData = const_cast<unsigned char*>(
        reinterpret_cast<const unsigned char*>(ctx.data()));
    info.cbAuthData = (ULONG)ctx.size();

    ULONG cb_result = 0;
    if (encrypt) {
        s = BCryptEncrypt(key_h.h,
                          const_cast<unsigned char*>(input), input_len,
                          &info,
                          nullptr, 0,
                          output, output_len,
                          &cb_result, 0);
    } else {
        s = BCryptDecrypt(key_h.h,
                          const_cast<unsigned char*>(input), input_len,
                          &info,
                          nullptr, 0,
                          output, output_len,
                          &cb_result, 0);
    }
    return BCRYPT_SUCCESS(s) && cb_result == output_len;
}
#else
// OpenSSL HKDF-SHA256 with HashLen-zero salt (RFC 5869 empty-salt equivalent).
bool hkdf_sha256_rfc5869(const unsigned char* ikm, size_t ikm_len,
                         const unsigned char* info, size_t info_len,
                         unsigned char okm[kKeyBytes]) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) return false;
    bool ok = true;
    if (EVP_PKEY_derive_init(ctx) <= 0) ok = false;
    unsigned char salt[kSha256Bytes];
    std::memset(salt, 0, sizeof(salt));
    if (ok && EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) ok = false;
    if (ok && EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) <= 0) ok = false;
    if (ok && EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_len) <= 0) ok = false;
    if (ok && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) <= 0) ok = false;
    }
    size_t outlen = kKeyBytes;
    if (ok && EVP_PKEY_derive(ctx, okm, &outlen) <= 0) ok = false;
    if (ok && outlen != kKeyBytes) ok = false;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}
#endif

bool fill_random(unsigned char* buf, size_t len) {
#ifdef _WIN32
    AlgHandle rng;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&rng.h, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(s)) return false;
    s = BCryptGenRandom(rng.h, buf, (ULONG)len, 0);
    return BCRYPT_SUCCESS(s);
#else
    return RAND_bytes(buf, (int)len) == 1;
#endif
}

bool aead_seal(const unsigned char key[kKeyBytes],
               const std::string& ctx,
               const unsigned char* nonce,
               const unsigned char* plain, size_t plain_len,
               unsigned char* ct,
               unsigned char* tag) {
#ifdef _WIN32
    return bcrypt_aead(true, key, ctx, nonce, (ULONG)kNonceBytes,
                       plain, (ULONG)plain_len, ct, (ULONG)plain_len,
                       tag, (ULONG)kTagBytes);
#else
    EVP_CIPHER_CTX* cc = EVP_CIPHER_CTX_new();
    if (!cc) return false;
    bool ok = true;
    if (EVP_EncryptInit_ex(cc, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
        ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_SET_IVLEN, (int)kNonceBytes, nullptr) != 1)
        ok = false;
    if (ok && EVP_EncryptInit_ex(cc, nullptr, nullptr, key, nonce) != 1) ok = false;
    int outl = 0;
    if (ok && EVP_EncryptUpdate(cc, nullptr, &outl,
                                reinterpret_cast<const unsigned char*>(ctx.data()),
                                (int)ctx.size()) != 1)
        ok = false;
    int written = 0;
    if (ok && EVP_EncryptUpdate(cc, ct, &outl, plain, (int)plain_len) != 1) ok = false;
    written = outl;
    if (ok && EVP_EncryptFinal_ex(cc, ct + written, &outl) != 1) ok = false;
    written += outl;
    if (ok && (size_t)written != plain_len) ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_GET_TAG, (int)kTagBytes, tag) != 1)
        ok = false;
    EVP_CIPHER_CTX_free(cc);
    return ok;
#endif
}

bool aead_open(const unsigned char key[kKeyBytes],
               const std::string& ctx,
               const unsigned char* nonce,
               const unsigned char* ct, size_t ct_len,
               const unsigned char* tag,
               unsigned char* plain) {
#ifdef _WIN32
    return bcrypt_aead(false, key, ctx, nonce, (ULONG)kNonceBytes,
                       ct, (ULONG)ct_len, plain, (ULONG)ct_len,
                       const_cast<unsigned char*>(tag), (ULONG)kTagBytes);
#else
    EVP_CIPHER_CTX* cc = EVP_CIPHER_CTX_new();
    if (!cc) return false;
    bool ok = true;
    if (EVP_DecryptInit_ex(cc, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
        ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_SET_IVLEN, (int)kNonceBytes, nullptr) != 1)
        ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_SET_TAG, (int)kTagBytes,
                                  const_cast<unsigned char*>(tag)) != 1)
        ok = false;
    if (ok && EVP_DecryptInit_ex(cc, nullptr, nullptr, key, nonce) != 1) ok = false;
    int outl = 0;
    if (ok && EVP_DecryptUpdate(cc, nullptr, &outl,
                                reinterpret_cast<const unsigned char*>(ctx.data()),
                                (int)ctx.size()) != 1)
        ok = false;
    int written = 0;
    if (ok && EVP_DecryptUpdate(cc, plain, &outl, ct, (int)ct_len) != 1) ok = false;
    written = outl;
    if (ok && EVP_DecryptFinal_ex(cc, plain + written, &outl) != 1) ok = false;
    written += outl;
    EVP_CIPHER_CTX_free(cc);
    return ok && (size_t)written == ct_len;
#endif
}

} // namespace

bool derive_key(const std::string& psk, const std::string& ctx,
                std::vector<unsigned char>& out_key) {
    out_key.assign(kKeyBytes, 0);
    return hkdf_sha256_rfc5869(
        reinterpret_cast<const unsigned char*>(psk.data()), psk.size(),
        reinterpret_cast<const unsigned char*>(ctx.data()), ctx.size(),
        out_key.data());
}

bool seal_with_nonce(const std::string& psk, const std::string& ctx,
                     const std::vector<unsigned char>& plain,
                     const std::vector<unsigned char>& nonce,
                     std::vector<unsigned char>& ct,
                     std::vector<unsigned char>& tag) {
    if (nonce.size() != kNonceBytes) return false;
    std::vector<unsigned char> key;
    if (!derive_key(psk, ctx, key)) return false;
    ct.assign(plain.size(), 0);
    tag.assign(kTagBytes, 0);
    return aead_seal(key.data(), ctx, nonce.data(),
                     plain.data(), plain.size(), ct.data(), tag.data());
}

bool seal(const std::string& psk, const std::string& ctx,
          const std::vector<unsigned char>& plain,
          std::vector<unsigned char>& nonce,
          std::vector<unsigned char>& ct,
          std::vector<unsigned char>& tag) {
    nonce.assign(kNonceBytes, 0);
    if (!fill_random(nonce.data(), nonce.size())) return false;
    return seal_with_nonce(psk, ctx, plain, nonce, ct, tag);
}

bool open(const std::string& psk, const std::string& ctx,
          const std::vector<unsigned char>& nonce,
          const std::vector<unsigned char>& ct,
          const std::vector<unsigned char>& tag,
          std::vector<unsigned char>& plain) {
    if (nonce.size() != kNonceBytes || tag.size() != kTagBytes) return false;
    std::vector<unsigned char> key;
    if (!derive_key(psk, ctx, key)) return false;
    plain.assign(ct.size(), 0);
    if (!aead_open(key.data(), ctx, nonce.data(), ct.data(), ct.size(),
                   tag.data(), plain.data())) {
        plain.clear();
        return false;
    }
    return true;
}

// B64 helpers using the standard alphabet.
std::string b64_encode(const std::vector<unsigned char>& v) {
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -6;
    for (auto c : v) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(alpha[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(alpha[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::vector<unsigned char> b64_decode(const std::string& s) {
    static int lookup[256];
    static bool init = false;
    if (!init) {
        for (auto& i : lookup) i = -1;
        for (int i = 0; i < 64; ++i)
            lookup[(unsigned char)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
        init = true;
    }
    std::vector<unsigned char> out;
    int val = 0, bits = -8;
    for (unsigned char c : s) {
        if (c == '=') break;
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        int v = lookup[c];
        if (v < 0) return {};
        val = (val << 6) + v;
        bits += 6;
        if (bits >= 0) {
            out.push_back((unsigned char)((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

std::string encode_envelope(const std::string& ctx,
                            const std::vector<unsigned char>& nonce,
                            const std::vector<unsigned char>& ct,
                            const std::vector<unsigned char>& tag) {
    nlohmann::json j = {
        {"nonce", b64_encode(nonce)},
        {"ct", b64_encode(ct)},
        {"tag", b64_encode(tag)},
        {"ctx", ctx},
    };
    return j.dump();
}

bool try_decode_envelope(const std::string& body, std::string& ctx,
                         std::vector<unsigned char>& nonce,
                         std::vector<unsigned char>& ct,
                         std::vector<unsigned char>& tag) {
    try {
        auto j = nlohmann::json::parse(body);
        if (!j.contains("nonce") || !j.contains("ct") || !j.contains("tag") || !j.contains("ctx")) {
            return false;
        }
        nonce = b64_decode(j["nonce"].get<std::string>());
        ct = b64_decode(j["ct"].get<std::string>());
        tag = b64_decode(j["tag"].get<std::string>());
        ctx = j["ctx"].get<std::string>();
        return !nonce.empty() && !ct.empty() && !tag.empty() && !ctx.empty();
    } catch (...) {
        return false;
    }
}

} // namespace nagomio_wire
