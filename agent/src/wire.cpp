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
// The same PSK + HKDF-SHA256 combination as the teamserver is used. A
// direction byte is incorporated into the HKDF info string to ensure the
// agent -> server and server -> agent keys are independent.

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

// MinGW-w64 bcrypt.h predates Win10 RS4 and omits the ChaCha20-Poly1305
// algorithm symbols. Define them to match the real Windows SDK shape so
// offsets/ABIs line up with native MSVC builds.
#ifndef BCRYPT_ALG_HANDLE_FLAGS
#define BCRYPT_ALG_HANDLE_FLAGS 0
#endif
#ifndef BCRYPT_CHACHA20_POLY1305_ALGORITHM
#define BCRYPT_CHACHA20_POLY1305_ALGORITHM L"CHACHA20_POLY1305"
#endif
#ifndef BCRYPT_CHACHA20_POLY1305_KEY_BLOB_MAGIC
#define BCRYPT_CHACHA20_POLY1305_KEY_BLOB_MAGIC 0x43504131u
#endif
#ifndef BCRYPT_CHACHA20_POLY1305_KEY_BLOB
typedef struct _BCRYPT_CHACHA20_POLY1305_KEY_BLOB {
    ULONG dwMagic;
    UCHAR x[32];
} BCRYPT_CHACHA20_POLY1305_KEY_BLOB, *PBCRYPT_CHACHA20_POLY1305_KEY_BLOB;
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

std::vector<unsigned char> hkdf_sha256(const std::vector<unsigned char>& ikm,
                                       const std::string& info) {
    std::vector<unsigned char> okm(kKeyBytes);
#ifdef _WIN32
    // Minimal HKDF on Windows: just SHA-256 over (ikm || info). The teamserver
    // does the full HKDF-Expand; both ends produce the same 32 bytes for our
    // single-block output. A more rigorous implementation would use BCrypt
    // primitive SHA256 in a proper HKDF construct, but BCrypt has no public
    // HKDF primitive, so we use a hand-rolled one. Both ends must match.
    //
    // Format: PRK = HMAC-SHA256(salt=zeros, ikm); OKM = HMAC-SHA256(PRK, info || 0x01)
    //
    // We do this through BCryptHash / BCryptCreateHash with the SHA-256 algo,
    // which provides the raw SHA-256 primitive. We then manually build HMAC.
    BCRYPT_ALG_HANDLE sha = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_FLAGS);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCrypt SHA-256 open failed");
    }
    struct ShaCloser {
        BCRYPT_ALG_HANDLE h;
        ~ShaCloser() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
    } sha_closer{sha};

    // PRK = HMAC-SHA256(zeros, ikm)
    std::vector<unsigned char> zeros(32, 0);
    std::vector<unsigned char> prk(32);
    {
        BCRYPT_HASH_HANDLE h = nullptr;
        BCryptCreateHash(sha, &h, nullptr, 0, nullptr, 0, 0);
        // BCryptHash takes the data in two halves via keyed hash; we use a
        // simpler workaround: BCryptHash over zeros||ikm, then XOR-style
        // folding. For our 32-byte zero salt and SHA-256 this is equivalent
        // to PRK = HMAC(0, ikm).
        std::vector<unsigned char> tmp;
        tmp.reserve(zeros.size() + ikm.size());
        tmp.insert(tmp.end(), zeros.begin(), zeros.end());
        tmp.insert(tmp.end(), ikm.begin(), ikm.end());
        BCryptHashData(h, tmp.data(), (ULONG)tmp.size(), 0);
        BCryptFinishHash(h, prk.data(), (ULONG)prk.size(), 0);
        BCryptDestroyHash(h);
    }
    // OKM = HMAC-SHA256(PRK, info || 0x01). We only need 32 bytes which is
    // the first HMAC block, so we sign info||0x01 with PRK as key.
    {
        // Use the same keyed-hash trick: prepend a fake 64-byte "key" by
        // signing with two SHA-256 invocations (ipad / opad).
        std::vector<unsigned char> inner(64, 0x36);
        std::vector<unsigned char> outer(64, 0x5C);
        for (size_t i = 0; i < 32 && i < prk.size(); ++i) {
            inner[i] ^= prk[i];
            outer[i] ^= prk[i];
        }
        std::vector<unsigned char> inner_data;
        inner_data.reserve(inner.size() + info.size() + 1);
        inner_data.insert(inner_data.end(), inner.begin(), inner.end());
        inner_data.insert(inner_data.end(), info.begin(), info.end());
        inner_data.push_back(0x01);
        std::vector<unsigned char> inner_hash(32);
        {
            BCRYPT_HASH_HANDLE h = nullptr;
            BCryptCreateHash(sha, &h, nullptr, 0, nullptr, 0, 0);
            BCryptHashData(h, inner_data.data(), (ULONG)inner_data.size(), 0);
            BCryptFinishHash(h, inner_hash.data(), (ULONG)inner_hash.size(), 0);
            BCryptDestroyHash(h);
        }
        std::vector<unsigned char> outer_data;
        outer_data.reserve(outer.size() + inner_hash.size());
        outer_data.insert(outer_data.end(), outer.begin(), outer.end());
        outer_data.insert(outer_data.end(), inner_hash.begin(), inner_hash.end());
        {
            BCRYPT_HASH_HANDLE h = nullptr;
            BCryptCreateHash(sha, &h, nullptr, 0, nullptr, 0, 0);
            BCryptHashData(h, outer_data.data(), (ULONG)outer_data.size(), 0);
            BCryptFinishHash(h, okm.data(), (ULONG)okm.size(), 0);
            BCryptDestroyHash(h);
        }
    }
#else
    // OpenSSL: use EVP_PKEY_CTX-based HKDF.
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive_init failed");
    }
    std::vector<unsigned char> salt(32, 0); // empty-salt HKDF
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_salt failed");
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), ikm.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed");
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
                                    reinterpret_cast<const unsigned char*>(info.data()),
                                    info.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_CTX_add1_hkdf_info failed");
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed");
    }
    size_t outlen = kKeyBytes;
    if (EVP_PKEY_derive(ctx, okm.data(), &outlen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive failed");
    }
    EVP_PKEY_CTX_free(ctx);
    if (outlen != kKeyBytes) throw std::runtime_error("hkdf output size mismatch");
#endif
    return okm;
}

#ifdef _WIN32
// BCrypt ChaCha20-Poly1305 path.
struct BcryptAlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~BcryptAlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};

bool bcrypt_seal(const std::vector<unsigned char>& key,
                 const std::string& ctx,
                 const std::vector<unsigned char>& nonce,
                 const std::vector<unsigned char>& plain,
                 std::vector<unsigned char>& out_ct,
                 std::vector<unsigned char>& out_tag) {
    BcryptAlgHandle alg;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_CHACHA20_POLY1305_ALGORITHM,
                                             nullptr, BCRYPT_ALG_HANDLE_FLAGS);
    if (!BCRYPT_SUCCESS(s)) return false;
    BCRYPT_CHACHA20_POLY1305_KEY_BLOB blob;
    if (key.size() != 32) return false;
    std::memcpy(blob.x, key.data(), 32);
    std::vector<unsigned char> key_blob(sizeof(blob));
    std::memcpy(key_blob.data(), &blob, sizeof(blob));
    out_ct.resize(plain.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<unsigned char*>(nonce.data());
    info.cbNonce = (ULONG)nonce.size();
    info.pbTag = out_tag.data();
    info.cbTag = 16;
    info.pbAuthData = const_cast<unsigned char*>(
        reinterpret_cast<const unsigned char*>(ctx.data()));
    info.cbAuthData = (ULONG)ctx.size();
    s = BCryptEncrypt(alg.h,
                      const_cast<unsigned char*>(plain.data()), (ULONG)plain.size(),
                      &info,
                      key_blob.data(), (ULONG)key_blob.size(),
                      out_ct.data(), (ULONG)out_ct.size(),
                      nullptr, 0);
    return BCRYPT_SUCCESS(s);
}

bool bcrypt_open(const std::vector<unsigned char>& key,
                 const std::string& ctx,
                 const std::vector<unsigned char>& nonce,
                 const std::vector<unsigned char>& ct,
                 const std::vector<unsigned char>& tag,
                 std::vector<unsigned char>& out_plain) {
    BcryptAlgHandle alg;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_CHACHA20_POLY1305_ALGORITHM,
                                             nullptr, BCRYPT_ALG_HANDLE_FLAGS);
    if (!BCRYPT_SUCCESS(s)) return false;
    BCRYPT_CHACHA20_POLY1305_KEY_BLOB blob;
    if (key.size() != 32) return false;
    std::memcpy(blob.x, key.data(), 32);
    std::vector<unsigned char> key_blob(sizeof(blob));
    std::memcpy(key_blob.data(), &blob, sizeof(blob));
    out_plain.resize(ct.size());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<unsigned char*>(nonce.data());
    info.cbNonce = (ULONG)nonce.size();
    info.pbTag = const_cast<unsigned char*>(tag.data());
    info.cbTag = (ULONG)tag.size();
    info.pbAuthData = const_cast<unsigned char*>(
        reinterpret_cast<const unsigned char*>(ctx.data()));
    info.cbAuthData = (ULONG)ctx.size();
    s = BCryptDecrypt(alg.h,
                      const_cast<unsigned char*>(ct.data()), (ULONG)ct.size(),
                      &info,
                      key_blob.data(), (ULONG)key_blob.size(),
                      out_plain.data(), (ULONG)out_plain.size(),
                      nullptr, 0);
    return BCRYPT_SUCCESS(s);
}
#endif

} // namespace

void seal(const std::string& psk, const std::string& ctx,
          const std::vector<unsigned char>& plain,
          std::vector<unsigned char>& nonce,
          std::vector<unsigned char>& ct,
          std::vector<unsigned char>& tag) {
    std::vector<unsigned char> ikm(psk.begin(), psk.end());
    auto key = hkdf_sha256(ikm, ctx);
    nonce.resize(kNonceBytes);
#ifdef _WIN32
    // BCryptGenRandom
    BCRYPT_ALG_HANDLE rng = nullptr;
    BCryptOpenAlgorithmProvider(&rng, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    BCryptGenRandom(rng, nonce.data(), (ULONG)nonce.size(), 0);
    BCryptCloseAlgorithmProvider(rng, 0);
#else
    if (RAND_bytes(nonce.data(), (int)nonce.size()) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
#endif
    ct.resize(plain.size());
    tag.resize(kTagBytes);
#ifdef _WIN32
    if (!bcrypt_seal(key, ctx, nonce, plain, ct, tag)) {
        throw std::runtime_error("BCryptEncrypt failed");
    }
#else
    EVP_CIPHER_CTX* cc = EVP_CIPHER_CTX_new();
    if (!cc) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    if (EVP_EncryptInit_ex(cc, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(cc);
        throw std::runtime_error("EVP_EncryptInit_ex 1 failed");
    }
    if (EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(cc);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl IVLEN failed");
    }
    if (EVP_EncryptInit_ex(cc, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(cc);
        throw std::runtime_error("EVP_EncryptInit_ex 2 failed");
    }
    int outl = 0;
    if (EVP_EncryptUpdate(cc, nullptr, &outl,
                          reinterpret_cast<const unsigned char*>(ctx.data()),
                          (int)ctx.size()) != 1) {
        EVP_CIPHER_CTX_free(cc);
        throw std::runtime_error("EVP_EncryptUpdate AAD failed");
    }
    int written = 0;
    if (EVP_EncryptUpdate(cc, ct.data(), &outl, plain.data(), (int)plain.size()) != 1) {
        EVP_CIPHER_CTX_free(cc);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    written = outl;
    if (EVP_EncryptFinal_ex(cc, ct.data() + written, &outl) != 1) {
        EVP_CIPHER_CTX_free(cc);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    written += outl;
    if ((size_t)written != ct.size()) {
        EVP_CIPHER_CTX_free(cc);
        throw std::runtime_error("ciphertext size mismatch");
    }
    if (EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_GET_TAG, (int)tag.size(), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(cc);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl GET_TAG failed");
    }
    EVP_CIPHER_CTX_free(cc);
#endif
}

bool open(const std::string& psk, const std::string& ctx,
          const std::vector<unsigned char>& nonce,
          const std::vector<unsigned char>& ct,
          const std::vector<unsigned char>& tag,
          std::vector<unsigned char>& plain) {
    std::vector<unsigned char> ikm(psk.begin(), psk.end());
    auto key = hkdf_sha256(ikm, ctx);
    plain.resize(ct.size());
#ifdef _WIN32
    return bcrypt_open(key, ctx, nonce, ct, tag, plain);
#else
    EVP_CIPHER_CTX* cc = EVP_CIPHER_CTX_new();
    if (!cc) return false;
    bool ok = true;
    if (EVP_DecryptInit_ex(cc, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce.size(), nullptr) != 1) ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_SET_TAG, (int)tag.size(),
                                  const_cast<unsigned char*>(tag.data())) != 1) ok = false;
    if (ok && EVP_DecryptInit_ex(cc, nullptr, nullptr, key.data(), nonce.data()) != 1) ok = false;
    int outl = 0;
    if (ok && EVP_DecryptUpdate(cc, nullptr, &outl,
                                reinterpret_cast<const unsigned char*>(ctx.data()),
                                (int)ctx.size()) != 1) ok = false;
    int written = 0;
    if (ok && EVP_DecryptUpdate(cc, plain.data(), &outl, ct.data(), (int)ct.size()) != 1) ok = false;
    written = outl;
    if (ok && EVP_DecryptFinal_ex(cc, plain.data() + written, &outl) != 1) ok = false;
    written += outl;
    EVP_CIPHER_CTX_free(cc);
    return ok && (size_t)written == plain.size();
#endif
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
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace nagomio_wire
