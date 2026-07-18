#pragma once

#include <string>
#include <vector>
#include "json.hpp"

namespace nagomio_wire {

// Derive the 32-byte ChaCha20-Poly1305 key via RFC 5869 HKDF-SHA256
// (salt = HashLen zeros / empty, info = ctx). Returns false on failure.
bool derive_key(const std::string& psk, const std::string& ctx,
                std::vector<unsigned char>& out_key);

// Seal a plaintext body with ChaCha20-Poly1305. The key is derived from
// `psk` via HKDF-SHA256(info=ctx); the nonce is random. Returns false on
// any crypto failure (does not throw).
bool seal(const std::string& psk, const std::string& ctx,
          const std::vector<unsigned char>& plain,
          std::vector<unsigned char>& nonce,
          std::vector<unsigned char>& ct,
          std::vector<unsigned char>& tag);

// Seal with a caller-provided 12-byte nonce (known-answer / interoperability tests).
bool seal_with_nonce(const std::string& psk, const std::string& ctx,
                     const std::vector<unsigned char>& plain,
                     const std::vector<unsigned char>& nonce,
                     std::vector<unsigned char>& ct,
                     std::vector<unsigned char>& tag);

// Open a sealed body. Returns false on tag mismatch or crypto failure.
bool open(const std::string& psk, const std::string& ctx,
          const std::vector<unsigned char>& nonce,
          const std::vector<unsigned char>& ct,
          const std::vector<unsigned char>& tag,
          std::vector<unsigned char>& plain);

std::string b64_encode(const std::vector<unsigned char>& v);
std::vector<unsigned char> b64_decode(const std::string& s);

// JSON envelope helpers. The envelope is a single JSON object:
//   { "nonce": ..., "ct": ..., "tag": ..., "ctx": ... }
// where each field is base64 (nonce/ct/tag) or a string (ctx).
std::string encode_envelope(const std::string& ctx,
                            const std::vector<unsigned char>& nonce,
                            const std::vector<unsigned char>& ct,
                            const std::vector<unsigned char>& tag);

// Returns true if `body` parses as an envelope. Does not authenticate.
bool try_decode_envelope(const std::string& body, std::string& ctx,
                         std::vector<unsigned char>& nonce,
                         std::vector<unsigned char>& ct,
                         std::vector<unsigned char>& tag);

} // namespace nagomio_wire
