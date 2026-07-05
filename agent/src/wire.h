#pragma once

#include <string>
#include <vector>
#include "json.hpp"

namespace nagomio_wire {

// Seal a plaintext body with ChaCha20-Poly1305. The key is derived from
// `psk` via HKDF-SHA256(info=ctx); the nonce is random. The 16-byte tag is
// returned separately.
void seal(const std::string& psk, const std::string& ctx,
          const std::vector<unsigned char>& plain,
          std::vector<unsigned char>& nonce,
          std::vector<unsigned char>& ct,
          std::vector<unsigned char>& tag);

// Open a sealed body. Returns false on tag mismatch.
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