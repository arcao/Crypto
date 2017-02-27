#ifndef CRYPTO_HASHER_H
#define CRYPTO_HASHER_H

#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include "CryptoTypes.h"

class AbstractHasher : public Print {
protected:
  const mbedtls_md_info_t *_hashInfo;
  mbedtls_md_context_t _ctx;
  bool _started = false;
  uint8_t *_hash = NULL;
  size_t _hashLen = 0;
public:
  virtual void end()= 0;

  void getHash(uint8_t *hash) {
    if (!_hash)
      return;

    end();

    memcpy(hash, _hash, _hashLen);
  }

  inline size_t getHashLen() { return _hashLen; }

  void getHashHex(char *hash) {
    static const char *hexChars = "0123456789abcdef";

    if (!_hash)
      return;

    for (size_t i = 0; i < _hashLen; i++) {
      hash[i * 2] = hexChars[_hash[i] >> 4];
      hash[i * 2 + 1] = hexChars[_hash[i] & 0xf];
    }
  }

  String getHashHex() {
    size_t bufferLen = _hashLen * 2 + 1;
    char buffer[bufferLen];

    memset(buffer, 0x00, sizeof(char) * bufferLen);

    getHashHex(buffer);
    return String(buffer);
  }

  String toString() { return getHashHex(); };
};

#endif //CRYPTO_HASHER_H
