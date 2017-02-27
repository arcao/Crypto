#ifndef CRYPTO_HMACHASHER_H
#define CRYPTO_HMACHASHER_H

#include "CryptoTypes.h"
#include "AbstractHasher.h"

class HmacHasher : public AbstractHasher {
public:
  HmacHasher(hash_algo_t algorithm);

  ~HmacHasher();

  size_t write(const uint8_t *buffer, size_t size) override;

  size_t write(uint8_t data) override;

  bool begin(const uint8_t *key, size_t keyLen);

  bool begin(const char *key) {
    return begin((uint8_t *) key, strlen(key));
  }

  bool begin(const String &key) {
    return begin((uint8_t *) key.c_str(), key.length());
  }

  void end() override;

  static String hash(hash_algo_t algorithm, const uint8_t *key, size_t keyLen, const uint8_t *data, size_t dataLen) {
    HmacHasher hasher(algorithm);
    if (!hasher.begin(key, keyLen))
      return String();
    hasher.write(data, dataLen);
    hasher.end();
    return hasher.getHashHex();
  }

  static String hashHex(hash_algo_t algorithm, const char *key, const uint8_t *data, size_t dataLen) {
    return hash(algorithm, (uint8_t *) key, strlen(key), data, dataLen);
  }
};


#endif //CRYPTO_HMACHASHER_H
