#ifndef CRYPTO_DEFAULTHASHER_H
#define CRYPTO_DEFAULTHASHER_H

#include "CryptoTypes.h"
#include "AbstractHasher.h"

class Hasher : public AbstractHasher {
private:
  const mbedtls_md_info_t *_hashInfo;
  mbedtls_md_context_t _ctx;
  bool _started = false;
public:
  Hasher(hash_algo_t algorithm);

  ~Hasher();

  size_t write(const uint8_t *buffer, size_t size) override;

  size_t write(uint8_t data) override;

  bool begin();

  void end() override;

  static String hash(hash_algo_t algorithm, const uint8_t *data, size_t size) {
    Hasher hasher(algorithm);
    hasher.begin();
    hasher.write(data, size);
    hasher.end();
    return hasher.getHashHex();
  }
};

#endif //CRYPTO_DEFAULTHASHER_H
