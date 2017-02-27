#include <mbedtls/md.h>
#include "HmacHasher.h"

HmacHasher::HmacHasher(hash_algo_t algorithm) {
  _hashInfo = mbedtls_md_info_from_type((mbedtls_md_type_t) algorithm);
  _hashLen = (size_t) _hashInfo->size;

  mbedtls_md_init(&_ctx);
}

HmacHasher::~HmacHasher() {
  if (_hash != NULL) {
    mbedtls_md_free(&_ctx);
    delete[] _hash;
  }

  _hashInfo = nullptr;
}


size_t HmacHasher::write(const uint8_t *buffer, size_t size) {
  if (!_started)
    return 0;

  mbedtls_md_hmac_update(&_ctx, buffer, size);
  return size;
}

size_t HmacHasher::write(uint8_t data) {
  return write(&data, 1);
}

bool HmacHasher::begin(const uint8_t *key, size_t len) {
  int res;

  if (_started)
    return false;

  if (_hash == NULL) {
    res = mbedtls_md_setup(&_ctx, _hashInfo, 1);
    if (res != 0)
      goto error;

    _hash = new uint8_t[_hashLen];
    if (_hash == NULL)
      goto error;
  }

  memset(_hash, 0x00, _hashLen);

  res = mbedtls_md_hmac_starts(&_ctx, key, len);
  if (res != 0)
    goto error;

  _started = true;
  return true;

error:
  mbedtls_md_free(&_ctx);

  if (_hash == NULL)
    delete[] _hash;

  return false;
}

void HmacHasher::end() {
  if (!_started)
    return;

  mbedtls_md_hmac_finish(&_ctx, _hash);
  _started = false;
}