#include <HardwareSerial.h>
#include "Hasher.h"

Hasher::Hasher(hash_algo_t algorithm) {
  _hashInfo = mbedtls_md_info_from_type((mbedtls_md_type_t) algorithm);
  _hashLen = (size_t) _hashInfo->size;

  mbedtls_md_init(&_ctx);
}

Hasher::~Hasher() {
  if (_hash != NULL) {
    mbedtls_md_free(&_ctx);
    delete[] _hash;
  }

  _hashInfo = nullptr;
}


size_t Hasher::write(const uint8_t *buffer, size_t size) {
  if (!_started && !begin())
    return 0;

  return mbedtls_md_update(&_ctx, buffer, size) == 0 ? size : 0;
}

size_t Hasher::write(uint8_t data) {
  return write(&data, 1);
}

bool Hasher::begin() {
  if (_started)
    return false;

  if (_hash == NULL) {
    if (mbedtls_md_setup(&_ctx, _hashInfo, false) != 0)
      goto error;

    _hash = new uint8_t[_hashLen];
    if (_hash == NULL)
      goto error;
  }

  memset(_hash, 0x00, _hashLen);

  if (mbedtls_md_starts(&_ctx) != 0)
    goto error;

  _started = true;
  return true;

error:
  mbedtls_md_free(&_ctx);

  if (!_hash)
    delete[] _hash;

  return false;
}

void Hasher::end() {
  if (!_started)
    return;

  mbedtls_md_finish(&_ctx, _hash);
  _started = false;
}