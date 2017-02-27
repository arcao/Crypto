#include <Arduino.h>
#include <HmacHasher.h>

void setup() {
  Serial.begin(115200);
}

void loop() {
  // Create HMAC Hasher with SHA1 hashing function
  HmacHasher hmacHasher(HASH_SHA1);

  // Begin hashing function with HMAC key
  hmacHasher.begin("test");

  // Write some test data to be hashed
  hmacHasher.print("test data");

  // Arduino Print interface is supported
  hmacHasher.println("some other test data");

  // Finish hashing function and create SHA1 HMAC hash
  hmacHasher.end();

  // Print SHA1 HMAC hash
  Serial.println(hmacHasher.toString());

  delay(10000);
}
