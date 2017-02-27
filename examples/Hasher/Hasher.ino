#include <Arduino.h>
#include <Hasher.h>

void setup() {
  Serial.begin(115200);
}

void loop() {
  // Create Hasher with SHA1 hashing function
  Hasher hasher(HASH_SHA1);

  // Begin hashing function
  hasher.begin();

  // Write some test data to be hashed
  hasher.print("test data");

  // Arduino Print interface is supported
  hasher.println("some other test data");

  // Finish hashing function and create SHA1 hash
  hasher.end();

  // Print SHA1 hash
  Serial.println(hasher.toString());

  delay(10000);
}
