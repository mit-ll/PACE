/*
 * Copyright 2016 MIT Lincoln Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.mit.ll.pace.encryption;

import java.util.Arrays;

import javax.crypto.IllegalBlockSizeException;

import org.cryptomator.siv.SivMode;
import org.cryptomator.siv.UnauthenticCiphertextException;

/**
 * Defines the contract for classes that supports symmetric encryption and decryption of data.
 */
final class DeterministicSIVValueEncryptor extends ValueEncryptorBase {

  /**
   * SIV cipher to use.
   */
  private final SivMode siv;

  /**
   * Creates an SIV encryptor to use for deterministic encryption.
   */
  DeterministicSIVValueEncryptor() {
    siv = new SivMode();
  }

  @Override
  byte[] encrypt(byte[] key, byte[] data) {
    // The key passed here contains both the AES and IV generation keys.
    byte[] encKey = Arrays.copyOfRange(key, 0, key.length / 2);
    byte[] macKey = Arrays.copyOfRange(key, key.length / 2, key.length);

    return siv.encrypt(encKey, macKey, data);
  }

  @Override
  byte[] decrypt(byte[] key, byte[] data) {
    // The key passed here contains both the AES and IV generation keys.
    byte[] encKey = Arrays.copyOfRange(key, 0, key.length / 2);
    byte[] macKey = Arrays.copyOfRange(key, key.length / 2, key.length);

    try {
      return siv.decrypt(encKey, macKey, data);
    } catch (IllegalBlockSizeException | UnauthenticCiphertextException e) {
      throw new EncryptionException(e);
    }
  }

}
