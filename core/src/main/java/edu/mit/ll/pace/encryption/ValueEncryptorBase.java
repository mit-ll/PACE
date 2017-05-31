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

import java.io.IOException;

/**
 * Defines the contract for classes that supports symmetric encryption and decryption of data.
 */
abstract class ValueEncryptorBase {

  /**
   * Encrypt the given data with the given key.
   *
   * @param key
   *          Key to encrypt with.
   * @param data
   *          Data to encrypt.
   * @return The encrypted data, encoded with any metadata needed to decrypt the data.
   * @throws EncryptionException
   *           Thrown if an error happens during encryption.
   * @throws IOException
   *           Not actually thrown.
   */
  abstract byte[] encrypt(byte[] key, byte[] data) throws EncryptionException, IOException;

  /**
   * Decrypt the given data with the given key.
   *
   * @param key
   *          Key to decrypt with.
   * @param data
   *          Data to decrypt, including the encoded metadata needed to decrypt the data.
   * @return The decrypted data.
   * @throws EncryptionException
   *           Thrown if an error happens during encryption
   * @throws IOException
   *           Not actually thrown.
   */
  abstract byte[] decrypt(byte[] key, byte[] data) throws EncryptionException, IOException;

}
