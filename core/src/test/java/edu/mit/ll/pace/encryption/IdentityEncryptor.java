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

import java.lang.reflect.Field;
import java.util.Collection;

/**
 * Encryptor that returns data instead of encrypting it.
 */
public class IdentityEncryptor extends ValueEncryptorBase {

  /**
   * Field accesser for {@link EntryEncryptor#encryptors}.
   */
  private static Field encryptorsField;

  /**
   * Field accesser for {@link FieldEncryptor#encryptor}.
   */
  private static Field encryptorField;

  static {
    try {
      encryptorsField = EntryEncryptor.class.getDeclaredField("encryptors");
      encryptorsField.setAccessible(true);

      encryptorField = FieldEncryptor.class.getDeclaredField("encryptor");
      encryptorField.setAccessible(true);
    } catch (NoSuchFieldException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Replace the internal {@link ValueEncryptorBase} for each field encryptor that makes up this entry encryptor.
   * <p>
   * Useful for testing or demoes.
   *
   * @param entryEncryptor
   *          Entry encryptor to modify.
   */
  static void replaceValueEncryptorsWithIdentityFunction(EntryEncryptor entryEncryptor) {
    try {
      @SuppressWarnings("unchecked")
      Collection<FieldEncryptor> fieldEncryptors = (Collection<FieldEncryptor>) encryptorsField.get(entryEncryptor);
      for (FieldEncryptor fieldEncryptor : fieldEncryptors) {
        replaceValueEncryptorWithIdentityFunction(fieldEncryptor);
      }
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Replace field encryptors internal {@link ValueEncryptorBase} to use an identity function instead of actual encryption.
   * <p>
   * Useful for testing or demoes.
   *
   * @param fieldEncryptor
   *          Field encryptor to modify.
   */
  static void replaceValueEncryptorWithIdentityFunction(FieldEncryptor fieldEncryptor) {
    try {
      encryptorField.set(fieldEncryptor, new IdentityEncryptor());
    } catch (IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  byte[] encrypt(byte[] key, byte[] data) {
    return data;
  }

  @Override
  byte[] decrypt(byte[] key, byte[] data) {
    return data;
  }

}
