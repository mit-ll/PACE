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

import static com.google.common.base.Preconditions.checkArgument;

import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;

import edu.mit.ll.pace.IllegalKeyRequestException;

/**
 * Interface defining operations that must be supported by a key container for it to work with this module.
 */
public interface EncryptionKeyContainer {

  /**
   * Key with its version.
   */
  final class KeyWithVersion {
    /**
     * Encryption key.
     */
    public final byte[] key;

    /**
     * Version of the key.
     */
    public final int version;

    /**
     * Key with its version.
     *
     * @param key
     *          Key.
     * @param version
     *          Version.
     */
    public KeyWithVersion(byte[] key, int version) {
      checkArgument(key != null, "key is null");
      checkArgument(key.length != 0, "key is empty");
      checkArgument(version >= 0, "version is negative");

      this.key = key;
      this.version = version;
    }

    @Override
    public int hashCode() {
      return Objects.hash(key, version);
    }

    @Override
    public boolean equals(Object obj) {
      if (null == obj || !(obj instanceof KeyWithVersion)) {
        return false;
      }

      KeyWithVersion other = (KeyWithVersion) obj;
      return Arrays.equals(key, other.key) && version == other.version;
    }
  }

  /**
   * Get all the versioned keys for the given id.
   *
   * @param id
   *          Id of the key to retrieve.
   * @param length
   *          Length of the key to return in bits.
   * @return Requested key of the desired length and the version of that key.
   * @throws IllegalKeyRequestException
   *           User lacks the permissions to obtain the desired key.
   */
  Collection<KeyWithVersion> getKeys(String id, int length) throws IllegalKeyRequestException;

  /**
   * Get the key for the given id.
   *
   * @param id
   *          Id of the key to retrieve.
   * @param length
   *          Length of the key to return in bits.
   * @return Requested key of the desired length and the version of that key.
   * @throws IllegalKeyRequestException
   *           User lacks the permissions to obtain the desired key.
   */
  KeyWithVersion getKey(String id, int length) throws IllegalKeyRequestException;

  /**
   * Get the key for the given id and version.
   *
   * @param id
   *          Id of the key to retrieve.
   * @param version
   *          Version of the key to retrieve.
   * @param length
   *          Length of the key to return in bits.
   * @return byte[] with requested key.
   * @throws IllegalKeyRequestException
   *           User lacks the permissions to obtain the desired key.
   */
  byte[] getKey(String id, int version, int length) throws IllegalKeyRequestException;

  /**
   * Get the encryption key for the given attribute.
   *
   * @param attribute
   *          Name of the attribute whose key is being retrieved.
   * @param id
   *          Id of the key to retrieve.
   * @param length
   *          Length of the key to return in bits.
   * @return Requested encryption key of the desired length and the version of those keys.
   * @throws IllegalKeyRequestException
   *           User lacks the permissions to obtain the desired key.
   */
  KeyWithVersion getAttributeKey(String attribute, String id, int length) throws IllegalKeyRequestException;

  /**
   * Get the encryption key for the given attribute.
   *
   * @param attribute
   *          Name of the attribute whose key is being retrieved.
   * @param id
   *          Id of the key to retrieve.
   * @param version
   *          Version of the key to retrieve.
   * @param length
   *          Length of the key to return in bits.
   * @return byte[] with the requested encryption key.
   * @throws IllegalKeyRequestException
   *           User lacks the permissions to obtain the desired key.
   */
  byte[] getAttributeKey(String attribute, String id, int version, int length) throws IllegalKeyRequestException;

}
