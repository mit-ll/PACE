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

import java.util.Collection;

import edu.mit.ll.pace.IllegalKeyRequestException;

/**
 * Interface defining operations that must be supported by a key container for it to work with this module.
 */
public interface EncryptionKeyContainer {

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
  Collection<EncryptionKey> getKeys(String id, int length) throws IllegalKeyRequestException;

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
  EncryptionKey getKey(String id, int length) throws IllegalKeyRequestException;

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
  EncryptionKey getKey(String id, int version, int length) throws IllegalKeyRequestException;

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
  EncryptionKey getAttributeKey(String attribute, String id, int length) throws IllegalKeyRequestException;

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
  EncryptionKey getAttributeKey(String attribute, String id, int version, int length) throws IllegalKeyRequestException;

}
