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
package edu.mit.ll.pace.authentication;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Class that handles hashing.
 */
public class Hash {

  private static final String HASH_ALGORITHM = "SHA-256";

  private static final MessageDigest DIGEST;
  static {
    try {
      DIGEST = MessageDigest.getInstance(HASH_ALGORITHM);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Could not create digest function: " + HASH_ALGORITHM, e);
    }
  }

  /**
   * Computes a SHA-256 nodeHash
   *
   * @param data
   *          The data to nodeHash
   * @return The SHA-256 nodeHash of the input
   */
  protected synchronized static byte[] hash(byte[]... data) {
    for (byte[] dataItem : data) {
      DIGEST.reset();
      DIGEST.update(dataItem);
    }
    return DIGEST.digest();
  }

}
