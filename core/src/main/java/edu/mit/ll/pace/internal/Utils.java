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
package edu.mit.ll.pace.internal;

import static com.google.common.base.Preconditions.checkArgument;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Utility functions used by PACE.
 */
public final class Utils {

  /**
   * The empty byte array.
   */
  public static final byte[] EMPTY = new byte[0];

  /**
   * Charset to use when changing column visibility bytes into a String and vice versa.
   */
  public static final Charset VISIBILITY_CHARSET = StandardCharsets.US_ASCII;

  /**
   * Static class.
   */
  private Utils() {}

  /**
   * XOR first and second, storing the result in first.
   *
   * @param first
   *          First argument.
   * @param second
   *          Second argument.
   * @return XOR'ed first argument.
   */
  public static byte[] xor(byte[] first, byte[] second) {
    checkArgument(first != null, "first is null");
    checkArgument(second != null, "second is null");
    checkArgument(first.length == second.length, "first and second must be the same length");

    for (int i = 0; i < first.length; i++) {
      first[i] = (byte) (first[i] ^ second[i]);
    }
    return first;
  }

}
