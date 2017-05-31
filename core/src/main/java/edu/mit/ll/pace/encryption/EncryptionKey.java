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
import java.util.Objects;

/**
 * Encryption key with metadata.
 */
public final class EncryptionKey {

  /**
   * Encryption key.
   */
  public final byte[] value;

  /**
   * Version of the key.
   */
  public final int version;

  /**
   * When the key started to be valid.
   */
  public final Long startValidity;

  /**
   * When the key stopped being valid.
   */
  public final Long endValidity;

  /**
   * Encryption key.
   *
   * @param value
   *          Key.
   */
  public EncryptionKey(byte[] value) {
    this(value, 0, null, null);
  }

  /**
   * Encryption key.
   *
   * @param value
   *          Key.
   * @param version
   *          Version.
   * @param startValidity
   *          When the key started to be valid, or null for no start validity.
   * @param endValidity
   *          When the key stopped being valid, or null for no end validity.
   */
  public EncryptionKey(byte[] value, int version, Long startValidity, Long endValidity) {
    checkArgument(value != null, "key is null");
    checkArgument(value.length != 0, "key is empty");
    checkArgument(version >= 0, "version is negative");
    checkArgument(startValidity == null || endValidity == null || endValidity >= startValidity, "end validity cannot come before start validity");

    this.value = value;
    this.version = version;
    this.startValidity = startValidity;
    this.endValidity = endValidity;
  }

  /**
   * Checks whether this key is valid for the given timestamp.
   *
   * @param timestamp
   *          Timestamp to check against.
   * @return Whether the key is valid at the given timestamp.
   */
  public boolean isValid(long timestamp) {
    if (startValidity != null && timestamp < startValidity) {
      return false;
    } else if (endValidity != null && timestamp > endValidity) {
      return false;
    } else {
      return true;
    }
  }

  @Override
  public int hashCode() {
    return Objects.hash(value, version, startValidity, endValidity);
  }

  @Override
  public boolean equals(Object obj) {
    if (null == obj || !(obj instanceof EncryptionKey)) {
      return false;
    }

    EncryptionKey other = (EncryptionKey) obj;
    return Arrays.equals(value, other.value) && version == other.version && Objects.equals(startValidity, other.startValidity)
        && Objects.equals(endValidity, other.endValidity);
  }
}
