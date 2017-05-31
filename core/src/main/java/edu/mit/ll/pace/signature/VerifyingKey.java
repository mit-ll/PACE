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
package edu.mit.ll.pace.signature;

import static com.google.common.base.Preconditions.checkArgument;

import java.security.PublicKey;
import java.util.Objects;

/**
 * Signing key with metadata.
 */
public final class VerifyingKey {

  /**
   * Private key.
   */
  public final PublicKey value;

  /**
   * When the key started to be valid.
   */
  public final Long startValidity;

  /**
   * When the key stopped being valid.
   */
  public final Long endValidity;

  /**
   * Constructor.
   *
   * @param value
   *          Public key.
   * @param startValidity
   *          When the key started to be valid, or null for no start validity.
   * @param endValidity
   *          When the key stopped being valid, or null for no end validity.
   */
  public VerifyingKey(PublicKey value, Long startValidity, Long endValidity) {
    checkArgument(value != null, "key is null");
    checkArgument(startValidity == null || endValidity == null || endValidity >= startValidity, "end validity cannot come before start validity");

    this.value = value;
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
    return Objects.hash(value, startValidity, endValidity);
  }

  @Override
  public boolean equals(Object obj) {
    if (null == obj || !(obj instanceof VerifyingKey)) {
      return false;
    }

    VerifyingKey other = (VerifyingKey) obj;
    return value.equals(other.value) && Objects.equals(startValidity, other.startValidity) && Objects.equals(endValidity, other.endValidity);
  }

}
