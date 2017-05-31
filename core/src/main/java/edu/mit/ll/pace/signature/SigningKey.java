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

import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * Signing key with metadata.
 */
public final class SigningKey {

  /**
   * Private key.
   */
  public final PrivateKey value;

  /**
   * Id associated with the private key.
   */
  public final byte[] id;

  /**
   * Constructor.
   *
   * @param value
   *          Private key.
   * @param id
   *          Id.
   */
  public SigningKey(PrivateKey value, byte[] id) {
    checkArgument(value != null, "key is null");
    checkArgument(id != null, "id ßis null");
    checkArgument(id.length != 0, "id is empty");

    this.value = value;
    this.id = id;
  }

  @Override
  public int hashCode() {
    return Objects.hash(value, id);
  }

  @Override
  public boolean equals(Object obj) {
    if (null == obj || !(obj instanceof SigningKey)) {
      return false;
    }

    SigningKey other = (SigningKey) obj;
    return value.equals(other.value) && Arrays.equals(id, other.id);
  }

}
