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

import static edu.mit.ll.pace.authentication.Hash.hash;

import java.util.Arrays;
import java.util.Objects;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;

/**
 * An element of a SkipList, containing the key and the hash of the value.
 */
final class SkipListElement {
  final Key key;
  final byte[] hash;

  public SkipListElement(Key key, byte[] hash) {
    this.key = key;
    this.hash = hash;
  }

  public SkipListElement(Key key, Value value) {
    this(key, hash(value.get()));
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof SkipListElement)) {
      return false;
    }
    SkipListElement other = (SkipListElement) obj;
    return key.equals(other.key) && Arrays.equals(hash, other.hash);
  }

  @Override
  public int hashCode() {
    return Objects.hash(key, hash);
  }

  @Override
  public String toString() {
    return String.format("{key: %s, hash: %s}", key.toString(), Arrays.toString(hash));
  }
}
