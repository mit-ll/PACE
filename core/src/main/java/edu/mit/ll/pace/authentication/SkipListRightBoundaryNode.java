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

import org.apache.accumulo.core.data.Key;

import edu.mit.ll.pace.internal.Utils;

/**
 * Node representing an element at the right boundary.
 */
final class SkipListRightBoundaryNode extends SkipListNode {

  private static final SkipListElement RIGHT_BOUNDARY_ELEMENT = new SkipListElement(null, Utils.EMPTY);
  private static final byte[] EMPTY_HASH = hash(new byte[0]);

  SkipListRightBoundaryNode() {
    super(RIGHT_BOUNDARY_ELEMENT);
  }

  SkipListRightBoundaryNode(SkipListRightBoundaryNode child) {
    super(child);
  }

  @Override
  void updateLabel() {}

  @Override
  byte[] getLabel() {
    return EMPTY_HASH;
  }

  @Override
  public int compareTo(Key other) {
    return 1;
  }

  @Override
  protected String toString(boolean includeNeighbors) {
    if (includeNeighbors) {
      return String.format("{right boundary, hasDown: %s}", getDown() != null);
    } else {
      return String.format("{right boundary}");
    }
  }
}
