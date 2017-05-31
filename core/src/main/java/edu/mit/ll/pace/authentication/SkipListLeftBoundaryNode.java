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

import org.apache.accumulo.core.data.Key;

import edu.mit.ll.pace.internal.Utils;

/**
 * Node representing an element at the left boundary.
 */
final class SkipListLeftBoundaryNode extends SkipListNode {

  private static final SkipListElement LEFT_BOUNDARY_ELEMENT = new SkipListElement(null, Utils.EMPTY);

  SkipListLeftBoundaryNode() {
    super(LEFT_BOUNDARY_ELEMENT);
  }

  SkipListLeftBoundaryNode(SkipListLeftBoundaryNode child) {
    super(child);
  }

  @Override
  public int compareTo(Key other) {
    return -1;
  }

  @Override
  protected String toString(boolean includeNeighbors) {
    if (includeNeighbors) {
      return String.format("{left boundary, hasDown: %s, right: %s}", getDown() != null, getRight().toString(false));
    } else {
      return String.format("{left boundary}");
    }
  }
}
