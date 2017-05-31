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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

import org.apache.accumulo.core.data.Key;

/**
 * A SkipList node encapsulating a KeyValue data element. Each node tracks its neighbors in all four directions.
 */
class SkipListNode {

  private SkipListNode down;
  private SkipListNode right;
  private SkipListNode up;
  private SkipListNode left;

  private SkipListElement element;
  private byte[] label;
  private int height;

  /**
   * Constructor for a new skip list node.
   */
  SkipListNode(SkipListElement element) {
    this.element = element;
    height = 0;
  }

  /**
   * Constructor for an upper-level skip list node.
   *
   * @param child
   *          The child (downward neighbor) of the node to be created.
   */
  SkipListNode(SkipListNode child) {
    element = child.element;

    down = child;
    child.up = this;

    height = child.height + 1;
  }

  final SkipListElement getElement() {
    return element;
  }

  /**
   * Accessor method for fDown
   *
   * @return The node below this node
   */
  final SkipListNode getDown() {
    return down;
  }

  /**
   * Accessor method for fRight
   *
   * @return The node to the right of this node
   */
  final SkipListNode getRight() {
    return right;
  }

  /**
   * Determines if the node is or isn't a plateau node
   *
   * @return true is the node is a plateau; false if it is not the top of its tower
   */
  final boolean isPlateau() {
    return up == null;
  }

  /**
   * Fluent modifier method for fRight
   *
   * @param right
   *          The value to set for fRight
   */
  final void setRight(SkipListNode right) {
    this.right = right;
    right.left = this;
  }

  /**
   * Accessor method for fDown
   *
   * @return The node below this node
   */
  final SkipListNode getUp() {
    return up;
  }

  /**
   * Accessor method for fRight
   *
   * @return The node to the right of this node
   */
  final SkipListNode getLeft() {
    return left;
  }

  /**
   * Accessor method for the node's authentication label
   *
   * @return The node's authentication label
   */
  byte[] getLabel() {
    return label;
  }

  /**
   * Lexicographic comparator
   *
   * @param other
   *          The KeyValue to compare against
   * @return 0 if other is equal to this; a value greater than 0 if other is greater than this; a value less than 0 if other is less than this
   */
  int compareTo(Key other) {
    return element.key.compareTo(other);
  }

  static int compare(SkipListElement first, SkipListElement second) {
    return first.key.compareTo(second.key);
  }

  /**
   * Update the node's label.
   */
  void updateLabel() {
    label = calculateLabel();
  }

  /**
   * Computes and stores the node's label.
   * <p>
   * The label is calculated as follows:
   * <ul>
   * <li>If at the base level:</li>
   * <ul>
   * <li>If the node's right neighbor is a tower, then label = h(element.hash, element.hash of neighbor)</li>
   * <li>If the node's right element is a plateau, then label = h(element.hash, label of neighbor).</li>
   * </ul>
   * <li>If not at the base level:</li>
   * <ul>
   * <li>If the node's right neighbor is a tower, then label = label of next level down.
   * <li>If the node's right element is a plateau, then label = h(label of next level down, label of neighbor).</li>
   * </ul>
   * </ul>
   */
  private byte[] calculateLabel() {
    if (down == null) {
      if (right.isPlateau()) {
        return commutativeHash(element.hash, right.getLabel());
      } else {
        return commutativeHash(element.hash, right.element.hash);
      }
    } else {
      if (right.isPlateau()) {
        return commutativeHash(down.getLabel(), right.getLabel());
      } else {
        return down.getLabel().clone();
      }
    }
  }

  /**
   * Helper function to perform a commutative nodeHash on two inputs (nodeHash(a,b) == nodeHash(b,a)) Appends "larger" array to "smaller" (based on
   * compareTo()), then hashes the result
   *
   * @param first
   *          The first byte[] to nodeHash
   * @param second
   *          The second byte[] to nodeHash
   * @return A commutative nodeHash of the parameters
   */
  private static byte[] commutativeHash(byte[] first, byte[] second) {
    ByteBuffer firstBuf = ByteBuffer.wrap(first);
    ByteBuffer secondBuf = ByteBuffer.wrap(second);

    if (firstBuf.compareTo(secondBuf) <= 0) {
      return hash(first, second);
    } else {
      return hash(second, first);
    }
  }

  public boolean equals(Object o) {
    if (!(o instanceof SkipListNode))
      return false;
    SkipListNode node = (SkipListNode) o;
    return element.equals(node.element) && Arrays.equals(label, node.label);
  }

  @Override
  public int hashCode() {
    return Objects.hash(element, label);
  }

  @Override
  public String toString() {
    return toString(true);
  }

  protected String toString(boolean includeNeighbors) {
    if (includeNeighbors) {
      return String.format("{%s, hasDown: %s, right: %s}", element.key, down != null, right.toString(false));
    } else {
      return String.format("{%s}", element.key);
    }
  }
}
