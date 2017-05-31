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

/**
 * A class encapsulating a node, a type signifying how it was discovered during traversal, and its plateau status.
 */
public class TraceItem {
  enum Type {
    ANTERIOR, DOWN_BOUNDARY, FOUND_NODE, RESULT, RIGHT_BOUNDARY, TRAVERSED
  }

  final SkipListNode node;
  Type type;
  boolean isPlateau;

  /**
   * TraceItem constructor
   *
   * @param node
   *          The SkipListNode to encapsulate
   * @param type
   *          The type, signifying how the node was discovered during traversal
   * @param plateau
   *          True if the node is a plateau, false otherwise
   */
  TraceItem(SkipListNode node, Type type, boolean plateau) {
    this.node = node;
    this.type = type;
    this.isPlateau = plateau;
  }

  /**
   * Set the TraceItem's type to RESULT
   */
  void setResult() {
    this.type = Type.RESULT;
  }

  /**
   * Set the TraceItem's type to ANTERIOR
   */
  void setAnterior() {
    this.type = Type.ANTERIOR;
  }
}
