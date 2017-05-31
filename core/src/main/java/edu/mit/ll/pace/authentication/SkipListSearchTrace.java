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

import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedList;

import org.apache.accumulo.core.data.Key;

/**
 * An object encapsulating the result and proof material from searching a SkipList for a given element.
 */
class SkipListSearchTrace implements Iterable<TraceItem> {

  private SkipListNode foundNode; // Tracks the item that was found: either the result or the anterior node
  private final Deque<TraceItem> trace; // Nodes visited when searching.
  private boolean success;

  /**
   * Finalize the query result by checking for success and modifying TraceItem types as necessary.
   *
   * @param searchKey
   *          The key that was searched for.
   */
  void finalize(Key searchKey) {
    for (TraceItem item : this) {
      if (item.type == TraceItem.Type.FOUND_NODE) {
        if (item.node.compareTo(searchKey) == 0) {
          item.setResult();
          foundNode = item.node;
          success = true;
        } else {
          item.setAnterior();
        }
        return;
      }
    }
  }

  /**
   * Adds the provided node to the list of visited nodes
   *
   * @param node
   *          The node to add to the list of visited nodes
   */
  void pushVisitedNode(SkipListNode node, TraceItem.Type type) {
    trace.push(new TraceItem(node, type, node.isPlateau()));
  }

  /**
   * Returns whether or not the query found the desired elements
   *
   * @return True if the range query found a result; false otherwise
   */
  boolean success() {
    return success;
  }

  /**
   * Returns the result of the search
   *
   * @return The node found as a result of the SkipList search
   */
  SkipListNode getFound() {
    return foundNode;
  }

  /**
   * Remove and return the top element of the trace
   *
   * @return The top element of the trace
   */
  TraceItem pop() {
    return trace.removeFirst();
  }

  /**
   * Accessor method for trace
   *
   * @return The list of visited nodes
   */
  @Override
  public Iterator<TraceItem> iterator() {
    return trace.iterator();
  }

  /**
   * Default constructor
   */
  SkipListSearchTrace() {
    this.trace = new LinkedList<>();
    success = false;
  }
}
