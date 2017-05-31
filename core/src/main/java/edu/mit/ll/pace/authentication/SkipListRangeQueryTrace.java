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
import org.apache.commons.collections.CollectionUtils;

import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedList;

/**
 * An object encapsulating the result and proof material from performing a range query on a SkipList.
 */
public class SkipListRangeQueryTrace implements Iterable<TraceItem> {

  private final SkipListSearchTrace trace; // Nodes visited when searching.
  private Deque<SkipListNode> foundNodes; // Nodes found within the specified range

  /**
   * Finalize the range query result by checking for success and modifying TraceItem types as necessary.
   *
   * @param minKey
   *          The lower boundary of the range searched
   * @param maxKey
   *          The upper boundary of the range searched
   */
  void finalize(Key minKey, Key maxKey) {
    foundNodes = new LinkedList<>();
    for (TraceItem item : this) {
      if (item.type == TraceItem.Type.RESULT) {
        foundNodes.add(item.node);
      }
    }
  }

  /**
   * Add a TraceItem to the stack containing the given node and type
   *
   * @param node
   *          The node to add
   * @param type
   *          The type of the TraceItem
   */
  void pushVisitedNode(SkipListNode node, TraceItem.Type type) {
    trace.pushVisitedNode(node, type);
  }

  /**
   * Returns whether or not the query found any elements within the given range
   *
   * @return True if the range query found results; false otherwise
   */
  boolean success() {
    return !CollectionUtils.isEmpty(foundNodes);
  }

  /**
   * Returns the query results
   *
   * @return A list of nodes found within the provided range
   */
  Deque<SkipListNode> getFound() {
    return foundNodes;
  }

  /**
   * Initialize a new RangeQueryTrace from a SearchTrace, removing the last TraceItem which is a boundary node representing the right neighbor of the minKey of
   * our new RangeQueryTrace.
   *
   * @param trace
   *          The SearchTrace for the minKey of this RangeQuery
   */
  SkipListRangeQueryTrace(SkipListSearchTrace trace) {
    trace.pop();
    this.trace = trace;

  }

  @Override
  public Iterator<TraceItem> iterator() {
    return trace.iterator();
  }

}
