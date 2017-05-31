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

import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.NoSuchElementException;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * A SkipList class, pre-Accumulo-integration.
 */
class SkipList implements Iterable<SkipListElement> {
  private SkipListLeftBoundaryNode root; // First element of the top level
  private SkipListRightBoundaryNode tail; // Last element of the top level

  /**
   * Constructor
   */
  SkipList() {
    root = new SkipListLeftBoundaryNode();
    tail = new SkipListRightBoundaryNode();
    root.setRight(tail);
    root.updateLabel();
  }

  /**
   * Searches for the largest element less than or equal to elem
   *
   * @param key
   *          The key to search for
   * @return BSkipListResult containing ordered list of visited nodes
   */
  SkipListSearchTrace search(Key key) {
    SkipListSearchTrace result = new SkipListSearchTrace();
    result.pushVisitedNode(root, TraceItem.Type.TRAVERSED);
    result.pushVisitedNode(tail, TraceItem.Type.RIGHT_BOUNDARY);

    // Search through each level, looking for an element that is greater than the key.
    SkipListNode current = root;
    while (current.getDown() != null) {
      current = current.getDown();

      while (true) {
        SkipListNode right = current.getRight();
        int cmp = right.compareTo(key);

        if (cmp <= 0) {
          result.pushVisitedNode(current, TraceItem.Type.TRAVERSED);
          if (current.getDown() != null) {
            result.pushVisitedNode(current.getDown(), TraceItem.Type.DOWN_BOUNDARY);
          }
          current = right;
        } else {
          if (current.getDown() != null) {
            result.pushVisitedNode(current, TraceItem.Type.TRAVERSED);
          } else {
            result.pushVisitedNode(current, TraceItem.Type.FOUND_NODE);
          }
          result.pushVisitedNode(right, TraceItem.Type.RIGHT_BOUNDARY);
          break;
        }
      }
    }

    result.finalize(key);
    return result;
  }

  /**
   * Returns a trace over the SkipList containing the search path to minKey, all elements between minKey and maxKey (inclusive), and the first element greater
   * than maxKey.
   *
   * @param minKey
   *          The lower boundary of the range to search
   * @param maxKey
   *          The upper boundary of the range to search
   * @return A trace over the SkipList containing results and nodes necessary for verification
   */
  SkipListRangeQueryTrace inclusiveRange(Key minKey, Key maxKey) {
    SkipListSearchTrace trace = search(minKey);
    SkipListNode current = trace.getFound();
    SkipListRangeQueryTrace result = new SkipListRangeQueryTrace(trace);

    while (true) {
      SkipListNode right = current.getRight();
      int cmp = right.compareTo(maxKey);

      if (cmp <= 0) {
        result.pushVisitedNode(right, TraceItem.Type.RESULT);
        current = right;
      } else {
        result.pushVisitedNode(right, TraceItem.Type.RIGHT_BOUNDARY);
        break;
      }
    }

    result.finalize(minKey, maxKey);
    return result;
  }

  /**
   * Insert provided element into SkipList
   *
   * @return The SearchTrace to the anterior node if element was inserted; null if it was already in the list
   */
  SkipListSearchTrace insert(SkipListElement element, int height) {
    checkArgument(height > 0, "Tower height must be greater than 0");

    // Ensure element does not already exist in SkipList
    SkipListSearchTrace searchTrace = search(element.key);
    if (searchTrace.success()) {
      return searchTrace;
    }

    // Create the new tower.
    Deque<SkipListNode> newNodes = new LinkedList<>();
    newNodes.add(new SkipListNode(element));
    for (int i = 1; i < height; i++) {
      newNodes.add(new SkipListNode(newNodes.peek()));
    }

    // Iterate over search path, updating tree as we go.
    for (TraceItem item : searchTrace) {
      switch (item.type) {
        case ANTERIOR:
          SkipListNode anterior = item.node;
          while (!newNodes.isEmpty()) {
            appendNode(newNodes.remove(), anterior);

            while (true) {
              if (anterior.getUp() != null) {
                anterior = anterior.getUp();
                break;
              } else {
                anterior = anterior.getLeft();
              }
            }
          }
          item.node.updateLabel();
          break;

        case DOWN_BOUNDARY:
          break; // boundary elements do not need to be updated.

        case TRAVERSED:
          item.node.updateLabel();
          break;

        case RIGHT_BOUNDARY:
          break; // boundary elements do not need to be updated.

        case RESULT:
        default:
          throw new IllegalStateException();
      }
    }

    while (!newNodes.isEmpty()) {
      appendNode(newNodes.pollFirst(), root);
    }

    return searchTrace;
  }

  private void appendNode(SkipListNode newNode, SkipListNode insertPoint) {
    boolean addRow = insertPoint == root;
    if (addRow) {
      addRow();
    }

    newNode.setRight(insertPoint.getRight());
    insertPoint.setRight(newNode);
    newNode.updateLabel();
    insertPoint.updateLabel();

    if (addRow) {
      root.updateLabel();
    }
  }

  /**
   * Add a new top level row to the tree.
   */
  private void addRow() {
    SkipListLeftBoundaryNode newRoot = new SkipListLeftBoundaryNode(root);
    SkipListRightBoundaryNode newTail = new SkipListRightBoundaryNode(tail);
    newRoot.setRight(newTail);

    root = newRoot;
    tail = newTail;
  }

  public byte[] getBasis() {
    return root.getLabel();
  }

  @Override
  public Iterator<SkipListElement> iterator() {
    return new Iterator<SkipListElement>() {
      SkipListNode current;
      {
        current = root;
        while (current.getDown() != null) {
          current = current.getDown();
        }
        current = current.getRight();
      }

      @Override
      public boolean hasNext() {
        return !(current instanceof SkipListRightBoundaryNode);
      }

      @Override
      public SkipListElement next() {
        if (!hasNext()) {
          throw new NoSuchElementException();
        }

        SkipListElement returnValue = current.getElement();
        current = current.getRight();
        return returnValue;
      }
    };
  }
}
