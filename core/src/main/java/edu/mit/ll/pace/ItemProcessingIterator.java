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
package edu.mit.ll.pace;

import java.util.Iterator;

/**
 * An iterator that iterates over items both post- and pre- processing.
 * <p>
 * More concretely, {@link #next()} returns the processed entry, and {@link #unprocessed()} returns the unprocessed entry that resulted in the value returned by
 * {@link #next()}.
 *
 * @param <E>
 *          Type parameter.
 */
public interface ItemProcessingIterator<E> extends Iterator<E> {

  /**
   * Get the unprocessed element that returned the next item.
   * <p>
   * Requires that {@link #next()} has been successfully called.
   *
   * @return Returns the next item.
   */
  E unprocessed();

}
