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

import java.util.Iterator;
import java.util.Map.Entry;
import java.util.NoSuchElementException;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;

import edu.mit.ll.pace.ItemProcessingIterator;

/**
 * Read signed Accumulo entries.
 */
final class SignedInlineScannerIterator implements ItemProcessingIterator<Entry<Key,Value>> {

  /**
   * The iterator with the Accumulo data.
   */
  private final Iterator<Entry<Key,Value>> iterator;

  /**
   * The verifier to use.
   */
  private final EntrySigner verifier;

  /**
   * Keep track of the encrypted entry that resulted in
   */
  private Entry<Key,Value> unprocessedEntry = null;

  /**
   * Read signed Accumulo data.
   * <p>
   * This only works when the signature is stored in the same entry as the value.
   *
   * @param iterator
   *          The iterator with the accumulo data.
   * @param verifier
   *          The signer to use in verifying signatures.
   */
  SignedInlineScannerIterator(Iterator<Entry<Key,Value>> iterator, EntrySigner verifier) {
    this.iterator = iterator;
    this.verifier = verifier;
  }

  @Override
  public boolean hasNext() {
    return iterator.hasNext();
  }

  @Override
  public Entry<Key,Value> next() {
    Entry<Key,Value> original = iterator.next();
    Entry<Key,Value> processedEntry = verifier.verify(original);
    unprocessedEntry = original;
    return processedEntry;
  }

  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }

  @Override
  public Entry<Key,Value> unprocessed() {
    if (unprocessedEntry == null) {
      throw new NoSuchElementException("next() has not been called");
    }
    return unprocessedEntry;
  }

}
