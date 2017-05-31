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
import java.util.SortedMap;
import java.util.TreeMap;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.PartialKey;
import org.apache.accumulo.core.data.Value;

import edu.mit.ll.pace.ItemProcessingIterator;

/**
 * Read signed Accumulo entries.
 */
final class SignedExternalScannerIterator implements ItemProcessingIterator<Entry<Key,Value>> {

  /**
   * The iterator with the Accumulo data.
   */
  private final Iterator<Entry<Key,Value>> valueIterator;

  /**
   * The iterator with the signature data.
   */
  private final Iterator<Entry<Key,Value>> signatureIterator;

  /**
   * The verifier to use.
   */
  private final EntrySigner verifier;

  /**
   * Whether the signatures are in the same order as the values.
   */
  private final boolean inOrder;

  /**
   * If we are processing out of order, then this map will store signatures that we have consumed, but for which the appropriate value is yet to be consumed.
   */
  private final SortedMap<Key,Entry<Key,Value>> bufferedSignatures = new TreeMap<>();

  /**
   * Keep track of the encrypted entry that resulted in
   */
  private Entry<Key,Value> unprocessedEntry = null;

  /**
   * Read signed Accumulo data where the signature is stored in a different entry than the value.
   *
   * @param valueIterator
   *          The iterator with the accumulo data.
   * @param signatureIterator
   *          The iterator with the signature data.
   * @param verifier
   *          The signer to use in verifying signatures.
   * @param inOrder
   *          Whether the signatures are in the same order as the values.
   */
  SignedExternalScannerIterator(Iterator<Entry<Key,Value>> valueIterator, Iterator<Entry<Key,Value>> signatureIterator, EntrySigner verifier, boolean inOrder) {
    this.valueIterator = valueIterator;
    this.signatureIterator = signatureIterator;
    this.verifier = verifier;
    this.inOrder = inOrder;
  }

  @Override
  public boolean hasNext() {
    return valueIterator.hasNext();
  }

  @Override
  public Entry<Key,Value> next() {
    unprocessedEntry = null;

    // Get the next signature.
    Entry<Key,Value> entry = valueIterator.next();
    Entry<Key,Value> signature = bufferedSignatures.get(entry.getKey());
    if (signature == null) {
      while (true) {
        if (!signatureIterator.hasNext()) {
          throw new SignatureException("no signature found");
        }

        signature = signatureIterator.next();

        // Timestamps might be slightly inconsistent, so don't include them in the compare. This requires that both of these tables be versioned.
        // TODO: Check that the tables are versioned, and if not throw an exception.
        int cmp = entry.getKey().compareTo(signature.getKey(), PartialKey.ROW_COLFAM_COLQUAL_COLVIS);

        if (cmp == 0) { // Found the signature
          break;
        } else if (cmp < 0) { // Entry is before the next signature.
          if (inOrder) {
            throw new SignatureException("no signature found for entry");
          } else {
            bufferedSignatures.put(signature.getKey(), signature);
          }
        } else { // Entry is after the next signature.
          if (!inOrder) {
            bufferedSignatures.put(signature.getKey(), signature);
          }
        }
      }
    }

    Entry<Key,Value> processedEntry = verifier.verify(entry, signature);
    unprocessedEntry = entry;
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
