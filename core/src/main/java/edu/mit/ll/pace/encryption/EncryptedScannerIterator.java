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
package edu.mit.ll.pace.encryption;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.SortedSet;

import org.apache.accumulo.core.data.Column;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;

import edu.mit.ll.pace.ItemProcessingIterator;

/**
 * Reads encrypted entries from Accumulo.
 */
final class EncryptedScannerIterator implements ItemProcessingIterator<Entry<Key,Value>> {

  /**
   * The underlying iterator that contains the data that will be decrypted.
   */
  private final Iterator<Entry<Key,Value>> iterator;

  /**
   * The {@link EntryEncryptor} to use to decrypt values.
   */
  private final EntryEncryptor encryptor;

  /**
   * The set of ranges that an entry must match to be returned.
   * <p>
   * These are handled client side, as it was not possible to push this filtering to the server.
   */
  private final List<Range> clientSideRanges;

  /**
   * The set of columns that an entry must match to be returned.
   * <p>
   * These are handled client side, as it was not possible to push this filtering to the server.
   */
  private final SortedSet<Column> clientSideColumnFilters;

  /**
   * Used to track the next element to return. Needed as the underlying iterator's {@link Iterator#hasNext()} doesn't match this iterator's {@link #hasNext()}.
   */
  private Entry<Key,Value> next = null;

  /**
   * Keep track of the encrypted entry that resulted in
   */
  private Entry<Key,Value> unprocessedEntry = null;

  /**
   * Wrap the given iterator, decrypting and filtering entries as appropriate.
   *
   * @param iterator
   *          The underlying iterator that contains the data that will be decrypted.
   * @param encryptor
   *          The {@link EntryEncryptor} to use to decrypt values.
   * @param clientSideRanges
   *          The set of ranges that an entry must match to be returned.
   * @param clientSideColumnFilters
   *          The set of columns that an entry must match to be returned.
   */
  EncryptedScannerIterator(Iterator<Entry<Key,Value>> iterator, EntryEncryptor encryptor, List<Range> clientSideRanges,
      SortedSet<Column> clientSideColumnFilters) {
    this.iterator = iterator;
    this.encryptor = encryptor;
    this.clientSideRanges = clientSideRanges;
    this.clientSideColumnFilters = clientSideColumnFilters;
  }

  @Override
  public boolean hasNext() {
    if (next == null) {
      advance();
    }
    return next != null;
  }

  @Override
  public Entry<Key,Value> next() {
    if (next == null) {
      advance();
    }

    if (next == null) {
      throw new NoSuchElementException();
    }

    // Clear next, as it has now been consumed.
    Entry<Key,Value> value = next;
    next = null;
    return value;
  }

  /**
   * Advance to the next entry that can be decrypted. This element is stored in next. If no more entries are left, next is set to null.
   */
  private void advance() {
    next = null;
    unprocessedEntry = null;

    while (iterator.hasNext()) {
      Entry<Key,Value> original = iterator.next();
      Entry<Key,Value> entry = encryptor.decrypt(original);

      // Check to see if the decrypted entry matches one of the set clientSideRanges.
      if (clientSideRanges.size() > 0) {
        boolean matches = false;
        for (Range range : clientSideRanges) {
          if (range.contains(entry.getKey())) {
            matches = true;
            break;
          }
        }
        if (!matches) {
          continue;
        }
      }

      // Check to see if the decrypted entry matches one of the filtered columns.
      if (clientSideColumnFilters.size() > 0) {
        boolean matches = false;
        for (Column column : clientSideColumnFilters) {
          // Column family always set and must be checked. Column qualifier may not be set.
          if (Arrays.equals(column.getColumnFamily(), entry.getKey().getColumnFamilyData().getBackingArray())
              && (column.getColumnQualifier() == null || Arrays.equals(column.getColumnQualifier(), entry.getKey().getColumnQualifierData().getBackingArray()))) {
            matches = true;
            break;
          }
        }
        if (!matches) {
          continue;
        }
      }

      // We've found the next entry and can end the loop.
      next = entry;
      unprocessedEntry = original;
      break;
    }
  }

  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }

  @Override
  public Entry<Key,Value> unprocessed() {
    if (next != null || unprocessedEntry == null) {
      throw new NoSuchElementException();
    }
    return unprocessedEntry;
  }
}
