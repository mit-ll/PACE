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
package edu.mit.ll.pace.internal;

import static edu.mit.ll.pace.internal.Utils.EMPTY;

import java.util.AbstractMap;
import java.util.Map;

import org.apache.accumulo.core.data.ColumnUpdate;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;

import edu.mit.ll.pace.EntryField;

/**
 * Mutable container representing an Accumulo entry.
 * <p>
 * This class is not part of the PACE API, and should not be used.
 * </p>
 */
public final class MutableEntry implements Cloneable {

  /**
   * The byte-based values in an entry.
   */
  public byte[] row = EMPTY, colF = EMPTY, colQ = EMPTY, colVis = EMPTY, value = EMPTY;

  /**
   * The timestamp for the entry.
   */
  public long timestamp = 0L;

  /**
   * Whether the entry has been deleted.
   */
  public boolean delete = false;

  /**
   * Creates an empty mutable entry.
   */
  public MutableEntry() {}

  /**
   * Creates a mutable entry for the given key.
   *
   * @param key
   *          Key to wrap.
   */
  public MutableEntry(Key key) {
    row = key.getRowData().getBackingArray();
    colF = key.getColumnFamilyData().getBackingArray();
    colQ = key.getColumnQualifierData().getBackingArray();
    colVis = key.getColumnVisibilityData().getBackingArray();
    timestamp = key.getTimestamp();
    delete = key.isDeleted();
  }

  /**
   * Creates a mutable entry for the given entry.
   *
   * @param entry
   *          Entry to wrap.
   */
  public MutableEntry(Map.Entry<Key,Value> entry) {
    this(entry.getKey());
    value = entry.getValue().get();
  }

  /**
   * Creates a mutable entry for the given update.
   *
   * @param row
   *          The row that is being updated.
   * @param update
   *          Update to wrap.
   */
  public MutableEntry(byte[] row, ColumnUpdate update) {
    this.row = row;
    this.colF = update.getColumnFamily();
    this.colQ = update.getColumnQualifier();
    this.colVis = update.getColumnVisibility();
    this.timestamp = update.getTimestamp();
    this.delete = update.isDeleted();
    this.value = update.getValue();
  }

  /**
   * Wrap the data in this class in a cannonical {@link Key}.
   *
   * @return An Accumulo key.
   */
  public Key toKey() {
    return new Key(row, colF, colQ, colVis, timestamp, delete, false);
  }

  /**
   * Wrap the data in this class in a cannonical {@literal Entry<Key,Value>}.
   *
   * @return An Accumulo entry.
   */
  public Map.Entry<Key,Value> toEntry() {
    return new AbstractMap.SimpleImmutableEntry<>(toKey(), new Value(value, false));
  }

  /**
   * Clone this object.
   * <p>
   * Cloning this object will never throw an exception.
   *
   * @return Shallow clone of this object.
   */
  public MutableEntry cloneEntry() {
    try {
      return (MutableEntry) super.clone();
    } catch (CloneNotSupportedException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Get the bytes for the given field.
   *
   * @param field
   *          Field for which to retrieve data.
   * @return Requested bytes.
   */
  public byte[] getBytes(EntryField field) {
    switch (field) {
      case ROW:
        return row;
      case COLUMN_FAMILY:
        return colF;
      case COLUMN_QUALIFIER:
        return colQ;
      case COLUMN_VISIBILITY:
        return colVis;
      case VALUE:
        return value;
      default:
        throw new IllegalArgumentException("invalid field");
    }
  }

  /**
   * Set the bytes for the given field.
   *
   * @param field
   *          Field for which to set data.
   * @param bytes
   *          Bytes to set.
   */
  public void setBytes(EntryField field, byte[] bytes) {
    switch (field) {
      case ROW:
        row = bytes;
        break;
      case COLUMN_FAMILY:
        colF = bytes;
        break;
      case COLUMN_QUALIFIER:
        colQ = bytes;
        break;
      case COLUMN_VISIBILITY:
        colVis = bytes;
        break;
      case VALUE:
        value = bytes;
        break;
      default:
        throw new IllegalArgumentException("invalid field");
    }
  }
}
