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
import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Map.Entry;

import org.apache.accumulo.core.data.ColumnUpdate;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.junit.Before;
import org.junit.Test;

import edu.mit.ll.pace.EntryField;

/**
 * Test {@link MutableEntry}.
 */
public final class MutableEntryTest {

  /**
   * Testing values.
   */
  private byte[] row, colF, colQ, colVis, value;
  private long timestamp;
  private boolean delete;
  private Key key;
  private Entry<Key,Value> entry;

  /**
   * Ensure that the core values are always in a good state.
   */
  @Before
  public void setupTestValues() {
    row = new byte[] {(byte) 1};
    colF = new byte[] {(byte) 2};
    colQ = new byte[] {(byte) 3};
    colVis = "A".getBytes(VISIBILITY_CHARSET);
    value = new byte[] {(byte) 4};

    timestamp = 4;
    delete = true;

    key = new Key(row, colF, colQ, colVis, timestamp, delete);
    entry = new SimpleImmutableEntry<>(key, new Value(value));
  }

  @Test
  public void constructorWithKeyTest() {
    MutableEntry mutableKey = new MutableEntry(key);

    assertThat("row should be unmodified", mutableKey.row, is(equalTo(row)));
    assertThat("colF should be unmodified", mutableKey.colF, is(equalTo(colF)));
    assertThat("colQ should be unmodified", mutableKey.colQ, is(equalTo(colQ)));
    assertThat("colVis should be unmodified", mutableKey.colVis, is(equalTo(colVis)));
    assertThat("timestamp should be unmodified", mutableKey.timestamp, is(equalTo(timestamp)));
    assertThat("delete should be unmodified", mutableKey.delete, is(equalTo(delete)));
    assertThat("value should not be set", mutableKey.value, is(equalTo(EMPTY)));
  }

  @Test
  public void constructorWithEntryTest() {
    MutableEntry mutableEntry = new MutableEntry(entry);

    assertThat("row should be unmodified", mutableEntry.row, is(equalTo(row)));
    assertThat("colF should be unmodified", mutableEntry.colF, is(equalTo(colF)));
    assertThat("colQ should be unmodified", mutableEntry.colQ, is(equalTo(colQ)));
    assertThat("colVis should be unmodified", mutableEntry.colVis, is(equalTo(colVis)));
    assertThat("timestamp should be unmodified", mutableEntry.timestamp, is(equalTo(timestamp)));
    assertThat("delete should be unmodified", mutableEntry.delete, is(equalTo(delete)));
    assertThat("value should be unmodified", mutableEntry.value, is(equalTo(value)));
  }

  @Test
  public void constructorWithUpdateTest() {
    ColumnUpdate update = new ColumnUpdate(colF, colQ, colVis, true, timestamp, delete, value);
    MutableEntry mutableEntry = new MutableEntry(row, update);

    assertThat("row should be unmodified", mutableEntry.row, is(equalTo(row)));
    assertThat("colF should be unmodified", mutableEntry.colF, is(equalTo(colF)));
    assertThat("colQ should be unmodified", mutableEntry.colQ, is(equalTo(colQ)));
    assertThat("colVis should be unmodified", mutableEntry.colVis, is(equalTo(colVis)));
    assertThat("timestamp should be unmodified", mutableEntry.timestamp, is(equalTo(timestamp)));
    assertThat("delete should be unmodified", mutableEntry.delete, is(equalTo(delete)));
    assertThat("value should be unmodified", mutableEntry.value, is(equalTo(value)));
  }

  @Test
  public void toKeyTest() {
    MutableEntry mutableKey = new MutableEntry(key);
    assertThat("returned key should be the same as the original key", mutableKey.toKey(), is(equalTo(key)));
  }

  @Test
  public void toEntryTest() {
    MutableEntry mutableEntry = new MutableEntry(entry);
    assertThat("returned entry should be the same as the original entry", mutableEntry.toEntry(), is(equalTo(entry)));
  }

  @Test
  public void cloneTest() {
    MutableEntry mutableEntry = new MutableEntry(entry);
    MutableEntry mutableEntry2 = mutableEntry.cloneEntry();
    assertThat("returned entry should be the same as the original entry", mutableEntry2.toEntry(), is(equalTo(mutableEntry.toEntry())));
  }

  @Test
  public void getBytesTest() {
    MutableEntry mutableEntry = new MutableEntry(entry);

    assertThat("correct bytes returned", mutableEntry.getBytes(EntryField.ROW), is(equalTo(row)));
    assertThat("correct bytes returned", mutableEntry.getBytes(EntryField.COLUMN_FAMILY), is(equalTo(colF)));
    assertThat("correct bytes returned", mutableEntry.getBytes(EntryField.COLUMN_QUALIFIER), is(equalTo(colQ)));
    assertThat("correct bytes returned", mutableEntry.getBytes(EntryField.COLUMN_VISIBILITY), is(equalTo(colVis)));
    assertThat("correct bytes returned", mutableEntry.getBytes(EntryField.VALUE), is(equalTo(value)));
  }

  @Test(expected = IllegalArgumentException.class)
  public void getBytesException() {
    MutableEntry mutableEntry = new MutableEntry(entry);
    mutableEntry.getBytes(EntryField.TIMESTAMP);
  }

  @Test
  public void setBytesTest() {
    MutableEntry mutableEntry = new MutableEntry(new Key()); // Create an empty mutable entry.

    mutableEntry.setBytes(EntryField.ROW, row);
    mutableEntry.setBytes(EntryField.COLUMN_FAMILY, colF);
    mutableEntry.setBytes(EntryField.COLUMN_QUALIFIER, colQ);
    mutableEntry.setBytes(EntryField.COLUMN_VISIBILITY, colVis);
    mutableEntry.setBytes(EntryField.VALUE, value);
    mutableEntry.timestamp = timestamp;
    mutableEntry.delete = delete;

    assertThat("constructed entry should be the same as the testing entry", mutableEntry.toEntry(), is(equalTo(entry)));
  }

  @Test(expected = IllegalArgumentException.class)
  public void setBytesException() {
    MutableEntry mutableEntry = new MutableEntry(entry);
    mutableEntry.setBytes(EntryField.TIMESTAMP, EMPTY);
  }

}
