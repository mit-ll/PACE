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

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.InputStreamReader;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.TreeSet;

import org.apache.accumulo.core.data.Column;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.io.Text;
import org.junit.Test;

import com.google.common.collect.Lists;

import edu.mit.ll.pace.internal.Utils;
import edu.mit.ll.pace.test.Matchers;
import edu.mit.ll.pace.test.TestUtils;

/**
 * Test {@link EncryptedScannerIterator}.
 */
public class EncryptedScannerIteratorTest {

  /**
   * Encryption keys.
   */
  private final static MockEncryptionKeyContainer KEYS = new MockEncryptionKeyContainer(Pair.of("AES_GCM", 1));

  @Test
  public void hasNextTest() throws Exception {
    EntryEncryptor encryptor = new EntryEncryptor(getConfig("config.ini"), KEYS);

    List<Entry<Key,Value>> entries = new ArrayList<>();
    Entry<Key,Value> entry = new SimpleImmutableEntry<Key,Value>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    entries.add(encryptor.encrypt(entry));

    EncryptedScannerIterator iterator = new EncryptedScannerIterator(entries.iterator(), encryptor, Collections.singletonList(new Range()),
        new TreeSet<Column>());

    assertThat("has next item", iterator.hasNext(), is(true));
    assertThat("has next item", iterator.hasNext(), is(true));
    iterator.next();
    assertThat("does not have a next item", iterator.hasNext(), is(false));
  }

  @Test
  public void nextTest() throws Exception {
    EntryEncryptor encryptor = new EntryEncryptor(getConfig("config.ini"), KEYS);

    List<Entry<Key,Value>> entries = new ArrayList<>();
    Entry<Key,Value> entry = new SimpleImmutableEntry<Key,Value>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    entries.add(encryptor.encrypt(entry));

    EncryptedScannerIterator iterator = new EncryptedScannerIterator(entries.iterator(), encryptor, Collections.singletonList(new Range()),
        new TreeSet<Column>());
    assertThat("next item is correct", iterator.next(), Matchers.equalTo(entry));

    try {
      iterator.next();
      fail("no items should be left");
    } catch (NoSuchElementException e) { /* expected */}
  }

  @Test
  public void hasNextThenNextTest() throws Exception {
    EntryEncryptor encryptor = new EntryEncryptor(getConfig("config.ini"), KEYS);

    List<Entry<Key,Value>> entries = new ArrayList<>();
    Entry<Key,Value> entry = new SimpleImmutableEntry<Key,Value>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    entries.add(encryptor.encrypt(entry));

    EncryptedScannerIterator iterator = new EncryptedScannerIterator(entries.iterator(), encryptor, Collections.singletonList(new Range()),
        new TreeSet<Column>());
    assertThat("hasNext is true", iterator.hasNext(), is(true));
    assertThat("next item is correct", iterator.next(), Matchers.equalTo(entry));
  }

  @Test
  public void matchRangeTest() throws Exception {
    EntryEncryptor encryptor = new EntryEncryptor(getConfig("config.ini"), KEYS);

    List<Entry<Key,Value>> entries = new ArrayList<>();
    Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(Utils.VISIBILITY_CHARSET), 0,
        false, false), new Value(new byte[] {4}));
    Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7}, "secret".getBytes(Utils.VISIBILITY_CHARSET),
        0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));

    EncryptedScannerIterator iterator = new EncryptedScannerIterator(entries.iterator(), new EntryEncryptor(getConfig("config.ini"), KEYS),
        Collections.singletonList(new Range()), new TreeSet<>());
    assertThat("correct number of items", Lists.newArrayList(iterator), hasSize(2));

    iterator = new EncryptedScannerIterator(entries.iterator(), new EntryEncryptor(getConfig("config.ini"), KEYS), new ArrayList<Range>(),
        new TreeSet<Column>());
    assertThat("correct number of items", Lists.newArrayList(iterator), hasSize(2));

    iterator = getIteratorForRange(entries, (byte) 1);
    assertThat("correct number of items", Lists.newArrayList(iterator), hasSize(1));

    iterator = getIteratorForRange(entries, (byte) 3);
    assertThat("correct number of items", Lists.newArrayList(iterator), hasSize(0));
  }

  private EncryptedScannerIterator getIteratorForRange(List<Entry<Key,Value>> entries, byte row) throws Exception {
    return new EncryptedScannerIterator(entries.iterator(), new EntryEncryptor(getConfig("config.ini"), KEYS), Collections.singletonList(new Range(new Text(
        new byte[] {row}))), new TreeSet<Column>());
  }

  @Test
  public void matchColumnFilters() throws Exception {
    EntryEncryptor encryptor = new EntryEncryptor(getConfig("config.ini"), KEYS);

    List<Entry<Key,Value>> entries = new ArrayList<>();
    Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(Utils.VISIBILITY_CHARSET), 0,
        false, false), new Value(new byte[] {4}));
    Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {2}, new byte[] {7}, "secret".getBytes(Utils.VISIBILITY_CHARSET),
        0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));

    EncryptedScannerIterator iterator = new EncryptedScannerIterator(entries.iterator(), new EntryEncryptor(getConfig("config.ini"), KEYS),
        Collections.singletonList(new Range()), new TreeSet<>());
    assertThat("correct number of items", Lists.newArrayList(iterator), hasSize(2));

    iterator = getIteratorForColumn(entries, new byte[] {2}, null);
    assertThat("correct number of items", Lists.newArrayList(iterator), hasSize(2));

    iterator = getIteratorForColumn(entries, new byte[] {3}, null);
    assertThat("correct number of items", Lists.newArrayList(iterator), hasSize(0));

    iterator = getIteratorForColumn(entries, new byte[] {2}, new byte[] {7});
    assertThat("correct number of items", Lists.newArrayList(iterator), hasSize(1));
  }

  private EncryptedScannerIterator getIteratorForColumn(List<Entry<Key,Value>> entries, byte[] colF, byte[] colQ) throws Exception {
    TreeSet<Column> columns = new TreeSet<>();
    columns.add(new Column(colF, colQ, null));
    return new EncryptedScannerIterator(entries.iterator(), new EntryEncryptor(getConfig("config.ini"), KEYS), Collections.singletonList(new Range()), columns);
  }

  @Test
  public void unprocessedTest() throws Exception {
    EntryEncryptor encryptor = new EntryEncryptor(getConfig("config.ini"), KEYS);

    List<Entry<Key,Value>> entries = new ArrayList<>();
    Entry<Key,Value> entry = new SimpleImmutableEntry<Key,Value>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    entries.add(encryptor.encrypt(entry));

    EncryptedScannerIterator iterator = new EncryptedScannerIterator(entries.iterator(), encryptor, Collections.singletonList(new Range()),
        new TreeSet<Column>());
    iterator.next();
    assertThat("unprocessed item is correct", iterator.unprocessed(), Matchers.equalTo(entries.get(0)));
  }

  @Test
  public void unprocessedException() throws Exception {
    EntryEncryptor encryptor = new EntryEncryptor(getConfig("config.ini"), KEYS);

    List<Entry<Key,Value>> entries = new ArrayList<>();
    Entry<Key,Value> entry = new SimpleImmutableEntry<Key,Value>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    entries.add(encryptor.encrypt(entry));

    EncryptedScannerIterator iterator = new EncryptedScannerIterator(entries.iterator(), encryptor, Collections.singletonList(new Range()), new TreeSet<>());

    try {
      iterator.unprocessed();
      fail("cannot call unprocessed before calling next()");
    } catch (NoSuchElementException e) { /* expected */}

    try {
      iterator.hasNext();
      iterator.unprocessed();
      fail("cannot call unprocessed before calling next()");
    } catch (NoSuchElementException e) { /* expected */}
  }

  @Test
  public void removeException() throws Exception {
    EntryEncryptor encryptor = new EntryEncryptor(getConfig("config.ini"), KEYS);

    List<Entry<Key,Value>> entries = new ArrayList<>();
    Entry<Key,Value> entry = new SimpleImmutableEntry<Key,Value>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    entries.add(encryptor.encrypt(entry));

    EncryptedScannerIterator iterator = new EncryptedScannerIterator(entries.iterator(), encryptor, Collections.singletonList(new Range()), new TreeSet<>());

    try {
      iterator.remove();
      fail("remove not supported");
    } catch (UnsupportedOperationException e) { /* expected */}
  }

  /**
   * Get an encryptor config.
   *
   * @param resource
   *          Resource file containing the configuration.
   * @return EncryptionConfig.
   */
  private EncryptionConfig getConfig(String resource) throws Exception {
    return new EncryptionConfigBuilder().readFromFile(new InputStreamReader(TestUtils.getResourceAsStream(this.getClass(), resource))).build();
  }

}
