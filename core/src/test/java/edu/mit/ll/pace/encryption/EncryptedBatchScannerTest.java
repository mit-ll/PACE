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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.InputStreamReader;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import org.apache.accumulo.core.client.BatchScanner;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.IteratorSetting;
import org.apache.accumulo.core.client.sample.SamplerConfiguration;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.io.Text;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import edu.mit.ll.pace.internal.Utils;
import edu.mit.ll.pace.test.Matchers;
import edu.mit.ll.pace.test.TestUtils;

/**
 * Test {@link EncryptedBatchScanner}.
 */
public class EncryptedBatchScannerTest {

  /**
   * The default testing table.
   */
  private final static String TEST_TABLE = "test";

  /**
   * Authorizations.
   */
  private final static Authorizations authorizations = new Authorizations("admin", "secret", "top secret");

  /**
   * Encryption keys.
   */
  private final static MockEncryptionKeyContainer KEYS = new MockEncryptionKeyContainer(Pair.of("AES_GCM", 1), Pair.of("searchable_row", 2), Pair.of(
      "searchable_colFamily", 2), Pair.of("searchable_colQualifier", 2), Pair.of("secret", 1));

  @Mock
  private Connector mockConnector;

  @Mock
  private BatchScanner mockScanner;

  @Rule
  public MockitoRule mockitoRule = MockitoJUnit.rule();

  @Captor
  public ArgumentCaptor<Collection<Range>> captor;

  @Test
  public void badConstructorTest() throws Exception {
    try {
      new EncryptedBatchScanner(null, TEST_TABLE, authorizations, 0, getConfig("encrypt-value.ini"), KEYS);
      fail("null connector not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new EncryptedBatchScanner(mockConnector, null, authorizations, 0, getConfig("encrypt-value.ini"), KEYS);
      fail("null table name not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new EncryptedBatchScanner(mockConnector, TEST_TABLE, null, 0, getConfig("encrypt-value.ini"), KEYS);
      fail("null authorizations not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 0, null, KEYS);
      fail("null crypto config not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 0, getConfig("encrypt-value.ini"), null);
      fail("null key container not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void constructorTest() throws Exception {
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS);
    verify(mockConnector).createBatchScanner(TEST_TABLE, authorizations, 1);
  }

  @Test
  public void setRangesSemanticEncryptionTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("encrypt-key.ini"), KEYS);
    List<Map.Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-key.ini"), KEYS);
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    scanner.setRanges(Collections.singletonList(new Range(new Text(new byte[] {1}))));
    assertThat("has correct number of elements", scanner, iterableWithSize(1));

    scanner.setRanges(Collections.singletonList(new Range(new Text(new byte[] {1}), new Text(new byte[] {5}))));
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    // Should not have been handled server side.
    verify(mockScanner, times(2)).setRanges(captor.capture());

    for (Collection<Range> ranges : captor.getAllValues()) {
      assertThat("has the infinite range", ranges, hasSize(1));
      assertThat("has the infinite range", ranges.iterator().next(), equalTo(new Range()));
    }
  }

  @Test
  public void setRangesSearchableTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("searchable-row.ini"), KEYS);
    List<Map.Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("searchable-row.ini"), KEYS);
    scanner.setRanges(Collections.singletonList(new Range(new Text(new byte[] {1}))));
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    verify(mockScanner).setRanges(captor.capture());
    assertThat("correct number of ranges", captor.getValue(), hasSize(2));
  }

  @Test
  public void setRangesException() throws Exception {
    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-key.ini"), KEYS);

    try {
      scanner.setRanges(null);
      fail("null ranges not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      scanner.setRanges(new ArrayList<>());
      fail("empty ranges not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void fetchColumnFamilySemanticEncryptionTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("encrypt-key.ini"), KEYS);
    List<Map.Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-key.ini"), KEYS);
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    scanner.fetchColumnFamily(new Text(new byte[] {2}));
    assertThat("has correct number of elements", scanner, iterableWithSize(1));

    scanner.fetchColumnFamily(new Text(new byte[] {6}));
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    // Should not have been handled server side.
    verify(mockScanner, never()).fetchColumn(any());
  }

  @Test
  public void fetchColumnFamilySearchableTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("searchable.ini"), KEYS);
    List<Map.Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("searchable.ini"), KEYS);
    scanner.fetchColumnFamily(new Text(new byte[] {2}));
    assertThat("filtering is not happening client-side", scanner, iterableWithSize(2));
    verify(mockScanner, times(2)).fetchColumnFamily(any());
  }

  @Test
  public void fetchColumnFamilyException() throws Exception {
    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-key.ini"), KEYS);

    try {
      scanner.fetchColumnFamily(null);
      fail("null column family not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void fetchColumnSemanticEncryptionTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("encrypt-key.ini"), KEYS);
    List<Map.Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-key.ini"), KEYS);
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    scanner.fetchColumn(new IteratorSetting.Column(new Text(new byte[] {2}), new Text(new byte[] {3})));
    assertThat("has correct number of elements", scanner, iterableWithSize(1));

    scanner.fetchColumn(new IteratorSetting.Column(new Text(new byte[] {6}), new Text(new byte[] {7})));
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    // Should not have been handled server side.
    verify(mockScanner, never()).fetchColumn(any());
  }

  @Test
  public void fetchColumnSearchableTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("searchable.ini"), KEYS);
    List<Map.Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("searchable.ini"), KEYS);
    scanner.fetchColumn(new Text(new byte[] {2}), new Text(new byte[] {3}));
    assertThat("filtering is not happening client-side", scanner, iterableWithSize(2));
    verify(mockScanner, times(4)).fetchColumn(any(), any());
  }

  @Test
  public void fetchColumnPartiallySearchableTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("partially-searchable.ini"), KEYS);
    List<Map.Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("partially-searchable.ini"), KEYS);
    scanner.fetchColumn(new Text(new byte[] {2}), new Text(new byte[] {3}));
    assertThat("filtering is partially happening client-side", scanner, iterableWithSize(1));
    verify(mockScanner, times(2)).fetchColumnFamily(any());
  }

  @Test
  public void fetchColumnException() throws Exception {
    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-key.ini"), KEYS);

    try {
      scanner.fetchColumn(null);
      fail("null column not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      scanner.fetchColumn(null, new Text(Utils.EMPTY));
      fail("null column family not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      scanner.fetchColumn(new Text(Utils.EMPTY), null);
      fail("null column qualifier not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void clearColumnsTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("encrypt-key.ini"), KEYS);
    List<Map.Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-key.ini"), KEYS);
    scanner.fetchColumn(new Text(new byte[] {2}), new Text(new byte[] {2}));
    assertThat("has correct number of elements", scanner, iterableWithSize(0));

    scanner.clearColumns();
    assertThat("has correct number of elements", scanner, iterableWithSize(2));
  }

  @Test
  public void iteratorTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("encrypt-value.ini"), KEYS);
    List<Map.Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(encryptor.encrypt(entry));
    entries.add(encryptor.encrypt(entry2));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    BatchScanner scanner = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS);
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    Iterator<Entry<Key,Value>> iterator = scanner.iterator();
    assertThat("correct item", iterator.next(), Matchers.equalTo(entry));
    assertThat("correct item", iterator.next(), Matchers.equalTo(entry2));
  }

  @Test
  public void clearScanIteratorsTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).clearScanIterators();
    verify(mockScanner).clearScanIterators();
  }

  @Test
  public void closeTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).close();
    verify(mockScanner).close();
  }

  @Test
  public void getAuthorizationsTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    when(mockScanner.getAuthorizations()).thenReturn(authorizations);
    Authorizations auths = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).getAuthorizations();
    verify(mockScanner).getAuthorizations();
    assertThat("correct authorizations returned", auths, equalTo(authorizations));
  }

  @Test
  public void setSamplerConfigurationTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    SamplerConfiguration config = new SamplerConfiguration("test");
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).setSamplerConfiguration(config);
    verify(mockScanner).setSamplerConfiguration(config);
  }

  @Test
  public void getSamplerConfigurationTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    SamplerConfiguration config = new SamplerConfiguration("test");
    when(mockScanner.getSamplerConfiguration()).thenReturn(config);
    SamplerConfiguration value = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS)
        .getSamplerConfiguration();
    verify(mockScanner).getSamplerConfiguration();
    assertThat("correct config returned", value, equalTo(config));
  }

  @Test
  public void clearSamplerConfigurationTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).clearSamplerConfiguration();
    verify(mockScanner).clearSamplerConfiguration();
  }

  @Test
  public void setBatchTimeoutTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).setBatchTimeout(5L, TimeUnit.DAYS);
    verify(mockScanner).setBatchTimeout(5L, TimeUnit.DAYS);
  }

  @Test
  public void getBatchTimeoutTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    when(mockScanner.getBatchTimeout(TimeUnit.DAYS)).thenReturn(5L);
    long value = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).getBatchTimeout(TimeUnit.DAYS);
    verify(mockScanner).getBatchTimeout(TimeUnit.DAYS);
    assertThat("correct timeout returned", value, is(5L));
  }

  @Test
  public void setClassLoaderContextTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).setClassLoaderContext("test");
    verify(mockScanner).setClassLoaderContext("test");
  }

  @Test
  public void clearClassLoaderContextTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).clearClassLoaderContext();
    verify(mockScanner).clearClassLoaderContext();
  }

  @Test
  public void getClassLoaderContextTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    when(mockScanner.getClassLoaderContext()).thenReturn("test");
    String value = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).getClassLoaderContext();
    verify(mockScanner).getClassLoaderContext();
    assertThat("correct class loader context returned", value, is("test"));
  }

  @Test
  public void addScanIteratorTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    IteratorSetting test = new IteratorSetting(10, "test", "test2");
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).addScanIterator(test);
    verify(mockScanner).addScanIterator(test);
  }

  @Test
  public void removeScanIteratorTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).removeScanIterator("test");
    verify(mockScanner).removeScanIterator("test");
  }

  @Test
  public void updateScanIteratorOptionTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).updateScanIteratorOption("test", "a", "b");
    verify(mockScanner).updateScanIteratorOption("test", "a", "b");
  }

  @Test
  public void setTimeoutTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).setTimeout(5L, TimeUnit.DAYS);
    verify(mockScanner).setTimeout(5L, TimeUnit.DAYS);
  }

  @Test
  public void getTimeoutTest() throws Exception {
    when(mockConnector.createBatchScanner(TEST_TABLE, authorizations, 1)).thenReturn(mockScanner);
    when(mockScanner.getTimeout(TimeUnit.DAYS)).thenReturn(5L);
    Long value = new EncryptedBatchScanner(mockConnector, TEST_TABLE, authorizations, 1, getConfig("encrypt-value.ini"), KEYS).getTimeout(TimeUnit.DAYS);
    verify(mockScanner).getTimeout(TimeUnit.DAYS);
    assertThat("correct timeout returned", value, is(5L));
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
