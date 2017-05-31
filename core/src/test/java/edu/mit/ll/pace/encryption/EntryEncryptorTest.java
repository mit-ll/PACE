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

import static edu.mit.ll.pace.internal.Utils.EMPTY;
import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;
import static edu.mit.ll.pace.test.TestUtils.getResourceAsStream;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.InputStreamReader;
import java.security.Security;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;

import org.apache.accumulo.core.data.Column;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.io.Text;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.mit.ll.pace.encryption.EntryEncryptor.ColumnFilterResult;
import edu.mit.ll.pace.internal.MutableEntry;
import edu.mit.ll.pace.test.Matchers;
import edu.mit.ll.pace.test.TestUtils;

/**
 * Test {@link EntryEncryptor}.
 */
public class EntryEncryptorTest {

  /**
   * The mock key container, filled with several keys.
   */
  private static EncryptionKeyContainer keys = new MockEncryptionKeyContainer(Pair.of("searchable_row", 2), Pair.of("searchable_colFamily", 2), Pair.of(
      "searchable_colQualifier", 2), Pair.of("searchable_row", 2), Pair.of("secret", 2), Pair.of("top secret", 1), Pair.of("admin", 1), Pair.of("AES_GCM", 2),
      Pair.of("deterministic", 2));

  /**
   * Ensure that BouncyCastleProvider is registered.
   */
  @BeforeClass
  public static void setup() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void constructorExceptionTests() throws Exception {
    try {
      new EntryEncryptor(null, keys);
      fail("config must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getEncryptor("encrypt-value.ini", null); // Implicitly tests a good config, but a null key set.
      fail("keys must not be null");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void nullEntryTest() throws Exception {
    EntryEncryptor encryptor = getEncryptor("encrypt-entry.ini");

    try {
      encryptor.encrypt(null);
      fail("cannot call encrypt with a null value");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      encryptor.decrypt(null);
      fail("cannot call decrypt with a null value");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void encryptDecryptTest() throws Exception {
    Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET),
        (long) 5, false), new Value(new byte[] {6}));
    Entry<Key,Value> encrypted, decrypted;

    for (EntryEncryptor encryptor : getEncryptors()) { // Test all the various configs.
      encrypted = encryptor.encrypt(entry);
      assertThat("encrypting should change the data", encrypted, not(Matchers.equalTo(entry)));
      decrypted = encryptor.decrypt(encrypted);
      assertThat("encrypting than decrypting should return the original value", decrypted, Matchers.equalTo(entry));
    }
  }

  @Test
  public void canBeDeletedServerSideTest() throws Exception {
    assertThat("non-encrypted key can be updated", getEncryptor("encrypt-value.ini").canBeDeleteServerSide(), is(true));
    assertThat("non-deterministically encrypted key cannot be updated", getEncryptor("encrypt-entry.ini").canBeDeleteServerSide(), is(false));
    assertThat("searchable key can be updated", getEncryptor("searchable.ini").canBeDeleteServerSide(), is(true));
  }

  @Test
  public void getDeleteKeysTest() throws Exception {
    EntryEncryptor encryptor = getEncryptor("deterministic.ini");
    MutableEntry searchKey = new MutableEntry(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false));

    Collection<Key> keys = encryptor.getDeleteKeys(searchKey.toKey());
    assertThat("has correct number of delete keys", keys, hasSize(2));

    for (Key deleteKey : keys) {
      MutableEntry key = new MutableEntry(deleteKey);
      assertThat("row is encrypted", key.row, not(equalTo(searchKey.row)));
      assertThat("colF is zeroes", key.colF, equalTo(EMPTY));
      assertThat("colQ is plaintext", key.colQ, equalTo(searchKey.colQ));
      assertThat("colQ is plaintext", key.colVis, equalTo(searchKey.colVis));
      assertThat("colQ is plaintext", key.timestamp, equalTo(searchKey.timestamp));
      assertThat("delete is true", key.delete, is(true));
    }
  }

  @Test
  public void getDeleteKeysExceptionTest() throws Exception {
    EntryEncryptor encryptor = getEncryptor("encrypt-entry.ini");

    try {
      encryptor.getDeleteKeys(null);
      fail("cannot call delete keys with a null value");
    } catch (IllegalArgumentException e) { /* expected */}

    encryptor = getEncryptor("encrypt-entry.ini");

    try {
      encryptor.getDeleteKeys(new Key());
      fail("cannot call delete keys when the encryptor does not allow server side delete");
    } catch (IllegalArgumentException e) { /* expected */}

  }

  @Test
  public void getColumnFamilyFilterTest() throws Exception {
    byte[] columnFamily = new byte[] {2};

    ColumnFilterResult result = getEncryptor("encrypt-value.ini").getColumnFamilyFilter(new Text(columnFamily));
    assertThat("unencrypted column is searchable server side", result.serverSideFilters, hasSize(1));
    assertThat("unencrypted column is searchable server side", result.serverSideFilters, containsInAnyOrder(new Column(columnFamily, null, null)));
    assertThat("unencrypted column does not need client-side search", result.needsClientSideFiltering, is(false));

    result = getEncryptor("zeroed3.ini").getColumnFamilyFilter(new Text(columnFamily));
    assertThat("zeroed column is searchable server side", result.serverSideFilters, hasSize(1));
    assertThat("zeroed column is searchable server side", result.serverSideFilters, containsInAnyOrder(new Column(EMPTY, null, null)));
    assertThat("zeroed column needs client-side search", result.needsClientSideFiltering, is(true));

    result = getEncryptor("encrypt-entry.ini").getColumnFamilyFilter(new Text(columnFamily));
    assertThat("non-deterministically encrypted column is not searchable server side", result.serverSideFilters, hasSize(0));
    assertThat("non-deterministically encrypted column needs client-side search", result.needsClientSideFiltering, is(true));

    Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(EMPTY, columnFamily, EMPTY, EMPTY, (long) 0, false), new Value(EMPTY));
    MutableEntry encrypted1 = new MutableEntry(getEncryptor("filterable.ini",
        new MockEncryptionKeyContainer(Pair.of("searchable_colFamily", 1), Pair.of("searchable_colQualifier", 1))).encrypt(entry));
    MutableEntry encrypted2 = new MutableEntry(getEncryptor("filterable.ini",
        new MockEncryptionKeyContainer(Pair.of("searchable_colFamily", 2), Pair.of("searchable_colQualifier", 2))).encrypt(entry));

    result = getEncryptor("filterable.ini").getColumnFamilyFilter(new Text(columnFamily));
    assertThat("deterministically encrypted column is searchable server side", result.serverSideFilters, hasSize(2));
    assertThat("deterministically encrypted column is searchable server side", result.serverSideFilters,
        containsInAnyOrder(new Column(encrypted1.colF, null, null), new Column(encrypted2.colF, null, null)));
    assertThat("deterministically column does not needs client-side search", result.needsClientSideFiltering, is(false));
  }

  @Test
  public void getColumnFamilyFilterExceptionTest() throws Exception {
    EntryEncryptor encryptor = getEncryptor("encrypt-entry.ini");

    try {
      encryptor.getColumnFamilyFilter(null);
      fail("cannot call filter with a null value");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void getColumnFilterTest() throws Exception {
    byte[] columnFamily = new byte[] {2};
    byte[] columnQualifier = new byte[] {3};

    // Unencrypted column qualifier
    ColumnFilterResult result = getEncryptor("encrypt-value.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("unencrypted column is searchable server side", result.serverSideFilters, hasSize(1));
    assertThat("unencrypted column is searchable server side", result.serverSideFilters, containsInAnyOrder(new Column(columnFamily, columnQualifier, null)));
    assertThat("unencrypted column does not need client-side search", result.needsClientSideFiltering, is(false));

    // Zeroed column qualifier
    result = getEncryptor("zeroed1.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("zeroed column is searchable server side", result.serverSideFilters, hasSize(2));
    assertThat("zeroed column needs client-side search", result.needsClientSideFiltering, is(false));

    result = getEncryptor("zeroed2.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("zeroed column is searchable server side", result.serverSideFilters, hasSize(2));
    assertThat("zeroed column needs client-side search", result.needsClientSideFiltering, is(true));

    result = getEncryptor("zeroed3.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("zeroed column is searchable server side", result.serverSideFilters, hasSize(2));
    assertThat("zeroed column needs client-side search", result.needsClientSideFiltering, is(false));

    result = getEncryptor("zeroed4.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("zeroed column is searchable server side", result.serverSideFilters, hasSize(2));
    assertThat("zeroed column needs client-side search", result.needsClientSideFiltering, is(true));

    result = getEncryptor("zeroed5.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("zeroed column is searchable server side", result.serverSideFilters, hasSize(1));
    assertThat("zeroed column needs client-side search", result.needsClientSideFiltering, is(true));

    // Non-deterministic encrypted column qualifier
    result = getEncryptor("encrypt-entry.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("non-deterministically encrypted column is not searchable server side", result.serverSideFilters, hasSize(0));
    assertThat("non-deterministically encrypted column needs client-side search", result.needsClientSideFiltering, is(true));

    result = getEncryptor("filterable2.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("non-deterministically encrypted column is not searchable server side", result.serverSideFilters, hasSize(2));
    assertThat("non-deterministically encrypted column needs client-side search", result.needsClientSideFiltering, is(false));

    // Deterministically encrypted column qualifier
    result = getEncryptor("filterable.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("deterministically encrypted column is searchable server side", result.serverSideFilters, hasSize(4));
    assertThat("deterministically column does not needs client-side search", result.needsClientSideFiltering, is(false));

    result = getEncryptor("filterable3.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("deterministically encrypted column is searchable server side", result.serverSideFilters, hasSize(2));
    assertThat("deterministically column does not needs client-side search", result.needsClientSideFiltering, is(false));

    result = getEncryptor("filterable4.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("deterministically encrypted column is searchable server side", result.serverSideFilters, hasSize(2));
    assertThat("deterministically column does not needs client-side search", result.needsClientSideFiltering, is(true));

    result = getEncryptor("filterable5.ini").getColumnFilter(new Text(columnFamily), new Text(columnQualifier));
    assertThat("deterministically encrypted column is searchable server side", result.serverSideFilters, hasSize(0));
    assertThat("deterministically column does not needs client-side search", result.needsClientSideFiltering, is(true));
  }

  @Test
  public void getColumnFilterExceptionTest() throws Exception {
    EntryEncryptor encryptor = getEncryptor("encrypt-entry.ini");

    try {
      encryptor.getColumnFilter(null, new Text());
      fail("cannot call filter with a null value");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      encryptor.getColumnFilter(new Text(), null);
      fail("cannot call filter with a null value");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void transformRangeTest() throws Exception {
    // only value encrypted
    Range range = new Range("A");
    Collection<Range> serverSideRanges = new ArrayList<>();

    boolean result = getEncryptor("encrypt-value.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should be filtered server side", serverSideRanges, hasSize(1));
    assertThat("should be filtered server side", serverSideRanges, contains(range));
    assertThat("should not be filtered client side", result, is(false));

    // all fields encrypted
    range = new Range("A");
    serverSideRanges.clear();

    result = getEncryptor("encrypt-entry.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should not be filtered server side", serverSideRanges, hasSize(1));
    assertThat("should not be filtered server side", serverSideRanges, contains(new Range()));
    assertThat("should be filtered client side", result, is(true));

    // infinite range
    range = new Range();
    serverSideRanges.clear();

    result = getEncryptor("searchable.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should be filtered server side", serverSideRanges, hasSize(1));
    assertThat("should be filtered server side", serverSideRanges, contains(range));
    assertThat("should not be filtered client side", result, is(false));

    // single value search
    range = new Range(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), 0, false), new Key(new byte[] {1},
        new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), 0, false));
    serverSideRanges.clear();

    result = getEncryptor("searchable.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should be filtered server side", serverSideRanges, hasSize(8)); // 2 different key versions for each of the three search fields.
    assertThat("should not be filtered client side", result, is(false));

    // single value search, change unimportant variables
    range = new Range(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), 1, false), new Key(new byte[] {1},
        new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), 0, true));
    serverSideRanges.clear();

    result = getEncryptor("searchable.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should be filtered server side", serverSideRanges, hasSize(8)); // 2 different key versions for each of the three search fields.
    assertThat("should not be filtered client side", result, is(false));

    // range search, one searchable field
    range = new Range(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), 0, false), new Key(new byte[] {1},
        new byte[] {4}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), 0, false));
    serverSideRanges.clear();

    result = getEncryptor("searchable.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should be filtered server side", serverSideRanges, hasSize(2)); // 2 different key versions for the one searchable field.
    assertThat("should not be filtered client side", result, is(true));

    // range search, two searchable fields
    range = new Range(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), 0, false), new Key(new byte[] {1},
        new byte[] {2}, new byte[] {4}, "secret".getBytes(VISIBILITY_CHARSET), 0, false));
    serverSideRanges.clear();

    result = getEncryptor("searchable.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should be filtered server side", serverSideRanges, hasSize(4)); // 2 different key versions for the two searchable field.
    assertThat("should not be filtered client side", result, is(true));

    // range search, involves infinite key
    range = new Range(null, new Key(new byte[] {1}, new byte[] {2}, new byte[] {4}, "secret".getBytes(VISIBILITY_CHARSET), 0, false));
    serverSideRanges.clear();

    result = getEncryptor("searchable2.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should be filtered server side", serverSideRanges, hasSize(1)); // a range that is the first part of the search.
    assertThat("should not be filtered client side", result, is(true));

    range = new Range(new Key(new byte[] {1}, new byte[] {2}, new byte[] {4}, "secret".getBytes(VISIBILITY_CHARSET), 0, false), null);
    serverSideRanges.clear();

    result = getEncryptor("searchable2.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should be filtered server side", serverSideRanges, hasSize(1)); // a range that is the first part of the search.
    assertThat("should not be filtered client side", result, is(true));

    // single point search, non-deterministic encryption
    range = new Range(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), 0, false), new Key(new byte[] {1},
        new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET), 0, false));
    serverSideRanges.clear();

    result = getEncryptor("searchable3.ini", keys).transformRange(range, serverSideRanges);
    assertThat("should be filtered server side", serverSideRanges, hasSize(2)); // 2 different key versions for the one searchable field.
    assertThat("should not be filtered client side", result, is(true));
  }

  @Test
  public void transformRangeExceptionTest() throws Exception {
    Range range = new Range();
    Collection<Range> serverSideRanges = new ArrayList<>();
    EntryEncryptor encryptor = getEncryptor("searchable.ini");

    try {
      encryptor.transformRange(null, serverSideRanges);
      fail("cannot call with a null range");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      encryptor.transformRange(range, null);
      fail("cannot call with a null serverSideRanges");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  /**
   * Get an encryptor. The default set of keys will be used.
   *
   * @param resource
   *          Resource file containing the configuration.
   * @return EntryEncryptor.
   */
  private EntryEncryptor getEncryptor(String resource) throws Exception {
    return getEncryptor(resource, keys);
  }

  /**
   * Get an encryptor.
   *
   * @param resource
   *          Resource file containing the configuration.
   * @param keys
   *          Keys to use for the encryptor.
   * @return EntryEncryptor.
   */
  private EntryEncryptor getEncryptor(String resource, EncryptionKeyContainer keys) throws Exception {
    return new EntryEncryptor(new EncryptionConfigBuilder().readFromFile(new InputStreamReader(getResourceAsStream(this.getClass(), resource))).build(), keys);
  }

  /**
   * Get the value encryptors for this test class. The default set of keys will be used.
   *
   * @return Entry encryptors.
   */
  private Collection<EntryEncryptor> getEncryptors() throws Exception {
    List<EntryEncryptor> encryptors = new ArrayList<>();
    for (String line : IOUtils.readLines(this.getClass().getResourceAsStream(this.getClass().getSimpleName()))) {
      encryptors.add(new EntryEncryptor(new EncryptionConfigBuilder().readFromFile(new InputStreamReader(TestUtils.getResourceAsStream(this.getClass(), line)))
          .build(), keys));
    }
    return encryptors;
  }

}
