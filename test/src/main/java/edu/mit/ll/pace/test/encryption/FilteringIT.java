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
package edu.mit.ll.pace.test.encryption;

import static edu.mit.ll.pace.test.Matchers.equalToRow;
import static edu.mit.ll.pace.test.Matchers.hasData;
import static edu.mit.ll.pace.test.TestUtils.CHARSET;
import static edu.mit.ll.pace.test.TestUtils.getResourceAsStream;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.NoSuchElementException;

import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.BatchWriterConfig;
import org.apache.accumulo.core.client.IteratorSetting;
import org.apache.accumulo.core.client.MutationsRejectedException;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.PartialKey;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.hadoop.io.Text;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.google.common.collect.ImmutableList;

import edu.mit.ll.pace.encryption.EncryptedBatchScanner;
import edu.mit.ll.pace.encryption.EncryptedBatchWriter;
import edu.mit.ll.pace.encryption.EncryptionConfig;
import edu.mit.ll.pace.encryption.EncryptionConfigBuilder;
import edu.mit.ll.pace.harness.AccumuloInstance;
import edu.mit.ll.pace.harness.AccumuloRunner;
import edu.mit.ll.pace.internal.MutableEntry;

/**
 * Test that the Accumulo dependant pieces of the encryption code work together.
 */
@RunWith(AccumuloRunner.class)
public final class FilteringIT {

  /**
   * Users.
   */
  private final static String ALICE = "Alice";
  private final static String CHARLIE = "Charlie";

  /**
   * The default testing table.
   */
  private final static String TEST_TABLE = "FilteringIT";

  @BeforeClass
  public static void setup() throws Exception {
    AccumuloInstance.createTable(TEST_TABLE);
  }

  @AfterClass
  public static void teardown() throws Exception {
    AccumuloInstance.deleteTable(TEST_TABLE);
  }

  @Before
  public void clearTable() throws Exception {
    AccumuloInstance.clearTable(TEST_TABLE);
  }

  @Test
  public void simpleWriteReadTest() throws Exception {
    // Write the data.
    EncryptedBatchWriter writer = getEncryptedWriter(CHARLIE, "encrypt-value.ini");

    Mutation mutation = new Mutation("hello");
    mutation.put("world", "core", "works!");

    writer.addMutation(mutation);
    writer.flush();
    writer.close();

    // Verify that the data has been encrypted.
    Scanner plaintextScanner = AccumuloInstance.getConnector(ALICE).createScanner(TEST_TABLE, AccumuloInstance.getUser(ALICE).authorizations);

    List<Entry<Key,Value>> entries = ImmutableList.copyOf(plaintextScanner.iterator());
    assertThat("should have one entry", entries, hasSize(1));

    MutableEntry entry = new MutableEntry(entries.get(0));
    assertThat("should have correct row", entry.row, equalTo("hello".getBytes(CHARSET)));
    assertThat("should have correct row", entry.colF, equalTo("world".getBytes(CHARSET)));
    assertThat("should have correct row", entry.colQ, equalTo("core".getBytes(CHARSET)));
    assertThat("should have correct row", entry.value, not(equalTo("works!".getBytes(CHARSET))));

    // Read the encrypted data.
    EncryptedBatchScanner scanner = getEncryptedScanner(ALICE, "encrypt-value.ini");
    scanner.setRanges(Collections.singletonList(new Range("hello")));

    entries = ImmutableList.copyOf(scanner.iterator());
    assertThat("should have one entry", entries, hasSize(1));
    assertThat("should have correct row", entries.get(0), equalToRow("hello", "world", "core", "", "works!"));
  }

  @Test
  public void multipleWritesNotSearchableTest() throws Exception {
    List<String> rows = Arrays.asList("row1", "row2", "row3");
    List<String> colFs = Arrays.asList("colF1", "colF2", "colF3");
    List<String> colQs = Arrays.asList("colQ1", "colQ2", "colQ3");
    List<String> colVs = Arrays.asList("secret", ColumnVisibility.quote("top secret"));
    List<String> values = Arrays.asList("value1", "value2", "value3");

    // Initial data.
    EncryptedBatchWriter writer = getEncryptedWriter(CHARLIE, "all.ini");
    writeData(writer, rows, colFs, colQs, colVs, values);
    writer.close();

    EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, "all.ini");
    scanner.setRanges(Collections.singletonList(new Range()));
    assertThat("contains the correct data", scanner, hasData(rows, colFs, colQs, colVs, values));

    // Update the data.
    writer = getEncryptedWriter(CHARLIE, "all.ini");
    writeData(writer, rows, colFs, colQs, colVs, Collections.singletonList("value4"));
    writer.close();

    scanner = getEncryptedScanner(CHARLIE, "all.ini");
    scanner.setRanges(Collections.singletonList(new Range()));
    assertThat("contains the correct data", scanner, hasData(rows, colFs, colQs, colVs, Arrays.asList("value1", "value2", "value3", "value4")));
  }

  @Test
  public void multipleWritesSearchableTest() throws Exception {
    List<String> rows = Arrays.asList("row1", "row2", "row3");
    List<String> colFs = Arrays.asList("colF1", "colF2", "colF3");
    List<String> colQs = Arrays.asList("colQ1", "colQ2", "colQ3");
    List<String> colVs = Arrays.asList("secret", ColumnVisibility.quote("top secret"));
    List<String> values = Arrays.asList("value1", "value2", "value3");

    // Initial data.
    EncryptedBatchWriter writer = getEncryptedWriter(CHARLIE, "searchable.ini");
    writeData(writer, rows, colFs, colQs, colVs, values);
    writer.close();

    EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, "searchable.ini");
    scanner.setRanges(Collections.singletonList(new Range()));
    assertThat("contains the most recent version of the data", scanner, hasData(rows, colFs, colQs, colVs, Collections.singletonList("value3")));

    // Update the data.
    writer = getEncryptedWriter(CHARLIE, "searchable.ini");
    writeData(writer, rows, colFs, colQs, colVs, Collections.singletonList("value4"));
    writer.close();

    scanner = getEncryptedScanner(CHARLIE, "searchable.ini");
    scanner.setRanges(Collections.singletonList(new Range()));
    assertThat("contains the most recent version of the data", scanner, hasData(rows, colFs, colQs, colVs, Collections.singletonList("value4")));
  }

  @Test
  public void setRangesTest() throws Exception {
    setRangesTest("setRanges1.ini"); // Client-side search.
    setRangesTest("setRanges2.ini"); // Partially server-side, partially client-side.
    setRangesTest("setRanges3.ini"); // Server-side search.
    setRangesTest("encrypt-value.ini"); // Non-encrypted search.
  }

  private void setRangesTest(String configuration) throws Exception {
    List<String> rows = Arrays.asList("row1", "row2");
    List<String> colFs = Arrays.asList("colF1", "colF2");
    List<String> colQs = Arrays.asList("colQ1", "colQ2");
    List<String> colVs = Collections.singletonList("");
    List<String> values = Collections.singletonList("value");

    clearTable();
    EncryptedBatchWriter writer = getEncryptedWriter(CHARLIE, configuration);
    writeData(writer, rows, colFs, colQs, colVs, values);
    writer.close();

    EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, configuration);
    scanner.setRanges(Collections.singletonList(new Range(new Key("row1", "colF1", "colQ1"), true, new Key("row1", "colF1", "colQ2")
        .followingKey(PartialKey.ROW_COLFAM_COLQUAL), false)));
    assertThat("contains the filtered data", scanner, hasData(Collections.singletonList("row1"), Collections.singletonList("colF1"), colQs, colVs, values));
  }

  @Test
  public void setRangesExceptionTest() throws Exception {
    try {
      EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, "searchable.ini");
      scanner.setRanges(null);
      fail("null ranges not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, "searchable.ini");
      scanner.setRanges(new ArrayList<>());
      fail("ranges must have at least one element");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void fetchColumnFamilyTest() throws Exception {
    fetchColumnFamilyTest("encrypt-value.ini"); // Encrypted, deterministic column family.
    fetchColumnFamilyTest("fetchColumnFamily1.ini"); // Encrypted, non-deterministic column family.
    fetchColumnFamilyTest("fetchColumnFamily2.ini"); // Non-encrypted column family.
  }

  private void fetchColumnFamilyTest(String configuration) throws Exception {
    List<String> rows = Arrays.asList("row1", "row2");
    List<String> colFs = Arrays.asList("colF1", "colF2");
    List<String> colQs = Arrays.asList("colQ1", "colQ2");
    List<String> colVs = Collections.singletonList("");
    List<String> values = Collections.singletonList("value");

    clearTable();
    EncryptedBatchWriter writer = getEncryptedWriter(CHARLIE, configuration);
    writeData(writer, rows, colFs, colQs, colVs, values);
    writer.close();

    EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, configuration);
    scanner.setRanges(Collections.singletonList(new Range()));
    scanner.fetchColumnFamily(new Text("colF1"));
    assertThat("contains the filtered data", scanner, hasData(rows, Collections.singletonList("colF1"), colQs, colVs, values));
  }

  @Test
  public void fetchColumnFamilyExceptionTest() throws Exception {
    try {
      EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, "searchable.ini");
      scanner.fetchColumnFamily(null);
      fail("null column family not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void fetchColumnTest() throws Exception {
    fetchColumnTest("fetchColumn1.ini"); // Encrypted, deterministic column family and qualifier.
    fetchColumnTest("fetchColumn2.ini"); // Encrypted, deterministic column family, and encrypted, non-deterministic column qualifier.
    fetchColumnTest("fetchColumn3.ini"); // Encrypted, deterministic column family, and non-deterministic column qualifier.
    fetchColumnTest("fetchColumn4.ini"); // Encrypted, non-deterministic column family.
    fetchColumnTest("fetchColumn5.ini"); // Non-encrypted column family, and encrypted, deterministic column qualifier.
    fetchColumnTest("fetchColumn6.ini"); // Non-encrypted column family, and encrypted, non-deterministic column qualifier.
    fetchColumnTest("encrypt-value.ini"); // Non-encrypted column family, and non-encrypted column qualifier.
  }

  private void fetchColumnTest(String configuration) throws Exception {
    List<String> rows = Arrays.asList("row1", "row2");
    List<String> colFs = Arrays.asList("colF1", "colF2");
    List<String> colQs = Arrays.asList("colQ1", "colQ2");
    List<String> colVs = Collections.singletonList("");
    List<String> values = Collections.singletonList("value");

    clearTable();
    EncryptedBatchWriter writer = getEncryptedWriter(CHARLIE, configuration);
    writeData(writer, rows, colFs, colQs, colVs, values);
    writer.close();

    EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, configuration);
    scanner.setRanges(Collections.singletonList(new Range()));
    scanner.fetchColumn(new IteratorSetting.Column(new Text("colF1"), new Text("colQ1")));
    assertThat("contains the filtered data", scanner, hasData(rows, Collections.singletonList("colF1"), Collections.singletonList("colQ1"), colVs, values));
  }

  @Test
  public void fetchColumnExceptionTest() throws Exception {
    try {
      EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, "searchable.ini");
      scanner.fetchColumn(null);
      fail("null column not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, "searchable.ini");
      scanner.fetchColumn(new Text("core"), null);
      fail("null column not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, "searchable.ini");
      scanner.fetchColumn(null, new Text("core"));
      fail("null column not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void encryptedScannerIteratorTest() throws Exception {
    List<String> rows = Arrays.asList("row1", "row2");
    List<String> colFs = Arrays.asList("colF1", "colF2");
    List<String> colQs = Arrays.asList("colQ1", "colQ2");
    List<String> colVs = Collections.singletonList("");
    List<String> values = Collections.singletonList("value");

    EncryptedBatchWriter writer = getEncryptedWriter(CHARLIE, "encrypt-value.ini");
    writeData(writer, rows, colFs, colQs, colVs, values);

    // Has next works in sequence.
    EncryptedBatchScanner scanner = getEncryptedScanner(CHARLIE, "encrypt-value.ini");
    scanner.setRanges(Collections.singletonList(new Range()));
    Iterator<Entry<Key,Value>> iterator = scanner.iterator();

    assertThat("hasNext is true", iterator.hasNext(), is(true));
    assertThat("hasNext is true", iterator.hasNext(), is(true));

    // Can call next() without checking hasNext().
    for (int i = 0; i < rows.size() * colFs.size() * colQs.size() * colVs.size() * values.size(); i++) {
      assertThat("gets next item", iterator.next(), is(notNullValue()));
    }

    // Calling next() when there is nothing should thrown an error.
    assertThat("hasNext is false", iterator.hasNext(), is(false));
    try {
      iterator.next();
      fail("next should throw an exception when no more items");
    } catch (NoSuchElementException e) { /* expected */}

    // Cannot remove items from iterator.
    iterator = scanner.iterator();
    iterator.next();
    try {
      iterator.remove();
      fail("removing elements should not be supported");
    } catch (UnsupportedOperationException e) { /* expected */}
  }

  /**
   * Get an {@link EncryptedBatchWriter}.
   *
   * @param user
   *          User to get the writer for.
   * @param resource
   *          Resource file containing the configuration.
   * @return EncryptedBatchWriter.
   */
  private EncryptedBatchWriter getEncryptedWriter(String user, String resource) throws Exception {
    return new EncryptedBatchWriter(AccumuloInstance.getConnector(user), TEST_TABLE, new BatchWriterConfig(), getConfig(resource),
        AccumuloInstance.getUser(user).encryptionKeys);
  }

  /**
   * Get an {@link EncryptedBatchScanner}.
   *
   * @param user
   *          User to get the scanner for.
   * @param resource
   *          Resource file containing the configuration.
   * @return EncryptedBatchScanner.
   */
  private EncryptedBatchScanner getEncryptedScanner(String user, String resource) throws Exception {
    return new EncryptedBatchScanner(AccumuloInstance.getConnector(user), TEST_TABLE, AccumuloInstance.getUser(user).authorizations, 1, getConfig(resource),
        AccumuloInstance.getUser(user).encryptionKeys);
  }

  /**
   * Get an encryptor config.
   *
   * @param resource
   *          Resource file containing the configuration.
   * @return EncryptionConfig.
   */
  private EncryptionConfig getConfig(String resource) throws Exception {
    return new EncryptionConfigBuilder().readFromFile(new InputStreamReader(getResourceAsStream(this.getClass(), resource))).build();
  }

  /**
   * Writes the given data to Accumulo. The full combinatorial of values is written.
   *
   * @param rows
   *          Rows to write.
   * @param colFs
   *          Column families to write.
   * @param colQs
   *          Column qualifiers to write.
   * @param colVs
   *          Column visibilities to write.
   * @param values
   *          Values to write.
   */
  private static void writeData(BatchWriter writer, Iterable<String> rows, Iterable<String> colFs, Iterable<String> colQs, Iterable<String> colVs,
      Iterable<String> values) throws MutationsRejectedException {
    List<Mutation> mutations = new ArrayList<>();

    for (String row : rows) {
      Mutation mutation = new Mutation(row);
      mutations.add(mutation);

      for (String colF : colFs) {
        for (String colQ : colQs) {
          for (String colV : colVs) {
            for (String value : values) {
              mutation.put(colF, colQ, new ColumnVisibility(colV), value);
            }
          }
        }
      }
    }

    writer.addMutations(mutations);
    writer.flush();
  }

}
