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
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.BatchWriterConfig;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.data.ColumnUpdate;
import org.apache.accumulo.core.data.Mutation;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import edu.mit.ll.pace.internal.MutableEntry;
import edu.mit.ll.pace.test.TestUtils;

/**
 * Test {@link EncryptedBatchWriter}.
 */
public class EncryptedBatchWriterTest {

  /**
   * The default testing table.
   */
  private final static String TEST_TABLE = "table";

  /**
   * Encryption keys.
   */
  private final static MockEncryptionKeyContainer KEYS = new MockEncryptionKeyContainer(Pair.of("AES_GCM", 1), Pair.of("deterministic", 2));

  @Mock
  private Connector mockConnector;

  @Mock
  private BatchWriter mockWriter;

  @Captor
  private ArgumentCaptor<Mutation> captor;

  @Rule
  public MockitoRule mockitoRule = MockitoJUnit.rule();

  @Test
  public void badConstructorTest() throws Exception {
    try {
      new EncryptedBatchWriter(null, TEST_TABLE, null, getConfig("encrypt-value.ini"), KEYS);
      fail("null connector not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new EncryptedBatchWriter(mockConnector, null, null, getConfig("encrypt-value.ini"), KEYS);
      fail("null table name not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new EncryptedBatchWriter(mockConnector, TEST_TABLE, null, null, KEYS);
      fail("null crypto config not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new EncryptedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("encrypt-value.ini"), null);
      fail("null key container not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void constructorTest() throws Exception {
    BatchWriterConfig config = new BatchWriterConfig();
    new EncryptedBatchWriter(mockConnector, TEST_TABLE, config, getConfig("encrypt-value.ini"), KEYS);
    verify(mockConnector).createBatchWriter(TEST_TABLE, config);
  }

  @Test
  public void addMutationTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    BatchWriter writer = new EncryptedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("encrypt-value.ini"), KEYS);

    EntryEncryptor encryptor = new EntryEncryptor(getConfig("encrypt-value.ini"), KEYS);

    Mutation mutation = new Mutation("row".getBytes());
    mutation.put("colF".getBytes(), "colQ".getBytes(), "val1".getBytes());
    mutation.put("colF".getBytes(), "colQ".getBytes(), 0, "val2".getBytes());
    writer.addMutation(mutation);

    verify(mockWriter, times(2)).addMutation(captor.capture());
    List<Mutation> mutations = captor.getAllValues();
    assertThat("two mutations", mutations, iterableWithSize(2));

    Mutation encrypted = mutations.get(0);
    assertThat("row is unchanged", encrypted.getRow(), equalTo("row".getBytes()));

    List<ColumnUpdate> updates = encrypted.getUpdates();
    assertThat("has 1 update", updates, hasSize(1));

    ColumnUpdate update = updates.get(0);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnQualifier(), equalTo("colQ".getBytes()));
    assertThat("timestamp not set", update.hasTimestamp(), is(false));
    assertThat("value is encrypted", update.getColumnFamily(), not(equalTo("val1".getBytes())));

    MutableEntry decrypted = new MutableEntry(encryptor.decrypt(new MutableEntry("row".getBytes(), update).toEntry()));
    assertThat("value was encrypted correctly", decrypted.value, equalTo("val1".getBytes()));

    encrypted = mutations.get(1);
    assertThat("row is unchanged", encrypted.getRow(), equalTo("row".getBytes()));

    updates = encrypted.getUpdates();
    assertThat("has 1 update", updates, hasSize(1));

    update = updates.get(0);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnQualifier(), equalTo("colQ".getBytes()));
    assertThat("timestamp is set", update.hasTimestamp(), is(true));
    assertThat("timestamp is correct", update.getTimestamp(), is(0L));
    assertThat("value is encrypted", update.getColumnFamily(), not(equalTo("val2".getBytes())));

    decrypted = new MutableEntry(encryptor.decrypt(new MutableEntry("row".getBytes(), update).toEntry()));
    assertThat("value was encrypted correctly", decrypted.value, equalTo("val2".getBytes()));
  }

  @Test
  public void addMutationDeterministicTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    BatchWriter writer = new EncryptedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("deterministic.ini"), KEYS);

    Mutation mutation = new Mutation("row".getBytes());
    mutation.put("colF1".getBytes(), "colQ".getBytes(), "val".getBytes());
    mutation.put("colF2".getBytes(), "colQ".getBytes(), 0, "val".getBytes());
    mutation.put("colF1".getBytes(), "colQ".getBytes(), 0, "val2".getBytes());
    writer.addMutation(mutation);

    verify(mockWriter, times(3)).addMutation(captor.capture());
    Iterable<Mutation> mutations = captor.getAllValues();
    assertThat("should have 2 mutations", mutations, iterableWithSize(3));
  }

  @Test
  public void deleteTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    BatchWriter writer = new EncryptedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("encrypt-entry.ini"), KEYS);

    Mutation mutation = new Mutation("row".getBytes());
    mutation.putDelete("colF1".getBytes(), "colQ".getBytes());

    try {
      writer.addMutation(mutation);
      fail("encrypted deletes are not allowed on non-deterministically encrypted data");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void deleteDeterministicTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    BatchWriter writer = new EncryptedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("deterministic.ini"), KEYS);

    Mutation mutation = new Mutation("row".getBytes());
    mutation.putDelete("colF1".getBytes(), "colQ".getBytes());
    mutation.putDelete("colF2".getBytes(), "colQ".getBytes(), 0);
    writer.addMutation(mutation);

    verify(mockWriter, times(4)).addMutation(captor.capture());
    Iterable<Mutation> mutations = captor.getAllValues();
    assertThat("should have 4 mutations", mutations, iterableWithSize(4));
  }

  @Test
  public void addMutationsTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    BatchWriter writer = new EncryptedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("encrypt-value.ini"), KEYS);

    List<Mutation> mutations = new ArrayList<>();
    Mutation mutation = new Mutation("row");
    mutation.put("colF", "colQ", "val");

    mutations.add(mutation);
    writer.addMutations(mutations);
    verify(mockWriter, times(1)).addMutation(any()); // 1 time

    mutations.add(mutation);
    writer.addMutations(mutations);
    verify(mockWriter, times(3)).addMutation(any()); // 1 + 2 times

    mutations.add(mutation);
    writer.addMutations(mutations);
    verify(mockWriter, times(6)).addMutation(any()); // 1 + 2 + 3 times
  }

  @Test
  public void flushTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    new EncryptedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("encrypt-value.ini"), KEYS).flush();
    verify(mockWriter).flush();
  }

  @Test
  public void closeTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    new EncryptedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("encrypt-value.ini"), KEYS).close();
    verify(mockWriter).close();
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
