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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.BatchWriterConfig;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.data.ColumnUpdate;
import org.apache.accumulo.core.data.Mutation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import edu.mit.ll.pace.internal.MutableEntry;
import edu.mit.ll.pace.internal.Utils;
import edu.mit.ll.pace.test.TestUtils;

/**
 * Test {@link SignedBatchWriter}.
 */
public class SignedBatchWriterTest {

  private final static String TEST_TABLE = "test";
  private final static String SIG_TABLE = "sigs";

  private Map<ValueSigner,SignatureKeyContainer> aliceKeyContainers = new HashMap<>();
  private Map<ValueSigner,SignatureKeyContainer> bobKeyContainers = new HashMap<>();

  @Mock
  private Connector mockConnector;

  @Mock
  private BatchWriter mockWriter;

  @Mock
  private BatchWriter mockSignatureWriter;

  @Captor
  private ArgumentCaptor<Mutation> captor;

  @Captor
  private ArgumentCaptor<Mutation> signatureCaptor;

  @Rule
  public MockitoRule mockitoRule = MockitoJUnit.rule();

  public SignedBatchWriterTest() throws NoSuchAlgorithmException {
    aliceKeyContainers = MockSignatureKeyContainer.getContainers("alice", "alice", "bob");
    bobKeyContainers = MockSignatureKeyContainer.getContainers("bob", "alice", "bob");
  }

  @BeforeClass
  public static void setupBouncyCastle() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void badConstructorTest() throws Exception {
    try {
      new SignedBatchWriter(null, TEST_TABLE, null, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
      fail("null connector not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new SignedBatchWriter(mockConnector, null, null, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
      fail("null table name not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new SignedBatchWriter(mockConnector, TEST_TABLE, null, null, aliceKeyContainers.get(ValueSigner.RSA_PSS));
      fail("null crypto config not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config1.ini"), null);
      fail("null key container not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void constructorTest() throws Exception {
    BatchWriterConfig config = new BatchWriterConfig();
    new SignedBatchWriter(mockConnector, TEST_TABLE, config, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
    verify(mockConnector).createBatchWriter(TEST_TABLE, config);
  }

  @Test
  public void constructorExternalTest() throws Exception {
    BatchWriterConfig config = new BatchWriterConfig();
    new SignedBatchWriter(mockConnector, TEST_TABLE, config, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.ECDSA));
    verify(mockConnector).createBatchWriter(TEST_TABLE, config);
    verify(mockConnector).createBatchWriter(SIG_TABLE, config);
  }

  @Test
  public void addMutationValueTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    BatchWriter writer = new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
    EntrySigner signer = new EntrySigner(getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));

    Mutation mutation = new Mutation("row".getBytes());
    mutation.put("colF".getBytes(), "colQ".getBytes(), "val1".getBytes());
    mutation.put("colF".getBytes(), "colQ".getBytes(), 0, "val2".getBytes());
    writer.addMutation(mutation);

    verify(mockWriter).addMutation(captor.capture());
    verify(mockSignatureWriter, never()).addMutation(any());

    List<Mutation> mutations = captor.getAllValues();
    assertThat("only a single mutation", mutations, hasSize(1));

    Mutation signed = mutations.get(0);
    assertThat("row is unchanged", signed.getRow(), equalTo("row".getBytes()));

    List<ColumnUpdate> updates = signed.getUpdates();
    assertThat("has 2 updates", updates, hasSize(2));

    ColumnUpdate update = updates.get(0);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp not set", update.hasTimestamp(), is(false));
    assertThat("signature in value", update.getColumnFamily(), not(equalTo("val1".getBytes())));

    MutableEntry verified = new MutableEntry(signer.verify(new MutableEntry("row".getBytes(), update).toEntry()));
    assertThat("value was correctly unwrapped", verified.value, equalTo("val1".getBytes()));

    update = updates.get(1);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp is set", update.hasTimestamp(), is(true));
    assertThat("timestamp is correct", update.getTimestamp(), is(0L));
    assertThat("signature in value", update.getColumnFamily(), not(equalTo("val2".getBytes())));

    verified = new MutableEntry(signer.verify(new MutableEntry("row".getBytes(), update).toEntry()));
    assertThat("value was correctly unwrapped", verified.value, equalTo("val2".getBytes()));
  }

  @Test
  public void addMutationColVisTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    BatchWriter writer = new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config2.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
    EntrySigner signer = new EntrySigner(getConfig("config2.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));

    Mutation mutation = new Mutation("row".getBytes());
    mutation.put("colF".getBytes(), "colQ".getBytes(), "val1".getBytes());
    mutation.put("colF".getBytes(), "colQ".getBytes(), 0, "val2".getBytes());
    writer.addMutation(mutation);

    verify(mockWriter).addMutation(captor.capture());
    verify(mockSignatureWriter, never()).addMutation(any());

    List<Mutation> mutations = captor.getAllValues();
    assertThat("only a single mutation", mutations, iterableWithSize(1));

    Mutation signed = mutations.get(0);
    assertThat("row is unchanged", signed.getRow(), equalTo("row".getBytes()));

    List<ColumnUpdate> updates = signed.getUpdates();
    assertThat("has 2 updates", updates, hasSize(2));

    ColumnUpdate update = updates.get(0);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnQualifier(), equalTo("colQ".getBytes()));
    assertThat("colQualifier has the default visibility", new String(update.getColumnVisibility(), Utils.VISIBILITY_CHARSET), startsWith("(default)"));
    assertThat("timestamp not set", update.hasTimestamp(), is(false));
    assertThat("value is unchanged", update.getValue(), equalTo("val1".getBytes()));

    MutableEntry verified = new MutableEntry(signer.verify(new MutableEntry("row".getBytes(), update).toEntry()));
    assertThat("value was correctly unwrapped", verified.value, equalTo("val1".getBytes()));

    update = updates.get(1);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnQualifier(), equalTo("colQ".getBytes()));
    assertThat("colQualifier has the default visibility", new String(update.getColumnVisibility(), Utils.VISIBILITY_CHARSET), startsWith("(default)"));
    assertThat("timestamp is set", update.hasTimestamp(), is(true));
    assertThat("timestamp is correct", update.getTimestamp(), is(0L));
    assertThat("value is unchanged", update.getValue(), equalTo("val2".getBytes()));

    verified = new MutableEntry(signer.verify(new MutableEntry("row".getBytes(), update).toEntry()));
    assertThat("value was correctly unwrapped", verified.value, equalTo("val2".getBytes()));
  }

  @Test
  public void addMutationSeparateTableTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    when(mockConnector.createBatchWriter(SIG_TABLE, null)).thenReturn(mockSignatureWriter);

    BatchWriter writer = new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.ECDSA));
    EntrySigner signer = new EntrySigner(getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.ECDSA));

    Mutation mutation = new Mutation("row".getBytes());
    mutation.put("colF".getBytes(), "colQ".getBytes(), "val1".getBytes());
    mutation.put("colF".getBytes(), "colQ".getBytes(), 0, "val2".getBytes());
    writer.addMutation(mutation);

    verify(mockWriter).addMutation(captor.capture());
    verify(mockSignatureWriter).addMutation(signatureCaptor.capture());

    // Check entry
    List<Mutation> mutations = captor.getAllValues();
    assertThat("only a single mutation", mutations, hasSize(1));

    Mutation signed = mutations.get(0);
    assertThat("row is unchanged", signed.getRow(), equalTo("row".getBytes()));

    List<ColumnUpdate> updates = signed.getUpdates();
    assertThat("has 2 updates", updates, hasSize(2));

    ColumnUpdate update = updates.get(0);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp not set", update.hasTimestamp(), is(false));
    assertThat("value is unchanged", update.getValue(), equalTo("val1".getBytes()));

    update = updates.get(1);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp is set", update.hasTimestamp(), is(true));
    assertThat("timestamp is correct", update.getTimestamp(), is(0L));
    assertThat("value is unchanged", update.getValue(), equalTo("val2".getBytes()));

    // Check signature.
    mutations = signatureCaptor.getAllValues();
    assertThat("only a single mutation", mutations, hasSize(1));

    signed = mutations.get(0);
    assertThat("row is unchanged", signed.getRow(), equalTo("row".getBytes()));

    updates = signed.getUpdates();
    assertThat("has 2 updates", updates, hasSize(2));

    update = updates.get(0);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp not set", update.hasTimestamp(), is(false));
    assertThat("signature in value", update.getColumnFamily(), not(equalTo("val1".getBytes())));

    update = updates.get(1);
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp is set", update.hasTimestamp(), is(true));
    assertThat("timestamp is correct", update.getTimestamp(), is(0L));
    assertThat("signature in value", update.getColumnFamily(), not(equalTo("val2".getBytes())));

    // Verify unwrapping of entry.
    MutableEntry verified = new MutableEntry(signer.verify(new MutableEntry("row".getBytes(), captor.getAllValues().get(0).getUpdates().get(0)).toEntry(),
        new MutableEntry("row".getBytes(), signatureCaptor.getAllValues().get(0).getUpdates().get(0)).toEntry()));
    assertThat("value was correctly unwrapped", verified.value, equalTo("val1".getBytes()));
  }

  @Test
  public void deleteTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    BatchWriter writer = new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));

    Mutation mutation = new Mutation("row".getBytes());
    mutation.putDelete("colF".getBytes(), "colQ".getBytes());
    mutation.putDelete("colF".getBytes(), "colQ".getBytes(), 0L);
    writer.addMutation(mutation);

    verify(mockWriter).addMutation(captor.capture());
    verify(mockSignatureWriter, never()).addMutation(any());

    List<Mutation> mutations = captor.getAllValues();
    assertThat("only a single mutation", mutations, iterableWithSize(1));

    Mutation signed = mutations.get(0);
    assertThat("row is unchanged", signed.getRow(), equalTo("row".getBytes()));

    List<ColumnUpdate> updates = signed.getUpdates();
    assertThat("has 2 updates", updates, hasSize(2));

    ColumnUpdate update = updates.get(0);
    assertThat("is delete operation", update.isDeleted(), is(true));
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnQualifier(), equalTo("colQ".getBytes()));
    assertThat("timestamp is not set", update.hasTimestamp(), is(false));

    update = updates.get(1);
    assertThat("is delete operation", update.isDeleted(), is(true));
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnQualifier(), equalTo("colQ".getBytes()));
    assertThat("timestamp is set", update.hasTimestamp(), is(true));
    assertThat("timestamp is correct", update.getTimestamp(), is(0L));
  }

  @Test
  public void deleteColVisTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    BatchWriter writer = new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config2.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));

    Mutation mutation = new Mutation("row".getBytes());
    mutation.putDelete("colF1".getBytes(), "colQ".getBytes());
    mutation.putDelete("colF1".getBytes(), "colQ".getBytes(), 0L);

    try {
      writer.addMutation(mutation);
      fail("signed deletes are not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void deleteExternalTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    when(mockConnector.createBatchWriter(SIG_TABLE, null)).thenReturn(mockSignatureWriter);

    BatchWriter writer = new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.ECDSA));

    Mutation mutation = new Mutation("row".getBytes());
    mutation.putDelete("colF".getBytes(), "colQ".getBytes());
    mutation.putDelete("colF".getBytes(), "colQ".getBytes(), 0);
    writer.addMutation(mutation);

    verify(mockWriter).addMutation(captor.capture());
    verify(mockSignatureWriter).addMutation(signatureCaptor.capture());

    // Check entry
    List<Mutation> mutations = captor.getAllValues();
    assertThat("only a single mutation", mutations, hasSize(1));

    Mutation signed = mutations.get(0);
    assertThat("row is unchanged", signed.getRow(), equalTo("row".getBytes()));

    List<ColumnUpdate> updates = signed.getUpdates();
    assertThat("has 2 updates", updates, hasSize(2));

    ColumnUpdate update = updates.get(0);
    assertThat("is delete operation", update.isDeleted(), is(true));
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp not set", update.hasTimestamp(), is(false));

    update = updates.get(1);
    assertThat("is delete operation", update.isDeleted(), is(true));
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp is set", update.hasTimestamp(), is(true));
    assertThat("timestamp is correct", update.getTimestamp(), is(0L));

    // Check signature.
    mutations = signatureCaptor.getAllValues();
    assertThat("only a single mutation", mutations, hasSize(1));

    signed = mutations.get(0);
    assertThat("row is unchanged", signed.getRow(), equalTo("row".getBytes()));

    updates = signed.getUpdates();
    assertThat("has 2 updates", updates, hasSize(2));

    update = updates.get(0);
    assertThat("is delete operation", update.isDeleted(), is(true));
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp not set", update.hasTimestamp(), is(false));

    update = updates.get(1);
    assertThat("is delete operation", update.isDeleted(), is(true));
    assertThat("column family is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("column qualifier is unchanged", update.getColumnFamily(), equalTo("colF".getBytes()));
    assertThat("timestamp is set", update.hasTimestamp(), is(true));
    assertThat("timestamp is correct", update.getTimestamp(), is(0L));
  }

  @Test
  public void addMutationsTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);

    BatchWriter writer = new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));

    List<Mutation> mutations = new ArrayList<>();
    Mutation mutation = new Mutation("row");
    mutation.put("colF", "colQ", "val");

    mutations.add(mutation);
    writer.addMutations(mutations);
    verify(mockWriter, times(1)).addMutation(any()); // 1 time
    verify(mockSignatureWriter, never()).addMutation(any());

    mutations.add(mutation);
    writer.addMutations(mutations);
    verify(mockWriter, times(3)).addMutation(any()); // 1 + 2 times
    verify(mockSignatureWriter, never()).addMutation(any());

    mutations.add(mutation);
    writer.addMutations(mutations);
    verify(mockWriter, times(6)).addMutation(any()); // 1 + 2 + 3 times
    verify(mockSignatureWriter, never()).addMutation(any());
  }

  @Test
  public void addMutationsExternalTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    when(mockConnector.createBatchWriter(SIG_TABLE, null)).thenReturn(mockSignatureWriter);

    BatchWriter writer = new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.ECDSA));

    List<Mutation> mutations = new ArrayList<>();
    Mutation mutation = new Mutation("row");
    mutation.put("colF", "colQ", "val");

    mutations.add(mutation);
    writer.addMutations(mutations);
    verify(mockWriter, times(1)).addMutation(any()); // 1 time
    verify(mockSignatureWriter, times(1)).addMutation(any()); // 1 time

    mutations.add(mutation);
    writer.addMutations(mutations);
    verify(mockWriter, times(3)).addMutation(any()); // 1 + 2 times
    verify(mockSignatureWriter, times(3)).addMutation(any()); // 1 + 2 times

    mutations.add(mutation);
    writer.addMutations(mutations);
    verify(mockWriter, times(6)).addMutation(any()); // 1 + 2 + 3 times
    verify(mockSignatureWriter, times(6)).addMutation(any()); // 1 + 2 + 3 times
  }

  @Test
  public void flushTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);

    new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).flush();
    verify(mockWriter).flush();
  }

  @Test
  public void flushExternalTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    when(mockConnector.createBatchWriter(SIG_TABLE, null)).thenReturn(mockSignatureWriter);

    new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.ECDSA)).flush();
    verify(mockWriter).flush();
    verify(mockSignatureWriter).flush();
  }

  @Test
  public void closeTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);

    new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).close();
    verify(mockWriter).close();
  }

  @Test
  public void closeExternalTest() throws Exception {
    when(mockConnector.createBatchWriter(TEST_TABLE, null)).thenReturn(mockWriter);
    when(mockConnector.createBatchWriter(SIG_TABLE, null)).thenReturn(mockSignatureWriter);

    new SignedBatchWriter(mockConnector, TEST_TABLE, null, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.ECDSA)).close();
    verify(mockWriter).close();
    verify(mockSignatureWriter).close();
  }

  /**
   * Get an encryptor config.
   *
   * @param resource
   *          Resource file containing the configuration.
   * @return EncryptionConfig.
   */
  private SignatureConfig getConfig(String resource) throws Exception {
    return new SignatureConfigBuilder().readFromFile(new InputStreamReader(TestUtils.getResourceAsStream(this.getClass(), resource))).build();
  }

}
