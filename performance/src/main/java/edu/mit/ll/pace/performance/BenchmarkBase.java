/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.mit.ll.pace.performance;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.accumulo.core.client.BatchScanner;
import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.MutationsRejectedException;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.commons.lang3.RandomStringUtils;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;

import edu.mit.ll.pace.encryption.EncryptedBatchScanner;
import edu.mit.ll.pace.encryption.EncryptedBatchWriter;
import edu.mit.ll.pace.encryption.EncryptionConfig;
import edu.mit.ll.pace.encryption.EncryptionConfigBuilder;
import edu.mit.ll.pace.encryption.EncryptionKeyContainer;
import edu.mit.ll.pace.harness.AccumuloInstance;
import edu.mit.ll.pace.harness.User;
import edu.mit.ll.pace.signature.SignatureConfig;
import edu.mit.ll.pace.signature.SignatureConfigBuilder;
import edu.mit.ll.pace.signature.SignatureKeyContainer;
import edu.mit.ll.pace.signature.SignedBatchWriter;
import edu.mit.ll.pace.signature.SignedScanner;
import edu.mit.ll.pace.signature.ValueSigner;

/**
 * Benchmark for reading encrypted entries.
 */
@BenchmarkMode(Mode.SingleShotTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 10)
@Measurement(iterations = 100)
@Fork(value = 10)
@State(Scope.Benchmark)
public abstract class BenchmarkBase {

  private static final String USER_NAME = "AccumuloUser";
  private static final ColumnVisibility VISIBILITY = new ColumnVisibility("\"doctor\"|(nurse&admin)");

  @Param({"100", "10"})
  public int keyFieldSize;

  @Param({"1000", "10"})
  public int valueFieldSize;

  @Param({"1000", "100", "10", "1"})
  public int rowCount;

  @Param({"10", "1"})
  public int columnCount;

  // Class params.
  private Connector connector;
  private Authorizations authorizations;
  private EncryptionKeyContainer encryptionKeys;
  private Map<ValueSigner,SignatureKeyContainer> signatureKeys;
  private final String[] tables;

  // Random number generator with set seed. Ensures that each test uses the same "random" data.
  private final Random rand = new Random(699838332);

  BenchmarkBase(String... tables) {
    this.tables = tables;
  }

  /**
   * Ensures Accumulo and the test are ready.
   */
  @Setup(Level.Trial)
  public void setupTrial() throws Exception {
    AccumuloInstance.setup();
    connector = AccumuloInstance.getConnector(USER_NAME);

    User user = AccumuloInstance.getUser(USER_NAME);
    authorizations = user.authorizations;
    encryptionKeys = user.encryptionKeys;
    signatureKeys = user.signatureKeys;

    for (String table : tables) {
      AccumuloInstance.createTable(table);
    }
  }

  /**
   * Ensures Accumulo and test are cleaned up.
   */
  @TearDown(Level.Trial)
  public void teardownTrial() throws Exception {
    for (String table : tables) {
      AccumuloInstance.deleteTable(table);
    }

    AccumuloInstance.teardown();
  }

  /**
   * Get an encrypted batch writer.
   *
   * @param configFile
   *          Configuration file to use, or empty if wanting a non-encrypted batch writer.
   * @param table
   *          Table to create the writer for.
   * @return Encrypted batch writer, or normal batch writer if configFile is empty.
   */
  BatchWriter getEncryptedBatchWriter(String configFile, String table) throws IOException, TableNotFoundException {
    if (configFile.isEmpty()) {
      return connector.createBatchWriter(table, null);
    } else {
      EncryptionConfig config = new EncryptionConfigBuilder().readFromFile(new InputStreamReader(BenchmarkBase.class.getResourceAsStream(configFile))).build();
      return new EncryptedBatchWriter(connector, table, null, config, encryptionKeys);
    }
  }

  /**
   * Get an encrypted batch scanner.
   *
   * @param configFile
   *          Configuration file to use, or empty if wanting a non-encrypted batch scanner.
   * @param table
   *          Table to create the scanner for.
   * @return Encrypted batch scanner, or normal batch scanner if configFile is empty.
   */
  BatchScanner getEncryptedBatchScanner(String configFile, String table) throws IOException, TableNotFoundException {
    BatchScanner scanner;
    if (configFile.isEmpty()) {
      scanner = connector.createBatchScanner(table, authorizations, 1);
    } else {
      EncryptionConfig config = new EncryptionConfigBuilder().readFromFile(new InputStreamReader(BenchmarkBase.class.getResourceAsStream(configFile))).build();
      scanner = new EncryptedBatchScanner(connector, table, authorizations, 1, config, encryptionKeys);
    }

    scanner.setRanges(Collections.singletonList(new Range()));
    return scanner;
  }

  /**
   * Get a signed batch writer.
   *
   * @param configFile
   *          Configuration file to use, or empty if wanting a non-signed batch writer.
   * @param table
   *          Table to create the writer for.
   * @return Signed batch writer, or normal batch writer if configFile is empty.
   */
  BatchWriter getSignedBatchWriter(String configFile, String table) throws IOException, TableNotFoundException {
    if (configFile.isEmpty()) {
      return connector.createBatchWriter(table, null);
    } else {
      SignatureConfig config = new SignatureConfigBuilder().readFromFile(new InputStreamReader(BenchmarkBase.class.getResourceAsStream(configFile))).build();
      return new SignedBatchWriter(connector, table, null, config, signatureKeys.get(config.getAlgorithm()));
    }
  }

  /**
   * Get a signed scanner.
   *
   * @param configFile
   *          Configuration file to use, or empty if wanting a non-signed scanner.
   * @param table
   *          Table to create the scanner for.
   * @return Signed scanner, or normal scanner if configFile is empty.
   */
  Scanner getSignedScanner(String configFile, String table) throws IOException, TableNotFoundException {
    if (configFile.isEmpty()) {
      return connector.createScanner(table, authorizations);
    } else {
      SignatureConfig config = new SignatureConfigBuilder().readFromFile(new InputStreamReader(BenchmarkBase.class.getResourceAsStream(configFile))).build();
      return new SignedScanner(connector, table, authorizations, config, signatureKeys.get(config.getAlgorithm()));
    }
  }

  /**
   * Write random entries.
   * <p>
   * Closes the writer after entries are written.
   *
   * @param writer
   *          Writer to write entries to.
   */
  void writeRandomEntries(BatchWriter writer) throws MutationsRejectedException {
    for (int i = 0; i < rowCount; i++) {
      byte[] row = getRandomBytes(keyFieldSize, true);

      for (int j = 0; j < columnCount; j++) {
        byte[] colF = getRandomBytes(keyFieldSize, true);
        byte[] colQ = getRandomBytes(keyFieldSize, true);
        byte[] value = getRandomBytes(valueFieldSize, false);

        Mutation mutation = new Mutation(row);
        mutation.put(colF, colQ, VISIBILITY, value);
        writer.addMutation(mutation);
      }
    }

    writer.close();
  }

  /**
   * Get random mutations to be written.
   *
   * @return Mutations.
   */
  List<Mutation> getMutations() {
    List<Mutation> mutations = new ArrayList<>(rowCount);
    for (int i = 0; i < rowCount; i++) {
      byte[] row = getRandomBytes(keyFieldSize, true);

      Mutation mutation = new Mutation(row);
      mutations.add(mutation);

      for (int j = 0; j < columnCount; j++) {
        byte[] colF = getRandomBytes(keyFieldSize, true);
        byte[] colQ = getRandomBytes(keyFieldSize, true);
        byte[] value = getRandomBytes(valueFieldSize, false);

        mutation.put(colF, colQ, VISIBILITY, value);
      }
    }
    return mutations;
  }

  /**
   * Get random bytes.
   *
   * @param count
   *          Number of bytes.
   * @param textual
   *          Whether the generated data should be textual.
   * @return The random bytes.
   */
  private byte[] getRandomBytes(int count, boolean textual) {
    if (textual) {
      return RandomStringUtils.random(count, 0, 0, true, true, null, rand).getBytes(StandardCharsets.US_ASCII);
    } else {
      byte[] data = new byte[count];
      rand.nextBytes(data);
      return data;
    }
  }

}
