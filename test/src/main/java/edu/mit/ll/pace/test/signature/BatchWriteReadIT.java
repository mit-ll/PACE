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
package edu.mit.ll.pace.test.signature;

import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;
import static edu.mit.ll.pace.test.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.InputStreamReader;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Random;

import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Value;
import org.apache.commons.io.IOUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import edu.mit.ll.pace.harness.AccumuloInstance;
import edu.mit.ll.pace.harness.AccumuloRunner;
import edu.mit.ll.pace.signature.SignatureConfig;
import edu.mit.ll.pace.signature.SignatureConfigBuilder;
import edu.mit.ll.pace.signature.SignedBatchWriter;
import edu.mit.ll.pace.signature.SignedScanner;
import edu.mit.ll.pace.test.TestUtils;

/**
 * Test the batch writer functionality.
 */
@RunWith(AccumuloRunner.class)
public class BatchWriteReadIT {

  private final static String USER = "Charlie";
  private final static String UNSIGNED_TEST_TABLE = "BatchWriteReadIT";
  private final static String SIGNED_TEST_TABLE = "BatchWriteReadIT_Signed";

  @BeforeClass
  public static void setup() throws Exception {
    AccumuloInstance.createTable(UNSIGNED_TEST_TABLE);
    AccumuloInstance.createTable(SIGNED_TEST_TABLE);
  }

  @AfterClass
  public static void teardown() throws Exception {
    AccumuloInstance.deleteTable(UNSIGNED_TEST_TABLE);
    AccumuloInstance.deleteTable(SIGNED_TEST_TABLE);
  }

  public void change(SignatureConfig config) throws Exception {
    Random random = new Random();
    List<Entry<Key,Value>> entries = new ArrayList<>();

    for (int i = 0; i < 1000; i++) {
      byte[] bytes = new byte[32 * 4];
      random.nextBytes(bytes);
      entries.add(new AbstractMap.SimpleImmutableEntry<>(new Key(Arrays.copyOfRange(bytes, 0, 32), Arrays.copyOfRange(bytes, 32, 64), Arrays.copyOfRange(bytes,
          64, 96), "secret".getBytes(VISIBILITY_CHARSET), (long) 0, false), new Value(Arrays.copyOfRange(bytes, 96, 128))));
    }

    // Write the entries to Accumulo.
    BatchWriter writer = null;
    BatchWriter signedWriter;

    if (!config.isSignatureInSeparateTable()) {
      writer = AccumuloInstance.getConnector(USER).createBatchWriter(UNSIGNED_TEST_TABLE, null);
      signedWriter = new SignedBatchWriter(AccumuloInstance.getConnector(USER), SIGNED_TEST_TABLE, null, config,
          AccumuloInstance.getUser(USER).signatureKeys.get(config.getAlgorithm()));
    } else {
      signedWriter = new SignedBatchWriter(AccumuloInstance.getConnector(USER), UNSIGNED_TEST_TABLE, null, config,
          AccumuloInstance.getUser(USER).signatureKeys.get(config.getAlgorithm()));
    }

    for (Entry<Key,Value> entry : entries) {
      Key key = entry.getKey();
      Mutation mutation = new Mutation(entry.getKey().getRow());

      if (key.isDeleted()) {
        mutation.putDelete(key.getColumnFamily(), key.getColumnQualifier(), key.getColumnVisibilityParsed(), key.getTimestamp());
      } else {
        mutation.put(key.getColumnFamily(), key.getColumnQualifier(), key.getColumnVisibilityParsed(), key.getTimestamp(), entry.getValue());
      }

      if (writer != null) {
        writer.addMutation(mutation);
      }
      signedWriter.addMutation(mutation);
    }

    if (writer != null) {
      writer.close();
    }
    signedWriter.close();
  }

  public void check(SignatureConfig config) throws Exception {
    Scanner scanner = AccumuloInstance.getConnector(USER).createScanner(UNSIGNED_TEST_TABLE, AccumuloInstance.getUser(USER).authorizations);
    Scanner signedScanner;

    if (!config.isSignatureInSeparateTable()) {
      signedScanner = new SignedScanner(AccumuloInstance.getConnector(USER), SIGNED_TEST_TABLE, AccumuloInstance.getUser(USER).authorizations, config,
          AccumuloInstance.getUser(USER).signatureKeys.get(config.getAlgorithm()));
    } else {
      signedScanner = new SignedScanner(AccumuloInstance.getConnector(USER), UNSIGNED_TEST_TABLE, AccumuloInstance.getUser(USER).authorizations, config,
          AccumuloInstance.getUser(USER).signatureKeys.get(config.getAlgorithm()));
    }

    Iterator<Entry<Key,Value>> iterator = signedScanner.iterator();
    for (Entry<Key,Value> entry : scanner) {
      assertThat("should have an entry that matches", iterator.hasNext(), is(true));
      assertThat("entries match", iterator.next(), equalTo(entry));
    }

    assertThat("should have no more entries", iterator.hasNext(), is(false));
  }

  @Test
  public void test() throws Exception {
    for (SignatureConfig config : getConfigs()) {
      change(config);
      check(config);
      AccumuloInstance.clearTable(UNSIGNED_TEST_TABLE);
      AccumuloInstance.clearTable(SIGNED_TEST_TABLE);
    }
  }

  /**
   * Get the value signature configs for this test class.
   *
   * @return Configs.
   */
  private Collection<SignatureConfig> getConfigs() throws Exception {
    List<SignatureConfig> configs = new ArrayList<>();

    // Add the default configurations from the core jar.
    final String PREFIX = "/edu/mit/ll/pace/signature";
    for (String line : IOUtils.readLines(this.getClass().getResourceAsStream(PREFIX))) {
      if (line.endsWith(".ini") && !line.contains("/")) { // Only get INI files from the first level.
        configs.add(new SignatureConfigBuilder().readFromFile(new InputStreamReader(this.getClass().getResourceAsStream(PREFIX + "/" + line))).build());
      }
    }

    // Add local configs.
    configs.add(new SignatureConfigBuilder().readFromFile(new InputStreamReader(TestUtils.getResourceAsStream(this.getClass(), "config1.ini"))).build());
    configs.add(new SignatureConfigBuilder().readFromFile(new InputStreamReader(TestUtils.getResourceAsStream(this.getClass(), "config2.ini"))).build());
    configs.add(new SignatureConfigBuilder().readFromFile(new InputStreamReader(TestUtils.getResourceAsStream(this.getClass(), "config3.ini"))).build());

    return configs;
  }

}
