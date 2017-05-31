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

import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;
import static edu.mit.ll.pace.test.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.InputStreamReader;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Random;

import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.commons.io.IOUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import edu.mit.ll.pace.encryption.EncryptedBatchScanner;
import edu.mit.ll.pace.encryption.EncryptedBatchWriter;
import edu.mit.ll.pace.encryption.EncryptionConfig;
import edu.mit.ll.pace.encryption.EncryptionConfigBuilder;
import edu.mit.ll.pace.harness.AccumuloInstance;
import edu.mit.ll.pace.harness.AccumuloRunner;
import edu.mit.ll.pace.test.TestUtils;

/**
 * Test the batch writer functionality.
 */
@RunWith(AccumuloRunner.class)
public class BatchWriteReadIT {

  private final static String USER = "Charlie";
  private final static String UNENCRYPTED_TEST_TABLE = "BatchWriteReadIT";
  private final static String ENCRYPTED_TEST_TABLE = "BatchWriteReadIT_Encrypted";

  @BeforeClass
  public static void setup() throws Exception {
    AccumuloInstance.createTable(UNENCRYPTED_TEST_TABLE);
    AccumuloInstance.createTable(ENCRYPTED_TEST_TABLE);
  }

  @AfterClass
  public static void teardown() throws Exception {
    AccumuloInstance.deleteTable(UNENCRYPTED_TEST_TABLE);
    AccumuloInstance.deleteTable(ENCRYPTED_TEST_TABLE);
  }

  public void change(EncryptionConfig config) throws Exception {
    Random random = new Random();
    List<Entry<Key,Value>> entries = new ArrayList<>();

    for (int i = 0; i < 1000; i++) {
      byte[] bytes = new byte[32 * 4];
      random.nextBytes(bytes);
      entries.add(new AbstractMap.SimpleImmutableEntry<>(new Key(Arrays.copyOfRange(bytes, 0, 32), Arrays.copyOfRange(bytes, 32, 64), Arrays.copyOfRange(bytes,
          64, 96), "secret".getBytes(VISIBILITY_CHARSET), (long) 0, false), new Value(Arrays.copyOfRange(bytes, 96, 128))));
    }

    // Write the entries to Accumulo.
    BatchWriter writer = AccumuloInstance.getConnector(USER).createBatchWriter(UNENCRYPTED_TEST_TABLE, null);
    BatchWriter encryptedWriter = new EncryptedBatchWriter(AccumuloInstance.getConnector(USER), ENCRYPTED_TEST_TABLE, null, config,
        AccumuloInstance.getUser(USER).encryptionKeys);

    for (Entry<Key,Value> entry : entries) {
      Key key = entry.getKey();
      Mutation mutation = new Mutation(entry.getKey().getRow());

      if (key.isDeleted()) {
        mutation.putDelete(key.getColumnFamily(), key.getColumnQualifier(), key.getColumnVisibilityParsed(), key.getTimestamp());
      } else {
        mutation.put(key.getColumnFamily(), key.getColumnQualifier(), key.getColumnVisibilityParsed(), key.getTimestamp(), entry.getValue());
      }

      writer.addMutation(mutation);
      encryptedWriter.addMutation(mutation);
    }

    writer.close();
    encryptedWriter.close();
  }

  public void check(EncryptionConfig config) throws Exception {
    Scanner scanner = AccumuloInstance.getConnector(USER).createScanner(UNENCRYPTED_TEST_TABLE, AccumuloInstance.getUser(USER).authorizations);
    EncryptedBatchScanner encryptedScanner = new EncryptedBatchScanner(AccumuloInstance.getConnector(USER), ENCRYPTED_TEST_TABLE,
        AccumuloInstance.getUser(USER).authorizations, 1, config, AccumuloInstance.getUser(USER).encryptionKeys);

    for (Entry<Key,Value> entry : scanner) {
      // Search for the entry.
      encryptedScanner.setRanges(Collections.singletonList(new Range(entry.getKey(), entry.getKey())));
      Iterator<Entry<Key,Value>> iterator = encryptedScanner.iterator();

      assertThat("should have an entry that matches", iterator.hasNext(), is(true));
      assertThat("entries match", iterator.next(), equalTo(entry));
      assertThat("should have no more entries", iterator.hasNext(), is(false));
    }
  }

  @Test
  public void test() throws Exception {
    for (EncryptionConfig config : getConfigs()) {
      change(config);
      check(config);
      AccumuloInstance.clearTable(UNENCRYPTED_TEST_TABLE);
      AccumuloInstance.clearTable(ENCRYPTED_TEST_TABLE);
    }
  }

  /**
   * Get the value encryptor configs for this test class.
   *
   * @return Configs.
   */
  private Collection<EncryptionConfig> getConfigs() throws Exception {
    List<EncryptionConfig> configs = new ArrayList<>();

    // Add the default configurations from the core jar.
    final String PREFIX = "/edu/mit/ll/pace/encryption";
    for (String line : IOUtils.readLines(this.getClass().getResourceAsStream(PREFIX))) {
      if (line.endsWith(".ini") && !line.contains("/")) {
        // Only get INI files from the first level.
        configs.add(new EncryptionConfigBuilder().readFromFile(new InputStreamReader(this.getClass().getResourceAsStream(PREFIX + "/" + line))).build());
      }
    }

    // Add local configs.
    configs.add(new EncryptionConfigBuilder().readFromFile(new InputStreamReader(TestUtils.getResourceAsStream(this.getClass(), "obfuscate-key.ini"))).build());

    return configs;
  }

}
