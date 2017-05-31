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

import java.util.Iterator;
import java.util.Map.Entry;

import org.apache.accumulo.core.client.BatchScanner;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;

/**
 * Benchmark for reading encrypted entries.
 */
public class EncryptionReadBenchmark extends BenchmarkBase {

  private static final String TEST_TABLE = "SYSTEM_PERFORMANCE_EncryptionReadBenchmark";

  @Param({"", "encryption/encrypt-baseline.ini", "encryption/encrypt-value.ini", "encryption/encrypt-entry.ini", "encryption/searchable.ini"})
  public String configFile;

  public EncryptionReadBenchmark() {
    super(TEST_TABLE);
  }

  @Override
  public void setupTrial() throws Exception {
    super.setupTrial();
    writeRandomEntries(getEncryptedBatchWriter(configFile, TEST_TABLE));
  }

  /**
   * Benchmark creating the scanner, reading the entries, and closing the scanner.
   */
  @Benchmark
  public void benchmark() throws Exception {
    BatchScanner scanner = getEncryptedBatchScanner(configFile, TEST_TABLE);
    Iterator<Entry<Key,Value>> iterator = scanner.iterator();
    while (iterator.hasNext()) {
      iterator.next();
    }
    scanner.close();
  }
}
