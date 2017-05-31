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

import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;

/**
 * Benchmark for reading signed entries.
 */
public class SignatureReadBenchmark extends BenchmarkBase {

  private static final String TEST_TABLE = "SYSTEM_PERFORMANCE_SignatureReadBenchmark";
  private static final String TEST_SIGNATURE_TABLE = "SYSTEM_PERFORMANCE_SignatureReadBenchmark_Signatures";

  @Param({"", "signature/read/value.ini", "signature/read/column.ini", "signature/read/table.ini", "signature/rsa-pkcs1.ini", "signature/dsa.ini",
      "signature/ecdsa.ini"})
  public String configFile;

  public SignatureReadBenchmark() {
    super(TEST_TABLE, TEST_SIGNATURE_TABLE);
  }

  @Override
  public void setupTrial() throws Exception {
    super.setupTrial();
    writeRandomEntries(getSignedBatchWriter(configFile, TEST_TABLE));
  }

  /**
   * Benchmark creating the scanner, reading the entries, and closing the scanner.
   */
  @Benchmark
  public void benchmark() throws Exception {
    Scanner scanner = getSignedScanner(configFile, TEST_TABLE);
    Iterator<Entry<Key,Value>> iterator = scanner.iterator();
    while (iterator.hasNext()) {
      iterator.next();
    }
    scanner.close();
  }
}
