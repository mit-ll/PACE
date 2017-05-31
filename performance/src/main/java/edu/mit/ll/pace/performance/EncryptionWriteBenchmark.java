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

import java.util.List;

import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.data.Mutation;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Setup;

/**
 * Benchmark for writing encrypted entries.
 */
public class EncryptionWriteBenchmark extends BenchmarkBase {

  private static final String TEST_TABLE = "SYSTEM_PERFORMANCE_EncryptionWriteBenchmark";
  private List<Mutation> mutations;

  @Param({"", "encryption/encrypt-baseline.ini", "encryption/encrypt-value.ini", "encryption/encrypt-entry.ini", "encryption/searchable.ini"})
  public String configFile;

  public EncryptionWriteBenchmark() {
    super(TEST_TABLE);
  }

  @Setup(Level.Iteration)
  public void setMutations() throws Exception {
    mutations = getMutations();
  }

  /**
   * Benchmark creating the writer, writing the entries, and closing the writer.
   * <p>
   * Generation of entries is also benchmarked. These could be generated before the fact, but that significantly increases the memory strain on the benchmark.
   */
  @Benchmark
  public void benchmark() throws Exception {
    BatchWriter writer = getEncryptedBatchWriter(configFile, TEST_TABLE);
    writer.addMutations(mutations);
    writer.close();
  }

}
