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
package edu.mit.ll.pace.test.utils;

import java.security.SecureRandom;
import java.util.SortedMap;
import java.util.TreeMap;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;

/**
 * Static class for generating random entries.
 */
public class GenerateRandomEntries {

  /**
   * A random number generator to use for key generation.
   */
  private static final SecureRandom random = new SecureRandom();

  // private constructor
  private GenerateRandomEntries() {}

  /**
   * Get random data.
   *
   * @param count
   *          Number of entries to create.
   * @param size
   *          Size (in bytes) of the various fields.
   * @param colVisValue
   *          Value to use for colVis.
   */
  static SortedMap<Key,Value> getRandomData(int count, int size, byte[] colVisValue) {
    return getRandomData(count, size, size, size, colVisValue, size);
  }

  /**
   * Get random data.
   *
   * @param count
   *          Number of entries to create.
   * @param rowSize
   *          Size (in bytes) of the row.
   * @param colFSize
   *          Size (in bytes) of the column family.
   * @param colQSize
   *          Size (in bytes) of the column qualifier.
   * @param colVisValue
   *          Value to use for colVis.
   * @param valueSize
   *          Size (in bytes) of the value.
   * @return Random data.
   */
  static SortedMap<Key,Value> getRandomData(int count, int rowSize, int colFSize, int colQSize, byte[] colVisValue, int valueSize) {
    SortedMap<Key,Value> data = new TreeMap<>();

    for (int i = 0; i < count; i++) {
      byte[] row = new byte[rowSize];
      byte[] colF = new byte[colFSize];
      byte[] colQ = new byte[colQSize];
      byte[] colVis = colVisValue.clone();
      byte[] value = new byte[valueSize];

      random.nextBytes(row);
      random.nextBytes(colF);
      random.nextBytes(colQ);
      random.nextBytes(value);
      long timestamp = random.nextLong();

      data.put(new Key(row, colF, colQ, colVis, timestamp, false, false), new Value(value));
    }

    return data;
  }
}
