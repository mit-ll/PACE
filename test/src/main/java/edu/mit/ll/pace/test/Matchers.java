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
package edu.mit.ll.pace.test;

import static edu.mit.ll.pace.test.TestUtils.CHARSET;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItems;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map.Entry;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.hamcrest.collection.IsIterableWithSize;

import edu.mit.ll.pace.internal.MutableEntry;

/**
 * Hamcrest matchers for use in testing.
 */
public class Matchers {

  /**
   * Gets a hamcrest matcher that tests whether two entires are the same.
   *
   * @param expectedValue
   *          The expected value to core against.
   * @return Method safe matcher that will core equality.
   */
  @Factory
  public static TypeSafeMatcher<Entry<Key,Value>> equalTo(final Entry<Key,Value> expectedValue) {
    return new TypeSafeMatcher<Entry<Key,Value>>() {
      @Override
      protected boolean matchesSafely(Entry<Key,Value> actualValue) {
        return expectedValue.getKey().equals(actualValue.getKey()) && expectedValue.getValue().equals(actualValue.getValue());
      }

      @Override
      protected void describeMismatchSafely(Entry<Key,Value> actualValue, Description description) {
        description.appendText("was {key=").appendValue(actualValue.getKey()).appendText(", value=").appendValue(actualValue.getValue()).appendText("}");
      }

      @Override
      public void describeTo(Description description) {
        description.appendText(" {key=").appendValue(expectedValue.getKey()).appendText(", value=").appendValue(expectedValue.getValue()).appendText("}");
      }
    };
  }

  /**
   * Checks if an {@link Entry} is equal to the given data.
   *
   * @param row
   *          Row to check for.
   * @param colF
   *          Column family to check for.
   * @param colQ
   *          Column qualifier to check for.
   * @param colVis
   *          Column visibility to check for.
   * @param value
   *          Value to check for.
   * @return Hamcrest matcher.
   */
  @Factory
  public static TypeSafeMatcher<Entry<Key,Value>> equalToRow(String row, String colF, String colQ, String colVis, String value) {
    final byte[] rowBytes = row.getBytes(CHARSET);
    final byte[] colFBytes = colF.getBytes(CHARSET);
    final byte[] colQBytes = colQ.getBytes(CHARSET);
    final byte[] colVisBytes = colVis.getBytes(CHARSET);
    final byte[] valueBytes = value.getBytes(CHARSET);

    return new TypeSafeMatcher<Entry<Key,Value>>() {
      @Override
      protected boolean matchesSafely(Entry<Key,Value> actualValue) {
        MutableEntry actualEntry = new MutableEntry(actualValue);
        return Arrays.equals(actualEntry.row, rowBytes) && Arrays.equals(actualEntry.colF, colFBytes) && Arrays.equals(actualEntry.colQ, colQBytes)
            && Arrays.equals(actualEntry.colVis, colVisBytes) && Arrays.equals(actualEntry.value, valueBytes);
      }

      @Override
      protected void describeMismatchSafely(Entry<Key,Value> actualValue, Description description) {
        description.appendText("was");
        MutableEntry actualEntry = new MutableEntry(actualValue);
        describeTo(description, actualEntry.row, actualEntry.colF, actualEntry.colQ, actualEntry.colVis, actualEntry.value);
      }

      @Override
      public void describeTo(Description description) {
        describeTo(description, rowBytes, colFBytes, colQBytes, colVisBytes, valueBytes);
      }

      /**
       * Describe the given values to the description.
       */
      private void describeTo(Description description, byte[] row, byte[] colF, byte[] colQ, byte[] colVis, byte[] value) {
        description.appendText(" {row: ").appendValue(row).appendText(", colF: ").appendValue(colF).appendText(", colQ: ").appendValue(colQ)
            .appendText(", colVis: ").appendValue(colVis).appendText(", value: ").appendValue(value).appendText("}");
      }
    };
  }

  /**
   * Matches the set of entries against the given set of values. The full combinatorial of values passed in is expected in the output set.
   *
   * @param rows
   *          Rows to check for.
   * @param colFs
   *          Column families to check for.
   * @param colQs
   *          Column qualifiers to check for.
   * @param colVs
   *          Column visibilities to check for.
   * @param values
   *          Values to check for.
   * @return Hamcrest matcher.
   */
  @Factory
  @SuppressWarnings("unchecked")
  public static Matcher<Iterable<Entry<Key,Value>>> hasData(Collection<String> rows, Collection<String> colFs, Collection<String> colQs,
      Collection<String> colVs, Collection<String> values) {
    int size = rows.size() * colFs.size() * colQs.size() * colVs.size() * values.size();
    ArrayList<Matcher<? super Iterable<Entry<Key,Value>>>> matchers = new ArrayList<>(size + 1);

    matchers.add(IsIterableWithSize.iterableWithSize(size));

    for (String row : rows) {
      for (String colF : colFs) {
        for (String colQ : colQs) {
          for (String colV : colVs) {
            for (String value : values) {
              matchers.add(hasItems(equalToRow(row, colF, colQ, colV, value)));
            }
          }
        }
      }
    }

    return allOf(matchers);
  }

}
