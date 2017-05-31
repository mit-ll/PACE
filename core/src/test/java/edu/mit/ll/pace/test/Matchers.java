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

import java.util.Map.Entry;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.TypeSafeMatcher;
import org.ini4j.Ini;
import org.ini4j.Profile.Section;

/**
 * Hamcrest matchers for use in testing.
 */
public class Matchers {
  /**
   * Gets a hamcrest matcher that tests whether two objects have the same fields.
   * <p>
   * This check uses reflection.
   *
   * @param expectedValue
   *          The expected value to core against.
   * @return Method safe matcher that will core field equality.
   */
  @Factory
  public static <T> TypeSafeMatcher<T> hasSameFieldsAs(final T expectedValue) {
    return new TypeSafeMatcher<T>() {
      @Override
      protected boolean matchesSafely(T actualValue) {
        return EqualsBuilder.reflectionEquals(expectedValue, actualValue, false);
      }

      @Override
      protected void describeMismatchSafely(T actualValue, Description description) {
        description.appendText("was {").appendText(ReflectionToStringBuilder.toString(actualValue, ToStringStyle.SIMPLE_STYLE)).appendText("}");
      }

      @Override
      public void describeTo(Description description) {
        description.appendText(" {").appendText(ReflectionToStringBuilder.toString(expectedValue, ToStringStyle.SIMPLE_STYLE)).appendText("}");
      }
    };
  }

  /**
   * Gets a hamcrest matcher that tests whether two Ini objects are equal.
   *
   * @param expectedValue
   *          The expected value to core against.
   * @return Method safe matcher that will core field equality.
   */
  @Factory
  public static TypeSafeMatcher<Ini> equalTo(final Ini expectedValue) {
    return new TypeSafeMatcher<Ini>() {
      @Override
      protected boolean matchesSafely(Ini actualValue) {
        if (expectedValue.size() != actualValue.size()) {
          return false;
        }

        for (Section expectedSection : expectedValue.values()) {
          Section actualSection = actualValue.get(expectedSection.getName());
          if (actualSection == null) {
            return false;
          }

          if (expectedSection.size() != actualSection.size()) {
            return false;
          }

          for (Entry<String,String> expectedEntry : expectedSection.entrySet()) {
            if (!actualSection.containsKey(expectedEntry.getKey())) {
              return false;
            }

            String actual = actualSection.get(expectedEntry.getKey());
            String expected = expectedEntry.getValue();
            if ((actual == null && expected != null) || (actual != null && !actual.equals(expected))) {
              return false;
            }

          }
        }

        return true;
      }

      @Override
      public void describeTo(Description description) {
        description.appendValue(expectedValue);
      }
    };
  }

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

}
