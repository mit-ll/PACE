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
package edu.mit.ll.pace;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * Test {@link EntryField}.
 */
public final class EntryFieldTest {

  @Test
  public void validEnumTest() {
    assertThat("should have seven values", 7, is(EntryField.values().length));
  }

  @Test
  public void toStringTest() {
    assertThat("toString should return correct value", "row", is(EntryField.ROW.toString()));
    assertThat("toString should return correct value", "colFamily", is(EntryField.COLUMN_FAMILY.toString()));
    assertThat("toString should return correct value", "colQualifier", is(EntryField.COLUMN_QUALIFIER.toString()));
    assertThat("toString should return correct value", "colVisibility", is(EntryField.COLUMN_VISIBILITY.toString()));
    assertThat("toString should return correct value", "timestamp", is(EntryField.TIMESTAMP.toString()));
    assertThat("toString should return correct value", "delete", is(EntryField.DELETE.toString()));
    assertThat("toString should return correct value", "value", is(EntryField.VALUE.toString()));
  }

  @Test
  public void fromStringTest() {
    assertThat("fromString should return correct enum value", EntryField.fromString("row"), is(EntryField.ROW));
    assertThat("fromString should return correct enum value", EntryField.fromString("colFamily"), is(EntryField.COLUMN_FAMILY));
    assertThat("fromString should return correct enum value", EntryField.fromString("colQualifier"), is(EntryField.COLUMN_QUALIFIER));
    assertThat("fromString should return correct enum value", EntryField.fromString("colVisibility"), is(EntryField.COLUMN_VISIBILITY));
    assertThat("fromString should return correct enum value", EntryField.fromString("timestamp"), is(EntryField.TIMESTAMP));
    assertThat("fromString should return correct enum value", EntryField.fromString("delete"), is(EntryField.DELETE));
    assertThat("fromString should return correct enum value", EntryField.fromString("value"), is(EntryField.VALUE));
  }

  @Test(expected = IllegalArgumentException.class)
  public void fromStringFailureTest() {
    EntryField.fromString("bad");
  }

}
