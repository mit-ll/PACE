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
package edu.mit.ll.pace.signature;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import edu.mit.ll.pace.signature.SignatureConfig.Destination;

/**
 * Test for {@link Destination}.
 */
public class SignatureConfigDestinationTest {

  @Test
  public void validEnumTest() {
    assertThat("should have three values", Destination.values(), is(arrayWithSize(3)));
  }

  @Test
  public void toStringTest() {
    assertThat("toString should return correct value", Destination.VALUE.toString(), is("value"));
    assertThat("toString should return correct value", Destination.COLUMN_VISIBILITY.toString(), is("colVis"));
    assertThat("toString should return correct value", Destination.SEPARATE_TABLE.toString(), is("table"));
  }

  @Test
  public void fromStringTest() {
    assertThat("fromString should return correct enum value", Destination.fromString("value"), is(Destination.VALUE));
    assertThat("fromString should return correct enum value", Destination.fromString("colVis"), is(Destination.COLUMN_VISIBILITY));
    assertThat("fromString should return correct enum value", Destination.fromString("table"), is(Destination.SEPARATE_TABLE));
  }

  @Test
  public void fromStringExceptionTest() {
    try {
      Destination.fromString("bad");
      fail("only valid names should be allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

}
