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
package edu.mit.ll.pace.internal;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;

import org.apache.accumulo.core.data.Key;
import org.junit.Test;

/**
 * Test {@link Utils}.
 */
public final class UtilsTest {

  @Test
  public void visibilityCharsetTest() {
    assertThat("correct visibility charset", Utils.VISIBILITY_CHARSET, is(StandardCharsets.US_ASCII));
  }

  @Test
  public void emptyTest() {
    assertThat("correct empty array", Utils.EMPTY, is(equalTo(new Key().getRow().getBytes())));
  }

  @Test
  public void xorTest() {
    byte[] first = new byte[] {0, 1, 2};
    byte[] second = new byte[] {0, 1, 1};

    byte[] result = Utils.xor(first, second);
    assertThat("the return value is the same as the first argument", result == first, is(true));
    assertThat("the correct result was achieved", result, is(equalTo(new byte[] {0, 0, 3})));
  }

  @Test
  public void xorExceptionTest() {
    byte[] first = new byte[] {0, 1, 2};
    byte[] second = new byte[] {0, 1, 2, 3};

    try {
      Utils.xor(null, second);
      fail("null first variable not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      Utils.xor(first, null);
      fail("null second variable not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      Utils.xor(first, second);
      fail("arrays with unequal length not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

}
