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
package edu.mit.ll.pace.encryption;

import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.junit.Assert.assertThat;

import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.mit.ll.pace.test.TestUtils;

/**
 * Test {@link ValueEncryptor}.
 */
public final class ValueEncryptorTest {

  @BeforeClass
  public static void registerBouncyCastle() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void validEnumTest() {
    assertThat("should have six values", ValueEncryptor.values(), is(arrayWithSize(6)));
  }

  @Test
  public void toStringTest() {
    assertThat("toString should return correct value", ValueEncryptor.AES_SIV_DETERMINISTIC.toString(), is("AES_SIV_DETERMINISTIC"));
    assertThat("toString should return correct value", ValueEncryptor.AES_CTR.toString(), is("AES_CTR"));
    assertThat("toString should return correct value", ValueEncryptor.AES_CFB.toString(), is("AES_CFB"));
    assertThat("toString should return correct value", ValueEncryptor.AES_CBC.toString(), is("AES_CBC"));
    assertThat("toString should return correct value", ValueEncryptor.AES_OFB.toString(), is("AES_OFB"));
    assertThat("toString should return correct value", ValueEncryptor.AES_GCM.toString(), is("AES_GCM"));
  }

  @Test
  public void fromStringTest() {
    assertThat("fromString should return correct enum value", ValueEncryptor.fromString("AES_SIV_DETERMINISTIC"), is(ValueEncryptor.AES_SIV_DETERMINISTIC));
    assertThat("fromString should return correct enum value", ValueEncryptor.fromString("AES_CTR"), is(ValueEncryptor.AES_CTR));
    assertThat("fromString should return correct enum value", ValueEncryptor.fromString("AES_CFB"), is(ValueEncryptor.AES_CFB));
    assertThat("fromString should return correct enum value", ValueEncryptor.fromString("AES_CBC"), is(ValueEncryptor.AES_CBC));
    assertThat("fromString should return correct enum value", ValueEncryptor.fromString("AES_OFB"), is(ValueEncryptor.AES_OFB));
    assertThat("fromString should return correct enum value", ValueEncryptor.fromString("AES_GCM"), is(ValueEncryptor.AES_GCM));
  }

  @Test(expected = IllegalArgumentException.class)
  public void fromStringFailureTest() {
    ValueEncryptor.fromString("bad");
  }

  @Test
  public void isDeterministicTest() {
    assertThat("isDeterministic is true", ValueEncryptor.AES_SIV_DETERMINISTIC.isDeterministic(), is(true));
    assertThat("isDeterministic is false", ValueEncryptor.AES_CTR.isDeterministic(), is(false));
    assertThat("isDeterministic is false", ValueEncryptor.AES_CFB.isDeterministic(), is(false));
    assertThat("isDeterministic is false", ValueEncryptor.AES_CBC.isDeterministic(), is(false));
    assertThat("isDeterministic is false", ValueEncryptor.AES_OFB.isDeterministic(), is(false));
    assertThat("isDeterministic is false", ValueEncryptor.AES_GCM.isDeterministic(), is(false));
  }

  @Test
  public void getDefaultKeyLengthTest() {
    assertThat("correct default key (32)", ValueEncryptor.AES_SIV_DETERMINISTIC.getDefaultKeyLength(), is(32));
    assertThat("correct default key (16)", ValueEncryptor.AES_CTR.getDefaultKeyLength(), is(16));
    assertThat("correct default key (16)", ValueEncryptor.AES_CFB.getDefaultKeyLength(), is(16));
    assertThat("correct default key (16)", ValueEncryptor.AES_CBC.getDefaultKeyLength(), is(16));
    assertThat("correct default key (16)", ValueEncryptor.AES_OFB.getDefaultKeyLength(), is(16));
    assertThat("correct default key (16)", ValueEncryptor.AES_GCM.getDefaultKeyLength(), is(16));
  }

  @Test
  public void isValidKeyLengthTest() {
    for (int keyLength : Arrays.asList(16, 24, 32)) {
      for (ValueEncryptor encryptor : ValueEncryptor.values()) {
        switch (encryptor) {
          case AES_SIV_DETERMINISTIC:
            assertThat("isValidKeyLength should accept good key lengths", encryptor.isValidKeyLength(keyLength * 2), is(true));
            assertThat("isValidKeyLength should accept good key lengths", encryptor.isValidKeyLength(keyLength * 2 + 1), is(false));
            break;

          default:
            assertThat("isValidKeyLength should accept good key lengths", encryptor.isValidKeyLength(keyLength), is(true));
            assertThat("isValidKeyLength should accept good key lengths", encryptor.isValidKeyLength(keyLength + 1), is(false));
        }
      }
    }
  }

  @Test
  public void getInstanceTest() throws Exception {
    assertThat("should return a valid ValueEncryptorBase instance", ValueEncryptor.AES_SIV_DETERMINISTIC.getInstance(null),
        is(instanceOf(ValueEncryptorBase.class)));
    assertThat("should return a valid ValueEncryptorBase instance", ValueEncryptor.AES_CTR.getInstance(null), is(instanceOf(ValueEncryptorBase.class)));
    assertThat("should return a valid ValueEncryptorBase instance", ValueEncryptor.AES_CFB.getInstance("BC"), is(instanceOf(ValueEncryptorBase.class)));
    assertThat("should return a valid ValueEncryptorBase instance", ValueEncryptor.AES_CBC.getInstance("BC"), is(instanceOf(ValueEncryptorBase.class)));
    assertThat("should return a valid ValueEncryptorBase instance", ValueEncryptor.AES_OFB.getInstance(null), is(instanceOf(ValueEncryptorBase.class)));
    assertThat("should return a valid ValueEncryptorBase instance", ValueEncryptor.AES_GCM.getInstance(null), is(instanceOf(ValueEncryptorBase.class)));
  }

  @Test
  public void encryptionTest() throws Exception {
    // Test each enum value and ensure it can properly encrypt data.
    for (ValueEncryptor encryptorEnum : ValueEncryptor.values()) {
      ValueEncryptorBase encryptor = encryptorEnum.getInstance(null);
      byte[] plaintext = "1234".getBytes(VISIBILITY_CHARSET);
      byte[] key = "aabbccddaabbccddaabbccddaabbccdd".getBytes(VISIBILITY_CHARSET); // 256-bit key valid for all encryptors.

      byte[] ciphertext1 = encryptor.encrypt(key, plaintext);
      assertThat("ciphertext should not contain the original plaintext", TestUtils.wrap(ciphertext1), is(not(arrayContaining(TestUtils.wrap(plaintext)))));

      byte[] plaintext1 = encryptor.decrypt(key, ciphertext1);
      assertThat("decrypting the ciphertext should give the plaintext", plaintext1, is(equalTo(plaintext)));

      byte[] ciphertext2 = encryptor.encrypt(key, "1235".getBytes(VISIBILITY_CHARSET));
      assertThat("ciphertext should be not be the same when different values are encrypted", ciphertext2, is(not(equalTo(ciphertext1))));
    }
  }

}
