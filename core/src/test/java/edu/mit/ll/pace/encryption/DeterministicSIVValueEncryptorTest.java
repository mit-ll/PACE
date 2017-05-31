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
import static edu.mit.ll.pace.test.TestUtils.wrap;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.isA;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.arrayContaining;
import static org.junit.Assert.assertThat;

import org.cryptomator.siv.UnauthenticCiphertextException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Test {@link DeterministicSIVValueEncryptor}.
 */
public class DeterministicSIVValueEncryptorTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void deterministicSivEncryptionTest() throws Exception {
    ValueEncryptorBase encryptor = ValueEncryptor.AES_SIV_DETERMINISTIC.getInstance(null);
    byte[] plaintext = "1234".getBytes(VISIBILITY_CHARSET);
    byte[] key = "aabbccddaabbccddaabbccddaabbccdd".getBytes(VISIBILITY_CHARSET);

    byte[] ciphertext1 = encryptor.encrypt(key, plaintext);
    assertThat("ciphertext should not contain the original plaintext", wrap(ciphertext1), is(not(arrayContaining(wrap(plaintext)))));

    byte[] plaintext1 = encryptor.decrypt(key, ciphertext1);
    assertThat("decrypting the ciphertext should give the plaintext", plaintext1, is(equalTo(plaintext)));

    byte[] ciphertext2 = encryptor.encrypt(key, plaintext);
    assertThat("ciphertext should be the same when identical values are encrypted", ciphertext2, is(equalTo(ciphertext1)));

    byte[] ciphertext3 = encryptor.encrypt(key, "1235".getBytes(VISIBILITY_CHARSET));
    assertThat("ciphertext should be not be the same when different values are encrypted", ciphertext3, is(not(equalTo(ciphertext1))));
  }

  @Test
  public void authenticatedEncryptionMacFailureTest() throws Exception {
    ValueEncryptorBase encryptor = ValueEncryptor.AES_SIV_DETERMINISTIC.getInstance(null);
    byte[] plaintext = "1234567890123457".getBytes(VISIBILITY_CHARSET);
    byte[] key = "aabbccddaabbccddaabbccddaabbccdd".getBytes(VISIBILITY_CHARSET);

    byte[] ciphertext = encryptor.encrypt(key, plaintext);
    ciphertext[20] = (byte) 0;

    thrown.expect(EncryptionException.class);
    thrown.expectCause(isA(UnauthenticCiphertextException.class));
    encryptor.decrypt(key, ciphertext);
  }

}
