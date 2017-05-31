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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.emptyArray;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.mit.ll.pace.test.TestUtils;

/**
 * Test for {@link ValueSigner}.
 */
public class ValueSignerTest {

  @BeforeClass
  public static void setupBouncyCastle() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void validEnumTest() {
    assertThat("should have four values", ValueSigner.values(), is(arrayWithSize(4)));
  }

  @Test
  public void toStringTest() {
    assertThat("toString should return correct value", ValueSigner.RSA_PKCS1.toString(), is("RSA-PKCS1"));
    assertThat("toString should return correct value", ValueSigner.RSA_PSS.toString(), is("RSA-PSS"));
    assertThat("toString should return correct value", ValueSigner.DSA.toString(), is("DSA"));
    assertThat("toString should return correct value", ValueSigner.ECDSA.toString(), is("ECDSA"));
  }

  @Test
  public void fromStringTest() {
    assertThat("fromString should return correct enum value", ValueSigner.fromString("RSA-PKCS1"), is(ValueSigner.RSA_PKCS1));
    assertThat("fromString should return correct enum value", ValueSigner.fromString("RSA-PSS"), is(ValueSigner.RSA_PSS));
    assertThat("fromString should return correct enum value", ValueSigner.fromString("DSA"), is(ValueSigner.DSA));
    assertThat("fromString should return correct enum value", ValueSigner.fromString("ECDSA"), is(ValueSigner.ECDSA));
  }

  @Test
  public void fromStringExceptionTest() {
    try {
      ValueSigner.fromString("bad");
      fail("only valid names should be allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void getKeyGenerationAlgorithmTest() throws Exception {
    assertThat("should return correct algorithm", ValueSigner.RSA_PKCS1.getKeyGenerationAlgorithm(), is("RSA"));
    assertThat("should return correct algorithm", ValueSigner.RSA_PSS.getKeyGenerationAlgorithm(), is("RSA"));
    assertThat("should return correct algorithm", ValueSigner.DSA.getKeyGenerationAlgorithm(), is("DSA"));
    assertThat("should return correct algorithm", ValueSigner.ECDSA.getKeyGenerationAlgorithm(), is("ECDSA"));
  }

  @Test
  public void getInstanceTest() throws Exception {
    assertThat("should return a Signature instance", ValueSigner.RSA_PKCS1.getInstance(null), is(instanceOf(Signature.class)));
    assertThat("should return a Signature instance", ValueSigner.RSA_PSS.getInstance("BC"), is(instanceOf(Signature.class)));
    assertThat("should return a Signature instance", ValueSigner.DSA.getInstance("BC"), is(instanceOf(Signature.class)));
    assertThat("should return a Signature instance", ValueSigner.ECDSA.getInstance(null), is(instanceOf(Signature.class)));
  }

  @Test
  public void signatureTest() throws Exception {
    for (ValueSigner signer : ValueSigner.values()) {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(signer.getKeyGenerationAlgorithm());
      switch (signer) {
        case RSA_PKCS1:
        case RSA_PSS:
          keyGen.initialize(1024);
          break;

        case DSA:
          keyGen.initialize(1024);
          break;

        case ECDSA:
          keyGen.initialize(256);
          break;
      }

      signatureTest(signer, keyGen);
    }
  }

  private void signatureTest(ValueSigner signer, KeyPairGenerator generator) throws Exception {
    byte[] data = "HELLO".getBytes();
    Signature signature = signer.getInstance(null);
    KeyPair pair = generator.generateKeyPair();

    signature.initSign(pair.getPrivate());
    signature.update(data);
    byte[] digest = signature.sign();

    assertThat("digest has a value", TestUtils.wrap(digest), is(not(emptyArray())));

    signature.initVerify(pair.getPublic());
    signature.update(data);
    assertThat("verification succeeds", signature.verify(digest), is(true));

    switch (signer) {
      case RSA_PKCS1:
        break;

      default:
        signature.initSign(pair.getPrivate());
        signature.update(data);
        assertThat("signatures correctly use random padding", signature.sign(), not(equalTo(digest)));
    }
  }
}
