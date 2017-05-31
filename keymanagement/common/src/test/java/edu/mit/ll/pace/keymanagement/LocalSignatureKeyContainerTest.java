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
package edu.mit.ll.pace.keymanagement;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import edu.mit.ll.pace.signature.ValueSigner;

/**
 * Unit tests for {@link LocalSignatureKeyContainer}.
 */
public class LocalSignatureKeyContainerTest {

  @BeforeClass
  public static void setupBouncyCastle() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static final Charset ENCODING_CHARSET = StandardCharsets.UTF_8;

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Test
  public void writeReadTest() throws Exception {
    for (ValueSigner signer : ValueSigner.values()) {
      KeyPairGenerator gen = KeyPairGenerator.getInstance(signer.getKeyGenerationAlgorithm());
      if (signer == ValueSigner.ECDSA) {
        gen.initialize(256);
      } else {
        gen.initialize(1024);
      }

      KeyPair pair = gen.generateKeyPair();
      byte[] keyId = String.format("%s_%s", gen.getAlgorithm(), "test").getBytes(ENCODING_CHARSET);
      LocalSignatureKeyContainer container = new LocalSignatureKeyContainer(pair, keyId);

      File file = folder.newFile();
      FileWriter writer = new FileWriter(file);
      container.write(writer);
      writer.close();

      LocalSignatureKeyContainer container2 = LocalSignatureKeyContainer.read(new FileReader(file));
      assertThat("has matching keys", container2.getSigningKey().value.getEncoded(), equalTo(container.getSigningKey().value.getEncoded()));
      assertThat("has matching keys", container2.getSigningKey().id, equalTo(container.getSigningKey().id));
      assertThat("has matching keys", container2.getVerifyingKey(keyId).value.getEncoded(), equalTo(container.getVerifyingKey(keyId).value.getEncoded()));
    }

  }

}
