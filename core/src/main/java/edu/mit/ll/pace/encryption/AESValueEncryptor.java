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

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.hadoop.io.WritableUtils;

/**
 * Defines the contract for a {@link ValueEncryptorBase} that performs semantic or authenticated encryption using AES.
 */
final class AESValueEncryptor extends ValueEncryptorBase {

  /**
   * The algorithm string to use when creating a key spec.
   */
  private final static String AES = "AES";

  /**
   * The cipher to use for encryption.
   */
  private final Cipher cipher;

  /**
   * Tracks whether this encryptor is a SunJCE provided instance of GCM. This is necessary as SunJCE uses "GCM" instead of "AES" for the algorithm name of this
   * cipher.
   */
  private final boolean isInstanceOfSunProvidedGCM;

  /**
   * Create the value encryptor.
   *
   * @param transformation
   *          ValueEncryptor transformation. Passed to {@link Cipher#getInstance(String, String)}.
   *          <p>
   *          The transformation defines the algorithm used, the mode it is used in, and any padding.
   * @param provider
   *          ValueEncryptor provider. Passed to {@link Cipher#getInstance(String, String)}.
   * @throws EncryptionException
   *           Thrown when the encryptor can't be instantiated.
   */
  AESValueEncryptor(String transformation, String provider) {
    try {
      if (provider == null) {
        cipher = Cipher.getInstance(transformation);
      } else {
        cipher = Cipher.getInstance(transformation, provider);
      }
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
      throw new EncryptionException(e);
    }

    isInstanceOfSunProvidedGCM = transformation.toUpperCase().startsWith("AES/GCM") && cipher.getProvider().getName().equals("SunJCE");
  }

  @Override
  byte[] encrypt(byte[] key, byte[] data) {
    try {
      SecretKeySpec keySpec = new SecretKeySpec(key, AES);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec);
      byte[] ciphertext = cipher.doFinal(data);

      // Write out the metadata.
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      DataOutput out = new DataOutputStream(stream);

      byte[] params = cipher.getParameters().getEncoded();
      WritableUtils.writeVInt(out, params.length);
      out.write(params);

      // Write the original ciphertext and return the new ciphertext.
      out.write(ciphertext);
      return stream.toByteArray();
    } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) {
      throw new EncryptionException(e);
    }
  }

  @Override
  byte[] decrypt(byte[] key, byte[] data) {
    try {
      // Sun's impelemntation of GCM uses a custom algorithm name. We handle this odd (potentially incorrect) behavior here.
      AlgorithmParameters params = AlgorithmParameters.getInstance(isInstanceOfSunProvidedGCM ? "GCM" : "AES");

      // Read the metadata.
      ByteArrayInputStream stream = new ByteArrayInputStream(data);
      DataInput in = new DataInputStream(stream);

      int metadataLength = WritableUtils.readVInt(in);
      byte[] metadata = new byte[metadataLength];
      in.readFully(metadata);
      params.init(metadata);

      // Decrypt the remaining data.
      SecretKeySpec keySpec = new SecretKeySpec(key, AES);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
      byte[] ciphertext = new byte[stream.available()];
      in.readFully(ciphertext);

      cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
      return cipher.doFinal(ciphertext);
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException
        | IOException e) {
      throw new EncryptionException(e);
    }
  }

}
