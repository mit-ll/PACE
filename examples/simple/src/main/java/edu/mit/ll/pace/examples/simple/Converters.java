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
package edu.mit.ll.pace.examples.simple;

import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.apache.accumulo.core.client.Durability;
import org.apache.accumulo.core.client.impl.DurabilityImpl;

import com.beust.jcommander.IStringConverter;

import edu.mit.ll.pace.encryption.EncryptionConfig;
import edu.mit.ll.pace.encryption.EncryptionConfigBuilder;
import edu.mit.ll.pace.encryption.EncryptionKeyContainer;
import edu.mit.ll.pace.keymanagement.LocalEncryptionKeyContainer;
import edu.mit.ll.pace.keymanagement.LocalSignatureKeyContainer;
import edu.mit.ll.pace.signature.SignatureConfig;
import edu.mit.ll.pace.signature.SignatureConfigBuilder;
import edu.mit.ll.pace.signature.SignatureKeyContainer;

/**
 * Converters used in the examples.
 */
public class Converters {

  // private constructor
  private Converters() {}

  /**
   * Convert a command line argument to a {@link Durability}.
   */
  static class DurabilityConverter implements IStringConverter<Durability> {
    @Override
    public Durability convert(String value) {
      return DurabilityImpl.fromString(value);
    }
  }

  /**
   * Convert a command line argument to an {@link EncryptionConfig}.
   */
  public static class EncryptionConfigConverter implements IStringConverter<EncryptionConfig> {
    @Override
    public EncryptionConfig convert(String value) {
      try {
        return new EncryptionConfigBuilder().readFromFile(new FileReader(value)).build();
      } catch (IOException e) {
        throw new IllegalArgumentException(e);
      }
    }
  }

  /**
   * Convert a command line argument to an {@link EncryptionKeyContainer}.
   */
  public static class EncryptionKeyContainerConverter implements IStringConverter<EncryptionKeyContainer> {
    @Override
    public EncryptionKeyContainer convert(String value) {
      try {
        return LocalEncryptionKeyContainer.read(new FileReader(value));
      } catch (IOException e) {
        throw new IllegalArgumentException(e);
      }
    }
  }

  /**
   * Convert a command line argument to a {@link SignatureConfig}.
   */
  public static class SignatureConfigConverter implements IStringConverter<SignatureConfig> {
    @Override
    public SignatureConfig convert(String value) {
      try {
        return new SignatureConfigBuilder().readFromFile(new FileReader(value)).build();
      } catch (IOException e) {
        throw new IllegalArgumentException(e);
      }
    }
  }

  /**
   * Convert a command line argument to a {@link SignatureKeyContainer}.
   */
  public static class SignatureKeyContainerConverter implements IStringConverter<SignatureKeyContainer> {
    @Override
    public SignatureKeyContainer convert(String value) {
      try {
        return LocalSignatureKeyContainer.read(new FileReader(value));
      } catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException e) {
        throw new IllegalArgumentException(e);
      }
    }
  }

}
