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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.apache.accumulo.core.cli.Help;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.FileConverter;
import com.google.common.primitives.Ints;

import edu.mit.ll.pace.keymanagement.LocalEncryptionKeyContainer;

public class GenerateEncryptionKeys {

  /**
   * An HKDF to use for key generation.
   */
  private static final HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA512Digest());

  /**
   * Symmetric key lengths to generate.
   */
  private static final int[] SYMMETRIC_KEY_LENGTHS = new int[] {16, 24, 32, 48, 64};

  /**
   * The encoding to use in serializing IDs.
   */
  private static final Charset ENCODING_CHARSET = StandardCharsets.UTF_8;

  /**
   * Default key version to use for generating keys.
   */
  private static final int DEFAULT_KEY_VERSION = 1;

  static class KeyArgs {
    final String attribute;
    final String keyId;
    final int version;

    KeyArgs(String attribute, String keyId, int version) {
      this.attribute = attribute;
      this.keyId = keyId;
      this.version = version;
    }
  }

  public static class KeyArgsConverter implements IStringConverter<KeyArgs> {
    @Override
    public KeyArgs convert(String value) {
      String[] args = value.split("\\|");
      switch (args.length) {
        case 1:
          return new KeyArgs(null, args[0], DEFAULT_KEY_VERSION);

        case 2:
          try {
            return new KeyArgs(null, args[0], Integer.parseInt(args[1]));
          } catch (NumberFormatException e) {
            return new KeyArgs(args[1], args[0], DEFAULT_KEY_VERSION);
          }

        case 3:
          return new KeyArgs(args[1], args[0], Integer.parseInt(args[2]));

        default:
          throw new IllegalArgumentException("invalid key description: " + value);
      }
    }
  }

  static class Opts extends Help {
    @Parameter(
        names = {"--key"},
        description = "Key that should be added to the key store. For attribute keys use the format \"keyId|attribute|version?\". For non-attribute keys use the"
            + " format \"keyId|version?\". If version is omitted, the value 1 will be used for version. In all cases keys of all viable lengths will be generated.",
        converter = KeyArgsConverter.class)
    List<KeyArgs> keyList = new ArrayList<>();
    @Parameter(names = {"--store"}, description = "location to store the generated key store", converter = FileConverter.class, required = true)
    File storeFile = null;
    @Parameter(names = {"--master-key-file"}, description = "the location of the master key file", converter = FileConverter.class)
    File masterKeyFile = null;
    @Parameter(names = "--read-master-key", description = "read the master-key from a file instead of generating it")
    boolean readMasterKey = false;
    @Parameter(names = "--write-master-key", description = "write the master-key to a file")
    boolean writeMasterKey = false;
  }

  public static void main(String[] args) {
    Opts opts = new Opts();
    opts.parseArgs(GenerateEncryptionKeys.class.getName(), args);

    // Read or generate the master key.
    final byte[] masterKey;
    if (opts.readMasterKey) {
      if (opts.masterKeyFile == null) {
        throw new IllegalArgumentException("master key file not set");
      } else {
        try {
          masterKey = Files.readAllBytes(opts.masterKeyFile.toPath());
        } catch (IOException e) {
          throw new IllegalArgumentException("invalid master key file", e);
        }
      }
    } else {
      masterKey = new byte[32];
      new SecureRandom().nextBytes(masterKey);
    }

    // Generate the keys using an HKDF function.
    LocalEncryptionKeyContainer container = new LocalEncryptionKeyContainer();
    for (KeyArgs keyArg : opts.keyList) {
      for (int version = 0; version <= keyArg.version; version++) {
        for (int keyLength : SYMMETRIC_KEY_LENGTHS) {
          if (keyArg.attribute == null) {
            container.addKey(keyArg.keyId, version, generateKey(masterKey, null, keyArg.keyId, version, keyLength));
          } else {
            container.addKey(keyArg.attribute, keyArg.keyId, version, generateKey(masterKey, keyArg.attribute, keyArg.keyId, version, keyLength));
          }
        }
      }
    }

    try {
      FileWriter writer = new FileWriter(opts.storeFile);
      container.write(writer);
      writer.close();
    } catch (IOException e) {
      throw new IllegalArgumentException("invalid store file", e);
    }

    // Write the master key.
    if (opts.writeMasterKey) {
      if (opts.masterKeyFile == null) {
        throw new IllegalArgumentException("master key file not set");
      } else {
        try {
          Files.write(opts.masterKeyFile.toPath(), masterKey, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
          throw new IllegalArgumentException("invalid master key file", e);
        }
      }
    }
  }

  /**
   * Generate a key from the given data.
   *
   * @param attribute
   *          Attribute of the key to generate.
   * @param id
   *          Id of the key to generate.
   * @param version
   *          Version of the key to generate.
   * @param length
   *          Length of the key to generate.
   * @return Generated key.
   */
  private static byte[] generateKey(byte[] masterSecret, String attribute, String id, int version, int length) {
    ByteArrayOutputStream metadata = new ByteArrayOutputStream();
    try {
      if (attribute != null) {
        metadata.write(Ints.toByteArray(attribute.length()));
        metadata.write(attribute.getBytes(ENCODING_CHARSET));
      }
      metadata.write(Ints.toByteArray(version));
      metadata.write(Ints.toByteArray(length));
    } catch (IOException e) { /* won't be thrown */}

    hkdf.init(new HKDFParameters(masterSecret, id.getBytes(ENCODING_CHARSET), metadata.toByteArray()));

    byte[] key = new byte[length];
    hkdf.generateBytes(key, 0, key.length);
    return key;
  }

}
