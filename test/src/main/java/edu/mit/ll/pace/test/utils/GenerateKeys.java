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
package edu.mit.ll.pace.test.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.apache.accumulo.core.cli.Help;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.FileConverter;
import com.google.common.primitives.Ints;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.mit.ll.pace.keymanagement.LocalEncryptionKeyContainer;
import edu.mit.ll.pace.keymanagement.LocalSignatureKeyContainer;
import edu.mit.ll.pace.signature.ValueSigner;

/**
 * Generates key containers for use in integration tests.
 */
public final class GenerateKeys {

  /**
   * An HKDF to use for key generation.
   */
  private static final HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA512Digest());

  /**
   * A random number generator to use for key generation.
   */
  private static final SecureRandom random = new SecureRandom();

  /**
   * Master secret for key generation.
   */
  private static final byte[] MASTER_SECRET = new byte[32];

  static {
    random.nextBytes(MASTER_SECRET);
  }

  /**
   * Symmetric key lengths to generate.
   */
  private static final int[] SYMMETRIC_KEY_LENGTHS = new int[] {16, 24, 32, 48, 64};

  /**
   * The encoding to use in serializing IDs.
   */
  private static final Charset ENCODING_CHARSET = StandardCharsets.UTF_8;

  /**
   * Static class only.
   */
  private GenerateKeys() {}

  static {
    // Register Bouncy castle, as it will be used to generate signature keys.
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   * Command line options.
   */
  static class Opts extends Help {
    @Parameter(names = {"-c", "--config"}, description = "configuration description", required = true, converter = FileConverter.class)
    File config;
    @Parameter(names = {"-d", "--destination"}, description = "Location to write keys to", converter = FileConverter.class)
    File directory = Paths.get(System.getProperty("user.dir"), "target", "keys").toFile();
    @Parameter(names = {"-e", "--encryption-keys"}, description = "generate encryption keys")
    boolean generateEncryptionKeys = true;
    @Parameter(names = {"-s", "--signature-keys"}, description = "generate signature keys")
    boolean generateSignatureKeys = true;
  }

  /**
   * Create a set of keys to use for testing.
   */
  public static void main(String[] args) throws Exception {
    Opts opts = new Opts();
    opts.parseArgs(GenerateKeys.class.getName(), args);

    if (opts.directory.exists()) {
      throw new IllegalArgumentException(opts.directory.getPath() + " already exists; please delete it first");
    }
    if (!opts.directory.mkdirs()) {
      throw new IllegalArgumentException("Unable to create output destination");
    }

    generateKeys(opts.config, opts.directory, opts.generateEncryptionKeys, opts.generateSignatureKeys);
  }

  /**
   * Generate keys.
   *
   * @param config
   *          Configuration file describing how keys are generated.
   * @param destination
   *          Directory keys will be placed in.
   * @param generateEncryptionKeys
   *          Whether to generate encryption keys.
   * @param generateSignatureKeys
   *          Whether to generate signature keys.
   */
  static void generateKeys(File config, File destination, boolean generateEncryptionKeys, boolean generateSignatureKeys) throws Exception {
    JsonParser parser = new JsonParser();
    JsonArray keyManifest = parser.parse(new FileReader(config)).getAsJsonObject().getAsJsonArray("keys");

    // Create the output directories.
    Map<String,String> userDirectories = new HashMap<>();
    for (int i = 0; i < keyManifest.size(); i++) {
      JsonObject item = keyManifest.get(i).getAsJsonObject();
      String userId = item.getAsJsonPrimitive("id").getAsString();
      Path path = Paths.get(destination.getPath(), userId);

      if (!path.toFile().mkdirs()) {
        throw new IllegalArgumentException("unable to create destination " + path.toString());
      }
      userDirectories.put(userId, path.toString());
    }

    // Build the encryption keys.
    if (generateEncryptionKeys) {
      for (int i = 0; i < keyManifest.size(); i++) {
        JsonObject item = keyManifest.get(i).getAsJsonObject();
        String userId = item.getAsJsonPrimitive("id").getAsString();
        LocalEncryptionKeyContainer container = new LocalEncryptionKeyContainer();

        JsonArray encryptionKeys = item.getAsJsonArray("encryptionKeys");
        for (int j = 0; j < encryptionKeys.size(); j++) {
          JsonObject encryptionKey = encryptionKeys.get(j).getAsJsonObject();

          String attribute = encryptionKey.has("attribute") ? encryptionKey.getAsJsonPrimitive("attribute").getAsString() : null;
          String id = encryptionKey.getAsJsonPrimitive("id").getAsString();
          int maxVersion = encryptionKey.getAsJsonPrimitive("version").getAsInt();

          for (int version = 0; version <= maxVersion; version++) {
            for (int keyLength : SYMMETRIC_KEY_LENGTHS) {
              if (attribute == null) {
                container.addKey(id, version, generateKey(null, id, version, keyLength));
              } else {
                container.addKey(attribute, id, version, generateKey(attribute, id, version, keyLength));
              }
            }
          }
        }

        container.write(new FileWriter(Paths.get(userDirectories.get(userId), "encryption.keys").toFile()));
      }
    }

    // Build the signing keys.
    if (generateSignatureKeys) {
      Map<Pair<String,ValueSigner>,LocalSignatureKeyContainer> containers = new HashMap<>();
      Map<Pair<String,ValueSigner>,Pair<byte[],PublicKey>> publicKeys = new HashMap<>();
      for (int i = 0; i < keyManifest.size(); i++) {
        JsonObject item = keyManifest.get(i).getAsJsonObject();
        String userId = item.getAsJsonPrimitive("id").getAsString();

        for (ValueSigner signer : ValueSigner.values()) {
          if (signer == ValueSigner.RSA_PKCS1)
            continue; // Only 1 RSA set of keys are needed.
          KeyPairGenerator gen = KeyPairGenerator.getInstance(signer.getKeyGenerationAlgorithm());
          if (signer == ValueSigner.ECDSA) {
            gen.initialize(256, random);
          } else {
            gen.initialize(1024, random);
          }

          KeyPair pair = gen.generateKeyPair();
          byte[] keyId = String.format("%s_%s", gen.getAlgorithm(), userId).getBytes(ENCODING_CHARSET);
          containers.put(Pair.of(userId, signer), new LocalSignatureKeyContainer(pair, keyId));
          publicKeys.put(Pair.of(userId, signer), Pair.of(keyId, pair.getPublic()));
        }
      }

      // Add the verification keys.
      for (int i = 0; i < keyManifest.size(); i++) {
        JsonObject item = keyManifest.get(i).getAsJsonObject();
        String userId = item.getAsJsonPrimitive("id").getAsString();

        for (ValueSigner signer : ValueSigner.values()) {
          if (signer == ValueSigner.RSA_PKCS1)
            continue; // Only 1 RSA set of keys are needed.
          LocalSignatureKeyContainer container = containers.get(Pair.of(userId, signer));

          JsonArray verifierKeys = item.getAsJsonArray("verifierKeys");
          for (int j = 0; j < verifierKeys.size(); j++) {
            String signerId = verifierKeys.get(j).getAsString();
            Pair<byte[],PublicKey> verifierKey = publicKeys.get(Pair.of(signerId, signer));
            container.addVerifierKey(verifierKey.getRight(), verifierKey.getLeft());
          }

          container.write(new FileWriter(Paths.get(userDirectories.get(userId), signer.getKeyGenerationAlgorithm() + "-signing.keys").toFile()));
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
  private static byte[] generateKey(String attribute, String id, int version, int length) {
    ByteArrayOutputStream metadata = new ByteArrayOutputStream();
    try {
      if (attribute != null) {
        metadata.write(Ints.toByteArray(attribute.length()));
        metadata.write(attribute.getBytes(ENCODING_CHARSET));
      }
      metadata.write(Ints.toByteArray(version));
      metadata.write(Ints.toByteArray(length));
    } catch (IOException e) { /* won't be thrown */}

    hkdf.init(new HKDFParameters(MASTER_SECRET, id.getBytes(ENCODING_CHARSET), metadata.toByteArray()));

    byte[] key = new byte[length];
    hkdf.generateBytes(key, 0, key.length);
    return key;
  }

}
