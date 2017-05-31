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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import com.google.common.primitives.Ints;

import edu.mit.ll.pace.IllegalKeyRequestException;

/**
 * Mock {@link EncryptionKeyContainer} to use for testing the encryption code.
 */
public final class MockEncryptionKeyContainer implements EncryptionKeyContainer {

  /**
   * Key to use in the HKDF function.
   */
  private static byte[] HKDF_KEY = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  /**
   * The keys that will be issued by this container, along with their current version.
   */
  private Map<String,Integer> keys = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

  /**
   * An HKDF to use for key generation.
   */
  private HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA512Digest());

  /**
   * Create the mock container with the supplied keys and versions.
   *
   * @param keys
   *          Keys to add to the mock container.
   */
  @SafeVarargs
  MockEncryptionKeyContainer(Pair<String,Integer>... keys) {
    for (Pair<String,Integer> pair : keys) {
      this.keys.put(pair.getLeft(), pair.getRight());
    }
  }

  @Override
  public Collection<KeyWithVersion> getKeys(String id, int length) throws IllegalKeyRequestException {
    if (!keys.containsKey(id)) {
      throw new IllegalKeyRequestException("getKey: " + id);
    }

    List<KeyWithVersion> versionedKeys = new ArrayList<>();
    int maxVersion = keys.get(id);

    // Get a key for each version, past and future.
    for (int i = 1; i <= maxVersion; i++) {
      versionedKeys.add(new KeyWithVersion(generateKey(id, i, length), i));
    }

    return versionedKeys;
  }

  @Override
  public KeyWithVersion getKey(String id, int length) throws IllegalKeyRequestException {
    if (!keys.containsKey(id)) {
      throw new IllegalKeyRequestException("getKey: " + id);
    }
    int version = keys.get(id);
    return new KeyWithVersion(generateKey(id, version, length), version);
  }

  @Override
  public byte[] getKey(String id, int version, int length) throws IllegalKeyRequestException {
    if (!keys.containsKey(id)) {
      throw new IllegalKeyRequestException("getKey: " + id);
    }
    int maxVersion = keys.get(id);
    if (version > maxVersion) {
      throw new IllegalArgumentException("invalid version");
    }

    return generateKey(id, version, length);
  }

  @Override
  public KeyWithVersion getAttributeKey(String attribute, String id, int length) throws IllegalKeyRequestException {
    if (!keys.containsKey(attribute)) {
      throw new IllegalKeyRequestException("getAttributeKey: " + attribute);
    }
    int version = keys.get(attribute);
    return new KeyWithVersion(generateKey(attribute, id, version, length), version);
  }

  @Override
  public byte[] getAttributeKey(String attribute, String id, int version, int length) throws IllegalKeyRequestException {

    if (!keys.containsKey(attribute)) {
      throw new IllegalKeyRequestException("getAttributeKey: " + attribute);
    }
    int maxVersion = keys.get(attribute);
    if (version > maxVersion) {
      throw new IllegalArgumentException("invalid version");
    }

    return generateKey(attribute, id, version, length);
  }

  /**
   * Generate a key from the given data.
   *
   * @param id
   *          Id of the key to generate.
   * @param version
   *          Version of the key to generate.
   * @param length
   *          Length of the key to generate.
   * @return Generated key.
   */
  private byte[] generateKey(String id, int version, int length) {
    return generateKey("keyIdOnly", id, version, length);
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
  private byte[] generateKey(String attribute, String id, int version, int length) {
    ByteArrayOutputStream metadata = new ByteArrayOutputStream();

    try {
      metadata.write(id.getBytes(StandardCharsets.UTF_8));
      metadata.write(Ints.toByteArray(version));
      metadata.write(Ints.toByteArray(length));
    } catch (IOException e) { /* won't be thrown */}

    byte[] key = new byte[length];
    hkdf.init(new HKDFParameters(HKDF_KEY, attribute.getBytes(StandardCharsets.UTF_8), metadata.toByteArray()));
    hkdf.generateBytes(key, 0, key.length);
    return key;
  }
}
