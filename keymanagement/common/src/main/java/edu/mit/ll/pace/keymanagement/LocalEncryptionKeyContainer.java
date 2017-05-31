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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.mit.ll.pace.IllegalKeyRequestException;
import edu.mit.ll.pace.encryption.EncryptionKey;
import edu.mit.ll.pace.encryption.EncryptionKeyContainer;

/**
 * Key container.
 */
public final class LocalEncryptionKeyContainer implements EncryptionKeyContainer {

  /**
   * Class for key lookup in key container map.
   */
  private static final class KeyLookup {
    private final String attribute;
    private final String id;
    private final int keyLength;

    KeyLookup(String id, int keyLength) {
      this.attribute = null;
      this.id = id;
      this.keyLength = keyLength;
    }

    KeyLookup(String attribute, String id, int keyLength) {
      this.attribute = attribute;
      this.id = id;
      this.keyLength = keyLength;
    }

    @Override
    public int hashCode() {
      return Objects.hash(attribute, id, keyLength);
    }

    @Override
    public boolean equals(Object obj) {
      if (null == obj || !(obj instanceof KeyLookup)) {
        return false;
      }

      KeyLookup other = (KeyLookup) obj;
      if (attribute == null) {
        if (other.attribute != null) {
          return false;
        }
      } else {
        if (!attribute.equals(other.attribute)) {
          return false;
        }
      }

      return id.equals(other.id) && keyLength == other.keyLength;
    }
  }

  /**
   * The version of the serialized data.
   */
  private static final int CURRENT_VERSION = 1;

  /**
   * The encryption keys stored in this container.
   */
  private final Map<KeyLookup,Map<Integer,EncryptionKey>> encryptionKeys = new HashMap<>();

  /**
   * Add a key to the store.
   *
   * @param id
   *          Id value used to derive the key.
   * @param version
   *          Version of the key.
   * @param key
   *          The key data.
   */
  public void addKey(String id, int version, byte[] key) {
    addKey(null, id, version, key, null, null, true);
  }

  /**
   * Add a key to the store.
   *
   * @param id
   *          Id value used to derive the key.
   * @param version
   *          Version of the key.
   * @param key
   *          The key data.
   * @param startValidity
   *          When the key started to be valid, or null for no start validity.
   * @param endValidity
   *          When the key stopped being valid, or null for no end validity.
   */
  public void addKey(String id, int version, byte[] key, Long startValidity, Long endValidity) {
    addKey(null, id, version, key, startValidity, endValidity, true);
  }

  /**
   * Add a key to the store.
   *
   * @param attribute
   *          Attribute the key is for.
   * @param id
   *          Id value used to derive the key.
   * @param version
   *          Version of the key.
   * @param key
   *          The key data.
   */
  public void addKey(String attribute, String id, int version, byte[] key) {
    checkArgument(attribute != null, "attribute is null");
    addKey(attribute, id, version, key, null, null, true);
  }

  /**
   * Add a key to the store.
   *
   * @param attribute
   *          Attribute the key is for.
   * @param id
   *          Id value used to derive the key.
   * @param version
   *          Version of the key.
   * @param key
   *          The key data.
   * @param startValidity
   *          When the key started to be valid, or null for no start validity.
   * @param endValidity
   *          When the key stopped being valid, or null for no end validity.
   */
  public void addKey(String attribute, String id, int version, byte[] key, Long startValidity, Long endValidity) {
    checkArgument(attribute != null, "attribute is null");
    addKey(attribute, id, version, key, startValidity, endValidity, true);
  }

  /**
   * Add a key to the store.
   *
   * @param attribute
   *          Attribute the key is for.
   * @param id
   *          Id value used to derive the key.
   * @param version
   *          Version of the key.
   * @param key
   *          The key data.
   * @param startValidity
   *          When the key started to be valid, or null for no start validity.
   * @param endValidity
   *          When the key stopped being valid, or null for no end validity.
   * @param copy
   *          Whether to copy the data.
   */
  private void addKey(String attribute, String id, int version, byte[] key, Long startValidity, Long endValidity, boolean copy) {
    checkArgument(id != null, "id is null");
    checkArgument(version >= 0, "version is negative");
    checkArgument(key != null, "key is null");
    checkArgument(key.length > 0, "key is empty");
    checkArgument(startValidity == null || endValidity == null || endValidity >= startValidity, "end validity cannot come before start validity");

    KeyLookup mapKey = new KeyLookup(attribute, id, key.length);
    Map<Integer,EncryptionKey> keys = encryptionKeys.computeIfAbsent(mapKey, k -> new HashMap<>());
    keys.put(version, new EncryptionKey(copy ? key.clone() : key, version, startValidity, endValidity));
  }

  @Override
  public Collection<EncryptionKey> getKeys(String id, int length) throws IllegalKeyRequestException {
    checkArgument(id != null, "id is null");
    checkArgument(length > 0, "length is non-positive");

    Map<Integer,EncryptionKey> versionedKeys = encryptionKeys.get(new KeyLookup(null, id, length));
    if (versionedKeys == null || versionedKeys.isEmpty()) {
      throw new IllegalKeyRequestException(getMessage(Pair.of("id", id), Pair.of("length", length)));
    }

    return versionedKeys.values();
  }

  @Override
  public EncryptionKey getKey(String id, int length) throws IllegalKeyRequestException {
    checkArgument(id != null, "id is null");
    checkArgument(length > 0, "length is non-positive");

    Map<Integer,EncryptionKey> versionedKeys = encryptionKeys.get(new KeyLookup(id, length));
    if (versionedKeys == null) {
      throw new IllegalKeyRequestException(getMessage(Pair.of("id", id), Pair.of("length", length)));
    }

    Optional<Integer> highestVersion = versionedKeys.keySet().stream().max(Integer::compareTo);
    if (!highestVersion.isPresent()) {
      throw new IllegalKeyRequestException(getMessage(Pair.of("id", id), Pair.of("length", length)));
    }

    return versionedKeys.get(highestVersion.get());
  }

  @Override
  public EncryptionKey getKey(String id, int version, int length) throws IllegalKeyRequestException {
    checkArgument(id != null, "id is null");
    checkArgument(version >= 0, "version is negative");
    checkArgument(length > 0, "length is non-positive");

    Map<Integer,EncryptionKey> versionedKeys = encryptionKeys.get(new KeyLookup(id, length));
    if (versionedKeys == null) {
      throw new IllegalKeyRequestException(getMessage(Pair.of("id", id), Pair.of("length", length)));
    }

    EncryptionKey key = versionedKeys.get(version);
    if (key == null) {
      throw new IllegalKeyRequestException(getMessage(Pair.of("id", id), Pair.of("length", length), Pair.of("version", version)));
    }

    return key;
  }

  @Override
  public EncryptionKey getAttributeKey(String attribute, String id, int length) throws IllegalKeyRequestException {
    checkArgument(attribute != null, "attribute is null");
    checkArgument(id != null, "id is null");
    checkArgument(length > 0, "length is non-positive");

    Map<Integer,EncryptionKey> versionedKeys = encryptionKeys.get(new KeyLookup(attribute, id, length));
    if (versionedKeys == null) {
      throw new IllegalKeyRequestException(getMessage(Pair.of("attribute", attribute), Pair.of("id", id), Pair.of("length", length)));
    }

    Optional<Integer> highestVersion = versionedKeys.keySet().stream().max(Integer::compareTo);
    if (!highestVersion.isPresent()) {
      throw new IllegalKeyRequestException(getMessage(Pair.of("attribute", attribute), Pair.of("id", id), Pair.of("length", length)));
    }

    return versionedKeys.get(highestVersion.get());
  }

  @Override
  public EncryptionKey getAttributeKey(String attribute, String id, int version, int length) throws IllegalKeyRequestException {
    checkArgument(attribute != null, "attribute is null");
    checkArgument(id != null, "id is null");
    checkArgument(version >= 0, "version is negative");
    checkArgument(length > 0, "length is non-positive");

    Map<Integer,EncryptionKey> versionedKeys = encryptionKeys.get(new KeyLookup(attribute, id, length));
    if (versionedKeys == null) {
      throw new IllegalKeyRequestException(getMessage(Pair.of("attribute", attribute), Pair.of("id", id), Pair.of("length", length)));
    }

    EncryptionKey key = versionedKeys.get(version);
    if (key == null) {
      throw new IllegalKeyRequestException(getMessage(Pair.of("attribute", attribute), Pair.of("id", id), Pair.of("length", length),
          Pair.of("version", version)));
    }

    return key;
  }

  /**
   * Get the illegal key request message.
   *
   * @param values
   *          Values that relate to the message.
   * @return String to throw with exception.
   */
  @SafeVarargs
  private final String getMessage(final Pair<String,?>... values) {
    return "no such key available {" + Arrays.stream(values).map(val -> String.format("%s=%s", val.getKey(), val.getValue())).collect(Collectors.joining(", "))
        + "}";
  }

  /**
   * Write the encryption key container to the writer.
   *
   * @param out
   *          Output writer.
   */
  public void write(Writer out) throws IOException {
    Gson gson = new GsonBuilder().enableComplexMapKeySerialization().setPrettyPrinting().create();

    JsonObject data = new JsonObject();
    data.addProperty("version", CURRENT_VERSION);

    JsonArray keys = new JsonArray();
    for (Entry<KeyLookup,Map<Integer,EncryptionKey>> entry : encryptionKeys.entrySet()) {
      for (EncryptionKey keyData : entry.getValue().values()) {
        JsonObject keyContainer = new JsonObject();
        if (entry.getKey().attribute != null) {
          keyContainer.addProperty("attribute", entry.getKey().attribute);
        }
        keyContainer.addProperty("id", entry.getKey().id);
        keyContainer.addProperty("version", keyData.version);
        keyContainer.addProperty("key", Base64.getEncoder().encodeToString(keyData.value));

        if (keyData.startValidity != null) {
          keyContainer.addProperty("startValidity", keyData.startValidity);
        }
        if (keyData.endValidity != null) {
          keyContainer.addProperty("endValidity", keyData.endValidity);
        }

        keys.add(keyContainer);
      }
    }
    data.add("keys", keys);

    gson.toJson(data, out);
    out.flush();
  }

  /**
   * Read the encryption key container from the reader.
   *
   * @param in
   *          Input reader.
   * @return Parsed encryption key container.
   */
  public static LocalEncryptionKeyContainer read(Reader in) {
    LocalEncryptionKeyContainer container = new LocalEncryptionKeyContainer();
    JsonParser parser = new JsonParser();

    JsonObject data = parser.parse(in).getAsJsonObject();
    int serializationVersion = data.getAsJsonPrimitive("version").getAsInt();

    switch (serializationVersion) {
      case 1:
        JsonArray keys = data.getAsJsonArray("keys");
        for (int i = 0; i < keys.size(); i++) {
          JsonObject keyContainer = keys.get(i).getAsJsonObject();

          String attribute = keyContainer.has("attribute") ? keyContainer.getAsJsonPrimitive("attribute").getAsString() : null;
          String id = keyContainer.getAsJsonPrimitive("id").getAsString();
          int version = keyContainer.getAsJsonPrimitive("version").getAsInt();
          byte[] key = Base64.getDecoder().decode(keyContainer.getAsJsonPrimitive("key").getAsString());
          Long startValidity = keyContainer.has("startValidity") ? keyContainer.getAsJsonPrimitive("startValidity").getAsLong() : null;
          Long endValidity = keyContainer.has("endValidity") ? keyContainer.getAsJsonPrimitive("endValidity").getAsLong() : null;

          container.addKey(attribute, id, version, key, startValidity, endValidity, false);
        }
        break;

      default:
        throw new UnsupportedOperationException("unsupported file version");
    }

    return container;
  }
}
