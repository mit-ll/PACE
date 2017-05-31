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

import java.util.Collection;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.commons.lang3.StringUtils;
import org.ini4j.Profile.Section;

import edu.mit.ll.pace.EntryField;

/**
 * Builder for configuration of field encryptor objects.
 */
public class FieldEncryptorConfigBuilder {

  // For definitions of these values see FieldEncryptorConfig.
  private ValueEncryptor valueEncryptor;
  private String provider;
  private boolean encryptUsingVisibility;
  private int keyLength;
  private String keyId;
  private EntryField destination;
  private SortedSet<EntryField> sources = new TreeSet<>();

  /**
   * Set the value encryptor.
   *
   * @param valueEncryptor
   *          The {@link ValueEncryptor} used to encrypt the field.
   * @return Builder.
   */
  public FieldEncryptorConfigBuilder setValueEncryptor(ValueEncryptor valueEncryptor) {
    this.valueEncryptor = valueEncryptor;
    return this;
  }

  /**
   * Set the provider to use.
   *
   * @param provider
   *          The provider to use when getting an instance of the {@link ValueEncryptor}. If this is null, will search for the appropriate providers as defined
   *          by the system.
   * @return Builder.
   */
  public FieldEncryptorConfigBuilder setProvider(String provider) {
    this.provider = provider;
    return this;
  }

  /**
   * Set the whether to encrypt using the visibility.
   *
   * @param encryptUsingVisibility
   *          Will this encryption encrypt the field using the visibility.
   * @return Builder.
   */
  public FieldEncryptorConfigBuilder setEncryptUsingVisibility(boolean encryptUsingVisibility) {
    this.encryptUsingVisibility = encryptUsingVisibility;
    return this;
  }

  /**
   * Set the key length.
   *
   * @param keyLength
   *          The length of the key to use.
   * @return Builder.
   */
  public FieldEncryptorConfigBuilder setKeyLength(int keyLength) {
    this.keyLength = keyLength;
    return this;
  }

  /**
   * Set the key ID.
   *
   * @param keyId
   *          Id of the key that will be used for encryption.
   * @return Builder.
   */
  public FieldEncryptorConfigBuilder setKeyId(String keyId) {
    this.keyId = keyId;
    return this;
  }

  /**
   * Set the destination field.
   *
   * @param destination
   *          The field where encrypted data will be written to by the encryptor.
   * @return Builder.
   */
  public FieldEncryptorConfigBuilder setDestination(EntryField destination) {
    this.destination = destination;
    return this;
  }

  /**
   * Add a source to the list of sources for this encryptor.
   *
   * @param source
   *          A field that will be encrypted and stored in the destination.
   * @return Builder.
   */
  public FieldEncryptorConfigBuilder addSource(EntryField source) {
    this.sources.add(source);
    return this;
  }

  /**
   * Set the sources.
   *
   * @param sources
   *          The fields that will be encrypted and stored in the destination.
   * @return Builder.
   */
  public FieldEncryptorConfigBuilder setSources(Collection<EntryField> sources) {
    this.sources.clear();
    if (sources != null) {
      this.sources.addAll(sources);
    }
    return this;
  }

  /**
   * Read the configuration from a Reader.
   *
   * @param section
   *          Ini section to read from.
   * @return BUilder
   */
  FieldEncryptorConfigBuilder readFromIni(Section section) {
    ValueEncryptor valueEncryptor = ValueEncryptor.fromString(section.get("cipher"));

    setValueEncryptor(valueEncryptor);
    setProvider(section.get("provider"));
    setEncryptUsingVisibility(section.containsKey("useVisibility") ? Boolean.parseBoolean(section.get("useVisibility")) : false);
    setKeyId(section.getOrDefault("keyId", valueEncryptor.toString()));
    setKeyLength(section.containsKey("keyLength") ? Integer.parseInt(section.get("keyLength")) : valueEncryptor.getDefaultKeyLength());
    setDestination(EntryField.fromString(section.getName()));

    if (!section.containsKey("sources")) {
      addSource(EntryField.fromString(section.getName()));
    } else {
      for (String source : StringUtils.split(section.get("sources"), ',')) {
        addSource(EntryField.fromString(source.trim()));
      }
    }

    return this;
  }

  /**
   * Build the {@link FieldEncryptorConfig}.
   *
   * @return Built config.
   */
  public FieldEncryptorConfig build() {
    return new FieldEncryptorConfig(valueEncryptor, provider, encryptUsingVisibility, keyId, keyLength, destination, sources);
  }
}
