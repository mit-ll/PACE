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

import static com.google.common.base.Preconditions.checkArgument;

import java.util.Collections;
import java.util.List;
import java.util.SortedSet;

import org.apache.commons.lang3.StringUtils;
import org.ini4j.Ini;
import org.ini4j.Profile.Section;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

import edu.mit.ll.pace.EntryField;

/**
 * Holds configuration data for encrypting an Accumulo field.
 * <p>
 * This class defines how data will be encrypted to a specific field. This includes defining which encryption scheme will be used, where the the data to be
 * encrypted is pulled from, and where it is to be written.
 */
public final class FieldEncryptorConfig {

  /**
   * The set of fields that can be the destination of encrypted content in the key.
   */
  static final List<EntryField> KEY_DESTINATION_FIELDS = ImmutableList.of(EntryField.ROW, EntryField.COLUMN_FAMILY, EntryField.COLUMN_QUALIFIER);

  /**
   * Set of fields that can be sources for data when encrypting a field in the key.
   */
  static final List<EntryField> KEY_SOURCE_FIELDS = ImmutableList.of(EntryField.ROW, EntryField.COLUMN_FAMILY, EntryField.COLUMN_QUALIFIER,
      EntryField.COLUMN_VISIBILITY);

  /**
   * Set of fields that can be sources for data when encrypting the value.
   */
  static final List<EntryField> VALUE_SOURCE_FIELDS = ImmutableList.of(EntryField.VALUE);

  /**
   * The {@link ValueEncryptor} used to encrypt the field.
   */
  final ValueEncryptor valueEncryptor;

  /**
   * The provider to use when getting an instance of the {@link ValueEncryptor}.
   */
  final String provider;

  /**
   * Will this encryption encrypt the field using the visibility.
   */
  final boolean encryptUsingVisibility;

  /**
   * Id of the key that will be used for encryption.
   */
  final String keyId;

  /**
   * The length of keys to use for encryption.
   */
  final int keyLength;

  /**
   * The field that the encrypted data will be written to.
   */
  final EntryField destination;

  /**
   * The fields that plaintext data is drawn from.
   */
  final SortedSet<EntryField> sources;

  /**
   * Creates a configuration for an {@link FieldEncryptor}.
   *
   * @param valueEncryptor
   *          The {@link ValueEncryptor} used to encrypt the field.
   * @param provider
   *          The provider to use when getting an instance of the {@link ValueEncryptor}. If this is null, will search for the appropriate providers as defined
   *          by the system.
   * @param encryptUsingVisibility
   *          Will this encryption encrypt the field using the visibility.
   * @param keyId
   *          Id of the key that will be used for encryption.
   * @param keyLength
   *          The length of the key to use.
   * @param destination
   *          The field where encrypted data will be written to by the encryptor.
   * @param sources
   *          The fields that plaintext data is drawn from.
   */
  public FieldEncryptorConfig(ValueEncryptor valueEncryptor, String provider, boolean encryptUsingVisibility, String keyId, int keyLength,
      EntryField destination, SortedSet<EntryField> sources) {
    checkArgument(valueEncryptor != null, "valueEncryptor is null");
    checkArgument(!encryptUsingVisibility || !valueEncryptor.isDeterministic(),
        "Cannot deterministically encrypt when encrypting fields using the visibility expression");
    checkArgument(!Strings.isNullOrEmpty(keyId), "keyId is null or empty");
    checkArgument(valueEncryptor.isValidKeyLength(keyLength), "invalid key length for the value encryptor");
    checkArgument(destination != null, "destination is null");
    checkArgument(KEY_DESTINATION_FIELDS.contains(destination) || destination == EntryField.VALUE, "invalid destination");
    checkArgument(sources != null, "sources is null");
    checkArgument(sources.size() > 0, "sources is empty");

    if (KEY_SOURCE_FIELDS.contains(destination)) {
      for (EntryField source : sources) {
        checkArgument(KEY_SOURCE_FIELDS.contains(source), source.toString() + " cannot be encrypted into a key field");
      }
    } else {
      for (EntryField source : sources) {
        checkArgument(VALUE_SOURCE_FIELDS.contains(source), source.toString() + " cannot be encrypted into the value field");
      }
    }

    this.valueEncryptor = valueEncryptor;
    this.provider = provider;
    this.encryptUsingVisibility = encryptUsingVisibility;
    this.keyLength = keyLength;
    this.keyId = keyId;
    this.destination = destination;
    this.sources = Collections.unmodifiableSortedSet(sources);
  }

  /**
   * Write's this FieldEncryptorBase configuration to the given INI.
   *
   * @param configIni
   *          INI to write to.
   */
  void write(Ini configIni) {
    Section section = configIni.add(destination.toString());

    section.put("cipher", valueEncryptor.toString());
    section.put("provider", provider);
    section.put("useVisibility", encryptUsingVisibility);
    section.put("keyId", keyId);
    section.put("keyLength", Integer.toString(keyLength));
    section.put("sources", StringUtils.join(sources, ','));
  }
}
