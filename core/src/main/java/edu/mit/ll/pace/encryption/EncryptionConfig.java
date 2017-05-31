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

import java.io.IOException;
import java.io.Writer;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.ini4j.Ini;

import edu.mit.ll.pace.EntryField;

/**
 * Holds configuration data for encrypting Accumulo entries.
 *
 * <p>
 * The actual configuration is a list of {@link FieldEncryptorConfig} objects, that specify how data will be encrypted and written to a given field. As having
 * two {@link FieldEncryptorConfig} with the same destination field would lead to conflicts, only a single {@link FieldEncryptorConfig} is allowed for a
 * destination field.
 */
public final class EncryptionConfig {

  /**
   * Read-only of {@link FieldEncryptorConfig} that define how encryption of an entry will happen.
   */
  final List<FieldEncryptorConfig> fieldEncryptorConfigs;

  /**
   * Creates an EncryptionConfig from a set of field encryptor configurations.
   *
   * @param fieldEncryptorConfigs
   *          The encryptor configs that define how encryption of an entry will happen.
   */
  EncryptionConfig(List<FieldEncryptorConfig> fieldEncryptorConfigs) {
    checkArgument(fieldEncryptorConfigs != null, "fieldEncryptorConfigs is null");
    checkArgument(fieldEncryptorConfigs.size() != 0, "fieldEncryptorConfigs is empty");

    // Scan for duplicate destinations.
    Set<EntryField> destinations = new HashSet<>();
    Set<EntryField> sources = new HashSet<>();
    for (FieldEncryptorConfig config : fieldEncryptorConfigs) {
      checkArgument(!destinations.contains(config.destination), "duplicate destination in fieldEncryptorConfigs");
      destinations.add(config.destination);
      sources.addAll(config.sources);
    }

    // Scan for duplicate
    for (EntryField destination : destinations) {
      checkArgument(sources.contains(destination), destination.toString() + " was a destination, but it was not a source.");
    }

    /*
     * TODO: Behavior with duplicate sources is undefined. This could lead to problems on decrypt. Consider the following situations: Encrypt with config:
     * colFamily = E(row) Update table: row = "new" Encrypt with config: colQualifier = E(row) Decrypt with config: row = D(colFamily), row = D(colQualifier) In
     * this case, row will have different values encrypted into it. This can only arise if different configs are allowed on a single table, but right now there
     * is nothing that stops that.
     */
    this.fieldEncryptorConfigs = Collections.unmodifiableList(fieldEncryptorConfigs);
  }

  /**
   * Write the object to a Writer.
   *
   * @param out
   *          Stream to write object out to.
   */
  public void write(Writer out) throws IOException {
    Ini configIni = new Ini();

    for (FieldEncryptorConfig config : fieldEncryptorConfigs) {
      config.write(configIni);
    }

    configIni.store(out);
  }
}
