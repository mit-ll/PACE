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

import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.ini4j.Ini;
import org.ini4j.Profile.Section;

/**
 * Builder for configuration of entry encryptor objects.
 */
public class EncryptionConfigBuilder {

  // For definitions of these values see FieldEncryptorConfig.
  private List<FieldEncryptorConfig> fieldEncryptorConfigs = new ArrayList<>();

  /**
   * Add a field encryptor config.
   *
   * @param fieldEncryptorConfig
   *          Field encryptor config to add.
   * @return Builder.
   */
  public EncryptionConfigBuilder addFieldEncryptorConfig(FieldEncryptorConfig fieldEncryptorConfig) {
    this.fieldEncryptorConfigs.add(fieldEncryptorConfig);
    return this;
  }

  /**
   * Set the field encryptor configs.
   *
   * @param fieldEncryptorConfigs
   *          Field encryptor config to use.
   * @return Builder.
   */

  public EncryptionConfigBuilder setFieldEncryptorConfigs(Collection<FieldEncryptorConfig> fieldEncryptorConfigs) {
    this.fieldEncryptorConfigs.clear();
    if (fieldEncryptorConfigs != null) {
      this.fieldEncryptorConfigs.addAll(fieldEncryptorConfigs);
    }
    return this;
  }

  /**
   * Read the configuration from a Reader.
   *
   * @param in
   *          Stream to read from.
   * @return Builder.
   */
  public EncryptionConfigBuilder readFromFile(Reader in) throws IOException {
    Ini configIni = new Ini(in);

    for (Section section : configIni.values()) {
      addFieldEncryptorConfig(new FieldEncryptorConfigBuilder().readFromIni(section).build());
    }

    return this;
  }

  /**
   * Build the {@link EncryptionConfig}.
   *
   * @return Built config.
   */
  public EncryptionConfig build() {
    return new EncryptionConfig(fieldEncryptorConfigs);
  }
}
