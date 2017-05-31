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
package edu.mit.ll.pace.signature;

import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;

import java.io.IOException;
import java.io.Reader;

import org.ini4j.Ini;
import org.ini4j.Profile.Section;

import edu.mit.ll.pace.signature.SignatureConfig.Destination;

/**
 * Builder for configuration of signer objects.
 */
public class SignatureConfigBuilder {

  // Variables from SignatureConfig.
  private ValueSigner signer;
  private String provider;
  private Destination destination;
  private String destinationTable;
  private byte[] defaultVisibility;

  /**
   * Set the algorithm to use to sign entries.
   *
   * @param signer
   *          The algorithm to use to sign entries.
   * @return Builder.
   */
  public SignatureConfigBuilder setSigner(ValueSigner signer) {
    this.signer = signer;
    return this;
  }

  /**
   * Set the provider to use when creating the signature.
   *
   * @param provider
   *          The provider to use for creating the {@link java.security.Signature}. If null, will allow the system to select the appropriate provider.
   * @return Builder.
   */
  public SignatureConfigBuilder setProvider(String provider) {
    this.provider = provider;
    return this;
  }

  /**
   * Set the destination for the signature.
   *
   * @param destination
   *          The destination where the signature is written to or read from.
   * @return Builder.
   */
  public SignatureConfigBuilder setDestination(Destination destination) {
    this.destination = destination;
    return this;
  }

  /**
   * Set the destination table.
   *
   * @param destinationTable
   *          The table that will store the signatures.
   * @return Builder.
   */
  public SignatureConfigBuilder setDestinationTable(String destinationTable) {
    this.destinationTable = destinationTable;
    return this;
  }

  /**
   * Set the default visibility.
   *
   * @param defaultVisibility
   *          Default visibility to use when wrapping data in the column visibility field.
   * @return Builder.
   */
  public SignatureConfigBuilder setDefaultVisibility(byte[] defaultVisibility) {
    this.defaultVisibility = defaultVisibility;
    return this;
  }

  /**
   * Read the configuration from a Reader.
   *
   * @param in
   *          Stream to read from.
   * @return builder.
   */
  public SignatureConfigBuilder readFromFile(Reader in) throws IOException {
    Ini configIni = new Ini(in);
    Section section = configIni.get(SignatureConfig.SECTION_NAME);

    setSigner(ValueSigner.fromString(section.get("algorithm")));
    setDestination(section.containsKey("destination") ? Destination.fromString(section.get("destination")) : Destination.VALUE);
    setProvider(section.get("provider")).setDestinationTable(section.get("table"));
    setDefaultVisibility(section.containsKey("defaultVisibility") ? section.get("defaultVisibility").getBytes(VISIBILITY_CHARSET) : null);

    return this;
  }

  /**
   * Build the signature config.
   *
   * @return The build signature config.
   */
  public SignatureConfig build() {
    return new SignatureConfig(signer, provider, destination, destinationTable, defaultVisibility);
  }

}
