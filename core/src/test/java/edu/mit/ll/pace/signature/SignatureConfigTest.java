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

import static edu.mit.ll.pace.test.Matchers.equalTo;
import static edu.mit.ll.pace.test.Matchers.hasSameFieldsAs;
import static edu.mit.ll.pace.test.TestUtils.getResourceAsStream;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import org.hamcrest.Matchers;
import org.ini4j.Ini;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import edu.mit.ll.pace.internal.Utils;
import edu.mit.ll.pace.signature.SignatureConfig.Destination;

/**
 * Test for {@link SignatureConfig} and {@link SignatureConfigBuilder}.
 */
public class SignatureConfigTest {

  @Rule
  public TemporaryFolder temp = new TemporaryFolder();

  // Configurations matching the ini files in the resource directory.
  private static final SignatureConfig config1 = new SignatureConfigBuilder().setSigner(ValueSigner.RSA_PSS).setProvider("BC")
      .setDestination(Destination.VALUE).build();
  private static final SignatureConfig config2 = new SignatureConfigBuilder().setSigner(ValueSigner.RSA_PKCS1).setDestination(Destination.COLUMN_VISIBILITY)
      .setDefaultVisibility("default".getBytes(Utils.VISIBILITY_CHARSET)).build();
  private static final SignatureConfig config3 = new SignatureConfigBuilder().setSigner(ValueSigner.ECDSA).setDestination(Destination.SEPARATE_TABLE)
      .setDestinationTable("sigs").build();

  @Test
  public void constructorExceptionTest() {
    try {
      getValidBuilder().setSigner(null).build();
      fail("signer must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(null).build();
      fail("destination must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(Destination.SEPARATE_TABLE).setDestinationTable(null).build();
      fail("if storing to a separate table, destination table must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(Destination.SEPARATE_TABLE).setDestinationTable("").build();
      fail("if storing to a separate table, destination table must not be empty");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(Destination.VALUE).setDestinationTable("something").build();
      fail("if not storing to a separate table, destination table must not be set");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(Destination.COLUMN_VISIBILITY).setDefaultVisibility(null).build();
      fail("if storing to the column visibility field, default visibility must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(Destination.COLUMN_VISIBILITY).setDefaultVisibility(Utils.EMPTY).build();
      fail("if storing to the column visibility field, default visibility must not be empty");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(Destination.VALUE).setDefaultVisibility("something".getBytes(Utils.VISIBILITY_CHARSET)).build();
      fail("if not storing to the column visibility field, default visibility must not be set");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void readTest() throws Exception {
    SignatureConfig actualConfig = new SignatureConfigBuilder().readFromFile(getReader("config1.ini")).build();
    assertThat("reading the ini file produces the correct configuration", actualConfig, hasSameFieldsAs(config1));

    actualConfig = new SignatureConfigBuilder().readFromFile(getReader("config1WithoutDefault.ini")).build();
    assertThat("reading the ini file produces the correct configuration", actualConfig, hasSameFieldsAs(config1));

    actualConfig = new SignatureConfigBuilder().readFromFile(getReader("config2.ini")).build();
    assertThat("reading the ini file produces the correct configuration", actualConfig, hasSameFieldsAs(config2));

    actualConfig = new SignatureConfigBuilder().readFromFile(getReader("config3.ini")).build();
    assertThat("reading the ini file produces the correct configuration", actualConfig, hasSameFieldsAs(config3));
  }

  @Test
  public void writeTest() throws Exception {
    File file = writeConfigToFile(config1);
    Ini expectedIni = getIni("config1.ini");
    Ini actualIni = new Ini(file);
    assertThat("writing the ini file produces the correct configuration", expectedIni, equalTo(actualIni));

    file = writeConfigToFile(config2);
    expectedIni = getIni("config2.ini");
    actualIni = new Ini(file);
    assertThat("writing the ini file produces the correct configuration", expectedIni, equalTo(actualIni));

    file = writeConfigToFile(config3);
    expectedIni = getIni("config3.ini");
    actualIni = new Ini(file);
    assertThat("writing the ini file produces the correct configuration", expectedIni, equalTo(actualIni));
  }

  @Test
  public void writeReadTest() throws Exception {
    File file = writeConfigToFile(config1);
    SignatureConfig actualConfig = new SignatureConfigBuilder().readFromFile(new FileReader(file)).build();
    assertThat("writing then reading the config produces an equivalent configuration", actualConfig, hasSameFieldsAs(config1));

    file = writeConfigToFile(config2);
    actualConfig = new SignatureConfigBuilder().readFromFile(new FileReader(file)).build();
    assertThat("writing then reading the config produces an equivalent configuration", actualConfig, hasSameFieldsAs(config2));

    file = writeConfigToFile(config3);
    actualConfig = new SignatureConfigBuilder().readFromFile(new FileReader(file)).build();
    assertThat("writing then reading the config produces an equivalent configuration", actualConfig, hasSameFieldsAs(config3));
  }

  @Test
  public void getAlgorithmTest() {
    assertThat("correct algorithm", config1.getAlgorithm(), Matchers.equalTo(config1.algorithm));
    assertThat("correct algorithm", config2.getAlgorithm(), Matchers.equalTo(config2.algorithm));
    assertThat("correct algorithm", config3.getAlgorithm(), Matchers.equalTo(config3.algorithm));
  }

  @Test
  public void isSignatureInSeparateTableTest() {
    assertThat("correct return value", config1.isSignatureInSeparateTable(), is(false));
    assertThat("correct return value", config2.isSignatureInSeparateTable(), is(false));
    assertThat("correct return value", config3.isSignatureInSeparateTable(), is(true));
  }

  /**
   * Write the given configuration to a file.
   *
   * @param config
   *          Configuration to write.
   * @return The file that was written to.
   */
  private File writeConfigToFile(SignatureConfig config) throws IOException {
    File file = temp.newFile();
    FileWriter writer = new FileWriter(file);
    config.write(writer);
    writer.close();
    return file;
  }

  /**
   * Get a builder wrapping a valid configuration.
   *
   * @return Valid builder.
   */
  private SignatureConfigBuilder getValidBuilder() {
    return new SignatureConfigBuilder().setSigner(ValueSigner.RSA_PKCS1).setDestination(Destination.VALUE);
  }

  /**
   * Get the requested INI.
   *
   * @param resource
   *          INI file to get.
   * @return The INI file.
   */
  private Ini getIni(String resource) throws IOException {
    return new Ini(getResourceAsStream(this.getClass(), resource));
  }

  /**
   * Get the requested INI.
   *
   * @param resource
   *          INI file to get.
   * @return The INI file.
   */
  private Reader getReader(String resource) throws IOException {
    return new InputStreamReader(getResourceAsStream(this.getClass(), resource));
  }

}
