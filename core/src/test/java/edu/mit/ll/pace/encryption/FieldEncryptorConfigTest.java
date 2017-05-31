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

import static edu.mit.ll.pace.test.Matchers.hasSameFieldsAs;
import static edu.mit.ll.pace.test.TestUtils.getResourceAsStream;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.TreeSet;

import org.ini4j.Ini;
import org.junit.Test;

import com.google.common.collect.ImmutableSortedSet;

import edu.mit.ll.pace.EntryField;
import edu.mit.ll.pace.test.Matchers;

/**
 * Test {@link FieldEncryptorConfig}
 */
public class FieldEncryptorConfigTest {

  @Test
  public void constructorExceptionTests() throws IOException {

    try {
      getValidBuilder().setValueEncryptor(null).build();
      fail("valueEnctypor must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setKeyLength(1000).build();
      fail("keyLength must be appropriate for the encryptor");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setKeyId(null).build();
      fail("keyId must be set");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setKeyId("").build();
      fail("keyId must be set");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setValueEncryptor(ValueEncryptor.AES_SIV_DETERMINISTIC).setEncryptUsingVisibility(true).build();
      fail("deterministic encryption cannot be used when keys are created using the visibility");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(null).build();
      fail("destination must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(EntryField.COLUMN_VISIBILITY).build();
      fail("destination must not be column visibility");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(EntryField.TIMESTAMP).build();
      fail("destination must not be timestamp");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setDestination(EntryField.DELETE).build();
      fail("destination must not be delete");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setSources(null).build();
      fail("sources must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getValidBuilder().setSources(new TreeSet<>()).build();
      fail("sources must not be empty");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void readTest() throws IOException {
    FieldEncryptorConfig expectedConfig = new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_CBC).setProvider("SunJCE").setKeyLength(24)
        .setEncryptUsingVisibility(false).setKeyId("keyId").setDestination(EntryField.COLUMN_FAMILY)
        .setSources(ImmutableSortedSet.of(EntryField.ROW, EntryField.COLUMN_QUALIFIER, EntryField.COLUMN_FAMILY)).build();
    FieldEncryptorConfig actualConfig = new FieldEncryptorConfigBuilder().readFromIni(getIni("config1.ini").get(EntryField.COLUMN_FAMILY.toString())).build();
    assertThat("reading the ini file produces the correct configuration", actualConfig, hasSameFieldsAs(expectedConfig));

    expectedConfig = new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_CBC).setProvider("BC").setKeyLength(16)
        .setEncryptUsingVisibility(true).setKeyId("AES_CBC").setDestination(EntryField.ROW).setSources(ImmutableSortedSet.of(EntryField.ROW)).build();
    actualConfig = new FieldEncryptorConfigBuilder().readFromIni(getIni("config2.ini").get(EntryField.ROW.toString())).build();
    assertThat("reading the ini file produces the correct configuration", actualConfig, hasSameFieldsAs(expectedConfig));

    expectedConfig = new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_CBC).setKeyLength(16).setEncryptUsingVisibility(true)
        .setKeyId("AES_CBC").setDestination(EntryField.ROW).setSources(ImmutableSortedSet.of(EntryField.ROW)).build();
    actualConfig = new FieldEncryptorConfigBuilder().readFromIni(getIni("config2WithoutDefaults.ini").get(EntryField.ROW.toString())).build();
    assertThat("default values are correctly set", actualConfig, hasSameFieldsAs(expectedConfig));

    expectedConfig = new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_CBC).setProvider(null).setKeyLength(16)
        .setEncryptUsingVisibility(false).setKeyId(ValueEncryptor.AES_CBC.toString()).setDestination(EntryField.VALUE)
        .setSources(ImmutableSortedSet.of(EntryField.VALUE)).build();
    actualConfig = new FieldEncryptorConfigBuilder().readFromIni(getIni("config3.ini").get(EntryField.VALUE.toString())).build();
    assertThat("reading the ini file produces the correct configuration", actualConfig, hasSameFieldsAs(expectedConfig));
  }

  @Test
  public void writeTest() throws IOException {
    FieldEncryptorConfig config = new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_CBC).setProvider("SunJCE").setKeyLength(24)
        .setEncryptUsingVisibility(false).setKeyId("keyId").setDestination(EntryField.COLUMN_FAMILY)
        .setSources(ImmutableSortedSet.of(EntryField.ROW, EntryField.COLUMN_QUALIFIER, EntryField.COLUMN_FAMILY)).build();

    Ini ini = new Ini();
    config.write(ini);
    assertThat("the configuration is properly written to an ini", ini, is(Matchers.equalTo(getIni("config1.ini"))));

    config = new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_CBC).setProvider("BC").setKeyLength(16).setEncryptUsingVisibility(true)
        .setKeyId("AES_CBC").setDestination(EntryField.ROW).setSources(ImmutableSortedSet.of(EntryField.ROW)).build();
    ini = new Ini();
    config.write(ini);
    assertThat("empty fields are not included in the output ini", ini, is(Matchers.equalTo(getIni("config2.ini"))));
  }

  @Test
  public void writeReadTest() {
    FieldEncryptorConfig config = new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_CBC).setProvider("BC").setKeyLength(32)
        .setEncryptUsingVisibility(false).setKeyId("keyId").setDestination(EntryField.COLUMN_FAMILY)
        .setSources(ImmutableSortedSet.of(EntryField.ROW, EntryField.COLUMN_FAMILY, EntryField.COLUMN_QUALIFIER)).build();

    Ini ini = new Ini();
    config.write(ini);

    FieldEncryptorConfig config2 = new FieldEncryptorConfigBuilder().readFromIni(ini.values().iterator().next()).build();
    assertThat("writing then reading the config should produce an equivalent configuration", config2, hasSameFieldsAs(config));
  }

  /**
   * Get a valid config builder.
   *
   * @return Valid builder.
   */
  private static FieldEncryptorConfigBuilder getValidBuilder() {
    return new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_GCM).setKeyLength(ValueEncryptor.AES_GCM.getDefaultKeyLength())
        .setEncryptUsingVisibility(true).setDestination(EntryField.VALUE).setSources(ImmutableSortedSet.of(EntryField.VALUE));
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

}
