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

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.TreeMap;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.TypeSafeMatcher;
import org.ini4j.Ini;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSortedSet;

import edu.mit.ll.pace.EntryField;
import edu.mit.ll.pace.test.Matchers;

/**
 * Test {@link EncryptionConfig}.
 */
public class EncryptionConfigTest {

  /**
   * In memory representation of the config.
   */
  private static final EncryptionConfig config1 = new EncryptionConfigBuilder()
      .addFieldEncryptorConfig(
          new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_CBC).setProvider("BC").setKeyLength(16).setEncryptUsingVisibility(false)
              .setKeyId("keyId").setDestination(EntryField.COLUMN_FAMILY)
              .setSources(ImmutableSortedSet.of(EntryField.ROW, EntryField.COLUMN_FAMILY, EntryField.COLUMN_QUALIFIER)).build())
      .addFieldEncryptorConfig(
          new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_SIV_DETERMINISTIC).setKeyLength(32).setEncryptUsingVisibility(false)
              .setKeyId("keyId2").setDestination(EntryField.COLUMN_QUALIFIER)
              .setSources(ImmutableSortedSet.of(EntryField.COLUMN_FAMILY, EntryField.COLUMN_QUALIFIER)).build())
      .addFieldEncryptorConfig(
          new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_GCM).setKeyLength(24).setEncryptUsingVisibility(true).setKeyId("AES_GCM")
              .setDestination(EntryField.VALUE).setSources(ImmutableSortedSet.of(EntryField.VALUE)).build()).build();

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Test
  public void constructorExceptionTests() throws IOException {
    try {
      new EncryptionConfigBuilder().setFieldEncryptorConfigs(null).build();
      fail("null fieldEncryptionConfigs should not be allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new EncryptionConfigBuilder().readFromFile(getReader("emptyConfig.ini")).build();
      fail("empty fieldEncryptionConfigs should not be allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new EncryptionConfigBuilder().setFieldEncryptorConfigs(
          ImmutableList.of(
              new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_GCM).setProvider("BC").setKeyLength(32).setEncryptUsingVisibility(true)
                  .setKeyId("AES_GCM").setDestination(EntryField.VALUE).setSources(ImmutableSortedSet.of(EntryField.VALUE)).build(),
              new FieldEncryptorConfigBuilder().setValueEncryptor(ValueEncryptor.AES_GCM).setProvider("BC").setKeyLength(32).setEncryptUsingVisibility(true)
                  .setKeyId("AES_GCM").setDestination(EntryField.VALUE).setSources(ImmutableSortedSet.of(EntryField.VALUE)).build())).build();
      fail("duplicate fieldEncryptionConfigs should not be allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void readTest() throws IOException {
    EncryptionConfig actual = new EncryptionConfigBuilder().readFromFile(getReader("config1.ini")).build();
    assertThat("reading the ini produces the correct configuration", actual, is(equalTo(config1)));
  }

  @Test
  public void writeTest() throws IOException {
    File iniFile = testFolder.newFile();
    FileWriter out = new FileWriter(iniFile);
    config1.write(out);
    out.close();

    Ini actual = new Ini(new FileReader(iniFile));
    Ini expected = getIni("config1.ini");
    assertThat("reading the ini produces the correct configuration", actual, is(Matchers.equalTo(expected)));
  }

  @Test
  public void writeReadTest() throws IOException {
    File ini = testFolder.newFile();
    FileWriter out = new FileWriter(ini);
    config1.write(out);
    out.close();

    FileReader in = new FileReader(ini);
    EncryptionConfig config2 = new EncryptionConfigBuilder().readFromFile(in).build();
    in.close();

    assertThat("writing then reading the config should produce an equivalent configuration", config2, is(equalTo(config1)));
  }

  /**
   * Gets a hamcrest matcher that tests whether two {@link EncryptionConfig} are equal.
   *
   * @param expectedValue
   *          The expected value to core against.
   * @return Method safe matcher that will core field equality.
   */
  @Factory
  private static TypeSafeMatcher<EncryptionConfig> equalTo(final EncryptionConfig expectedValue) {
    final TreeMap<EntryField,TypeSafeMatcher<FieldEncryptorConfig>> configMatchers = new TreeMap<>();
    for (FieldEncryptorConfig config : expectedValue.fieldEncryptorConfigs) {
      configMatchers.put(config.destination, hasSameFieldsAs(config));
    }

    return new TypeSafeMatcher<EncryptionConfig>() {
      @Override
      protected boolean matchesSafely(EncryptionConfig actualValue) {
        if (actualValue.fieldEncryptorConfigs.size() != configMatchers.size()) {
          return false;
        }

        for (FieldEncryptorConfig config : actualValue.fieldEncryptorConfigs) {
          TypeSafeMatcher<FieldEncryptorConfig> matcher = configMatchers.get(config.destination);
          if (matcher == null || !matcher.matches(config)) {
            return false;
          }
        }

        return true;
      }

      @Override
      protected void describeMismatchSafely(EncryptionConfig actualValue, Description description) {
        description.appendText("was [\n");
        for (FieldEncryptorConfig config : actualValue.fieldEncryptorConfigs) {
          description.appendText("\t\t{").appendText(ReflectionToStringBuilder.toString(config, ToStringStyle.SIMPLE_STYLE)).appendText("}\n");
        }
        description.appendText("\t]");
      }

      @Override
      public void describeTo(Description description) {
        description.appendText("[\n");
        for (FieldEncryptorConfig config : expectedValue.fieldEncryptorConfigs) {
          description.appendText("\t\t{").appendText(ReflectionToStringBuilder.toString(config, ToStringStyle.SIMPLE_STYLE)).appendText("}\n");
        }
        description.appendText("\t]");
      }

    };
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
