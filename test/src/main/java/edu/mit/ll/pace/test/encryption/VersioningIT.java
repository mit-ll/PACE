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
package edu.mit.ll.pace.test.encryption;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.FileReader;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;

import edu.mit.ll.pace.test.utils.GenerateEncryptionVersioningFiles;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.client.rfile.RFile;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.VisibilityEvaluator;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.LocalFileSystem;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.mit.ll.pace.encryption.EncryptionConfig;
import edu.mit.ll.pace.encryption.EncryptionConfigBuilder;
import edu.mit.ll.pace.encryption.EncryptionKeyContainer;
import edu.mit.ll.pace.encryption.EntryEncryptor;
import edu.mit.ll.pace.harness.AccumuloRunner;
import edu.mit.ll.pace.internal.Utils;
import edu.mit.ll.pace.keymanagement.LocalEncryptionKeyContainer;

/**
 * Regression test to ensure that data stays consistent between versions.
 * <p>
 * When a change to data format is made, a new set of tests should be generated using {@link GenerateEncryptionVersioningFiles}.
 */
@RunWith(AccumuloRunner.class)
public class VersioningIT {

  @Test
  public void versionTest() throws Exception {
    String parentDirectory = Paths.get(System.getProperty("user.dir"), "src", "main", "resources", "edu", "mit", "ll", "pace", "test", "encryption",
        "VersioningIT").toString();

    JsonParser parser = new JsonParser();
    JsonArray versions = parser.parse(new FileReader(Paths.get(parentDirectory, "config.json").toFile())).getAsJsonObject().getAsJsonArray("versions");

    for (JsonElement versionElement : versions) {
      testVersion(Paths.get(parentDirectory, versionElement.getAsJsonPrimitive().getAsString()).toFile());
    }
  }

  /**
   * Test that rfiles created by a specific version of PACE still work correctly.
   *
   * @param versionConfig
   *          Configuration for the version with which the rfiles were generated.
   */
  private void testVersion(File versionConfig) throws Exception {
    String parentDirectory = versionConfig.getParent();

    JsonParser parser = new JsonParser();
    JsonObject configJson = parser.parse(new FileReader(versionConfig)).getAsJsonObject();

    // Get a scanner for the data file.
    List<byte[]> auths = new ArrayList<>();
    for (JsonElement authElem : configJson.getAsJsonArray("authorizations")) {
      auths.add(VisibilityEvaluator.escape(authElem.getAsString().getBytes(Utils.VISIBILITY_CHARSET), false));
    }
    Authorizations authorizations = new Authorizations(auths);

    LocalFileSystem fs = FileSystem.getLocal(new Configuration());
    Scanner dataScanner = RFile.newScanner().from(Paths.get(parentDirectory, configJson.getAsJsonPrimitive("data-table").getAsString()).toString())
        .withFileSystem(fs).withAuthorizations(authorizations).build();

    // Validate each configuration.
    for (JsonElement testElem : configJson.getAsJsonArray("tests")) {
      JsonObject test = testElem.getAsJsonObject();
      EncryptionConfig encryptionConfig = new EncryptionConfigBuilder().readFromFile(
          new FileReader(Paths.get(parentDirectory, test.getAsJsonPrimitive("config").getAsString()).toFile())).build();
      EncryptionKeyContainer keyContainer = LocalEncryptionKeyContainer.read(new FileReader(Paths.get(parentDirectory,
          test.getAsJsonPrimitive("keys").getAsString()).toFile()));

      EntryEncryptor decryptor = new EntryEncryptor(encryptionConfig, keyContainer);
      Scanner encryptedScanner = RFile.newScanner().from(Paths.get(parentDirectory, test.getAsJsonPrimitive("table").getAsString()).toString())
          .withFileSystem(fs).withAuthorizations(authorizations).build();

      runTest(dataScanner, encryptedScanner, decryptor);
    }
  }

  /**
   * Run a specific test for a given version and configuration.
   *
   * @param dataScanner
   *          Scanner for the unsigned data.
   * @param encryptedScanner
   *          Scanner for the encryption data.
   * @param decryptor
   *          Decryptor for the data.
   */
  private void runTest(Scanner dataScanner, Scanner encryptedScanner, EntryEncryptor decryptor) {
    // Read the encrypted data into memory.
    SortedMap<Key,Value> decryptedData = new TreeMap<>();
    for (Entry<Key,Value> encryptedEntry : encryptedScanner) {
      Entry<Key,Value> decryptedEntry = decryptor.decrypt(encryptedEntry);
      decryptedData.put(decryptedEntry.getKey(), decryptedEntry.getValue());
    }

    for (Entry<Key,Value> entry : dataScanner) {
      assertThat("there is a matching decrypted value", decryptedData.containsKey(entry.getKey()), is(true));
      assertThat("the value also matches", decryptedData.get(entry.getKey()).get(), equalTo(entry.getValue().get()));
    }
  }

}
