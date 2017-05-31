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
package edu.mit.ll.pace.test.signature;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.FileReader;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import edu.mit.ll.pace.test.utils.GenerateSignatureVersioningFiles;
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

import edu.mit.ll.pace.harness.AccumuloRunner;
import edu.mit.ll.pace.internal.Utils;
import edu.mit.ll.pace.keymanagement.LocalSignatureKeyContainer;
import edu.mit.ll.pace.signature.EntrySigner;
import edu.mit.ll.pace.signature.SignatureConfig;
import edu.mit.ll.pace.signature.SignatureConfigBuilder;
import edu.mit.ll.pace.signature.SignatureKeyContainer;
import edu.mit.ll.pace.test.Matchers;

/**
 * Regression test to ensure that data stays consistent between versions.
 * <p>
 * When a change to data format is made, a new set of tests should be generated using {@link GenerateSignatureVersioningFiles}.
 */
@RunWith(AccumuloRunner.class)
public class VersioningIT {

  @Test
  public void versionTest() throws Exception {
    String parentDirectory = Paths.get(System.getProperty("user.dir"), "src", "main", "resources", "edu", "mit", "ll", "pace", "test", "signature",
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
      SignatureConfig signatureConfig = new SignatureConfigBuilder().readFromFile(
          new FileReader(Paths.get(parentDirectory, test.getAsJsonPrimitive("config").getAsString()).toFile())).build();
      SignatureKeyContainer keyContainer = LocalSignatureKeyContainer.read(new FileReader(Paths.get(parentDirectory,
          test.getAsJsonPrimitive("keys").getAsString()).toFile()));

      EntrySigner verifier = new EntrySigner(signatureConfig, keyContainer);
      Scanner signedScanner = RFile.newScanner().from(Paths.get(parentDirectory, test.getAsJsonPrimitive("table").getAsString()).toString()).withFileSystem(fs)
          .withAuthorizations(authorizations).build();

      runTest(dataScanner, signedScanner, verifier, signatureConfig);
    }
  }

  /**
   * Run a specific test for a given version and configuration.
   *
   * @param dataScanner
   *          Scanner for the unsigned data.
   * @param signedScanner
   *          Scanner for the signed data.
   * @param verifier
   *          Verifier for the signed data.
   * @param signatureConfig
   *          Configuration for the verifier.
   */
  private void runTest(Scanner dataScanner, Scanner signedScanner, EntrySigner verifier, SignatureConfig signatureConfig) {
    Iterator<Entry<Key,Value>> iterator = signedScanner.iterator();
    for (Entry<Key,Value> entry : dataScanner) {
      assertThat("should have more entries", iterator.hasNext(), is(true));
      Entry<Key,Value> signedEntry = iterator.next();

      Entry<Key,Value> verifiedEntry;
      if (signatureConfig.isSignatureInSeparateTable()) {
        assertThat("keys should match", signedEntry.getKey(), equalTo(entry.getKey()));
        assertThat("values should not match", signedEntry.getValue().get(), not(equalTo(entry.getValue().get())));
        verifiedEntry = verifier.verify(entry, signedEntry);
      } else {
        verifiedEntry = verifier.verify(signedEntry);
      }

      assertThat("entries should match", verifiedEntry, Matchers.equalTo(entry));
    }

    assertThat("should have no more entries", iterator.hasNext(), is(false));
  }

}
