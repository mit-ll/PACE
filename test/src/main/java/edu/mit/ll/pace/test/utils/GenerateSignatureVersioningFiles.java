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
package edu.mit.ll.pace.test.utils;

import java.io.File;
import java.io.FileReader;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Map.Entry;
import java.util.SortedMap;

import org.apache.accumulo.core.cli.Help;
import org.apache.accumulo.core.client.rfile.RFile;
import org.apache.accumulo.core.client.rfile.RFileWriter;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.LocalFileSystem;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.FileConverter;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.mit.ll.pace.keymanagement.LocalSignatureKeyContainer;
import edu.mit.ll.pace.signature.EntrySigner;
import edu.mit.ll.pace.signature.SignatureConfig;
import edu.mit.ll.pace.signature.SignatureConfigBuilder;
import edu.mit.ll.pace.signature.SignatureKeyContainer;

/**
 * Generates files for use in the version-based signature regression tests.
 */
public final class GenerateSignatureVersioningFiles {

  /**
   * Static class only.
   */
  private GenerateSignatureVersioningFiles() {}

  static {
    // Register Bouncy castle, as it may be needed for reading keys.
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   * Command line options.
   */
  static class Opts extends Help {
    @Parameter(names = {"-c", "--config"}, description = "configuration description", required = true, converter = FileConverter.class)
    File config;
    @Parameter(names = {"-d", "--destination"}, description = "Location to write data", converter = FileConverter.class)
    File destination = Paths.get(System.getProperty("user.dir"), "target", "data").toFile();
    @Parameter(names = {"--count"}, description = "number of entries to create in each file")
    int entryCount = 1000;
    @Parameter(names = {"--size"}, description = "size of the generated entry fields")
    int entryFieldSize = 32;
  }

  /**
   * Create files to use for testing.
   */
  public static void main(String[] args) throws Exception {
    Opts opts = new Opts();
    opts.parseArgs(GenerateSignatureVersioningFiles.class.getName(), args);

    if (opts.destination.exists()) {
      throw new IllegalArgumentException(opts.destination.getPath() + " already exists; please delete it first");
    }
    if (!opts.destination.mkdirs()) {
      throw new IllegalArgumentException("Unable to create output destination");
    }

    generateFiles(opts.config, opts.destination, opts.entryCount, opts.entryFieldSize);
  }

  /**
   * Generate files for the versioning test.
   *
   * @param config
   *          Configuration file describing how the data is generated.
   * @param destination
   *          Directory data will be placed in.
   * @param entryCount
   *          Number of entries to create in each file.
   * @param entryFieldSize
   *          Size of each field in the generated entries.
   */
  private static void generateFiles(File config, File destination, int entryCount, int entryFieldSize) throws Exception {
    String parentDirectory = config.getParent();
    JsonParser parser = new JsonParser();
    JsonObject configJson = parser.parse(new FileReader(config)).getAsJsonObject();

    // Generate the signing keys.
    File keyManifest = Paths.get(parentDirectory, configJson.getAsJsonPrimitive("key-manifest").getAsString()).toFile();
    GenerateKeys.generateKeys(keyManifest, destination, false, true);

    // Generate the data and write it to a file.
    byte[] visibility = new ColumnVisibility(configJson.getAsJsonPrimitive("visibility").getAsString()).getExpression();
    SortedMap<Key,Value> data = GenerateRandomEntries.getRandomData(entryCount, entryFieldSize, visibility);

    LocalFileSystem fs = FileSystem.getLocal(new Configuration());
    RFileWriter writer = RFile.newWriter().to(Paths.get(parentDirectory, configJson.getAsJsonPrimitive("data-table").getAsString()).toString())
        .withFileSystem(fs).build();
    writer.append(data.entrySet());
    writer.close();

    // Generate the files for each configuration.
    for (JsonElement testElem : configJson.getAsJsonArray("tests")) {
      JsonObject test = testElem.getAsJsonObject();
      SignatureConfig signatureConfig = new SignatureConfigBuilder().readFromFile(
          new FileReader(Paths.get(parentDirectory, test.getAsJsonPrimitive("config").getAsString()).toFile())).build();
      SignatureKeyContainer keyContainer = LocalSignatureKeyContainer.read(new FileReader(Paths.get(parentDirectory,
          test.getAsJsonPrimitive("keys").getAsString()).toFile()));

      EntrySigner signer = new EntrySigner(signatureConfig, keyContainer);
      RFileWriter signedWriter = RFile.newWriter().to(Paths.get(parentDirectory, test.getAsJsonPrimitive("table").getAsString()).toString()).withFileSystem(fs)
          .build();

      for (Entry<Key,Value> entry : data.entrySet()) {
        Entry<Key,Value> signedEntry = signer.sign(entry, true);
        signedWriter.append(signedEntry.getKey(), signedEntry.getValue());
      }

      signedWriter.close();
    }
  }

}
