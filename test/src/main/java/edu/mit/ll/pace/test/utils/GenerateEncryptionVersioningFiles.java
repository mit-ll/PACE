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
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;

import org.apache.accumulo.core.cli.Help;
import org.apache.accumulo.core.client.rfile.RFile;
import org.apache.accumulo.core.client.rfile.RFileWriter;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.LocalFileSystem;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.FileConverter;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.mit.ll.pace.encryption.EncryptionConfig;
import edu.mit.ll.pace.encryption.EncryptionConfigBuilder;
import edu.mit.ll.pace.encryption.EncryptionKeyContainer;
import edu.mit.ll.pace.encryption.EntryEncryptor;
import edu.mit.ll.pace.keymanagement.LocalEncryptionKeyContainer;

/**
 * Generate files for use in the version-based encryption regression tests.
 */
public final class GenerateEncryptionVersioningFiles {

  /**
   * Static class only.
   */
  private GenerateEncryptionVersioningFiles() {}

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
    opts.parseArgs(GenerateEncryptionVersioningFiles.class.getName(), args);

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
    GenerateKeys.generateKeys(keyManifest, destination, true, false);

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
      EncryptionConfig encryptionConfig = new EncryptionConfigBuilder().readFromFile(
          new FileReader(Paths.get(parentDirectory, test.getAsJsonPrimitive("config").getAsString()).toFile())).build();
      EncryptionKeyContainer keyContainer = LocalEncryptionKeyContainer.read(new FileReader(Paths.get(parentDirectory,
          test.getAsJsonPrimitive("keys").getAsString()).toFile()));
      EntryEncryptor encryptor = new EntryEncryptor(encryptionConfig, keyContainer);

      // We have to add entries to a sorted map first, as RFiles must be in order.
      SortedMap<Key,Value> encryptedEntries = new TreeMap<>();
      for (Entry<Key,Value> entry : data.entrySet()) {
        Entry<Key,Value> encryptedEntry = encryptor.encrypt(entry);
        encryptedEntries.put(encryptedEntry.getKey(), encryptedEntry.getValue());
      }

      RFileWriter encryptedWriter = RFile.newWriter().to(Paths.get(parentDirectory, test.getAsJsonPrimitive("table").getAsString()).toString())
          .withFileSystem(fs).build();
      encryptedWriter.append(encryptedEntries.entrySet());
      encryptedWriter.close();
    }
  }

}
