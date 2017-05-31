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
package edu.mit.ll.pace.examples.simple;

import java.util.Map.Entry;

import org.apache.accumulo.core.cli.BatchWriterOpts;
import org.apache.accumulo.core.cli.ScannerOpts;
import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.BatchWriterConfig;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.util.ByteArraySet;

import com.beust.jcommander.Parameter;

import edu.mit.ll.pace.encryption.EncryptedBatchWriter;
import edu.mit.ll.pace.encryption.EncryptionConfig;
import edu.mit.ll.pace.encryption.EncryptionKeyContainer;
import edu.mit.ll.pace.examples.simple.Converters.EncryptionConfigConverter;
import edu.mit.ll.pace.examples.simple.Converters.EncryptionKeyContainerConverter;

/**
 * Demonstrates how to write then read encrypted data.
 */
public class EncryptedConverterExample {

  static class Opts extends ConverterOpts {
    @Parameter(names = {"--encryption-config"}, description = "encryption config file", required = true, converter = EncryptionConfigConverter.class)
    EncryptionConfig encryptionConfig = null;
    @Parameter(names = {"--encryption-keys"}, description = "encryption key store", required = true, converter = EncryptionKeyContainerConverter.class)
    EncryptionKeyContainer encryptionKeys = null;
  }

  // hidden constructor
  private EncryptedConverterExample() {}

  public static void main(String[] args) throws Exception {
    Opts opts = new Opts();
    ScannerOpts scanOpts = new ScannerOpts();
    BatchWriterOpts batchOpts = new BatchWriterOpts();
    opts.parseArgs(EncryptedConverterExample.class.getName(), args, batchOpts, scanOpts);

    Connector conn = opts.getConnector();

    // add the authorizations to the user
    Authorizations userAuthorizations = conn.securityOperations().getUserAuthorizations(opts.getPrincipal());
    ByteArraySet auths = new ByteArraySet(userAuthorizations.getAuthorizations());
    auths.addAll(opts.auths.getAuthorizations());
    if (!auths.isEmpty())
      conn.securityOperations().changeUserAuthorizations(opts.getPrincipal(), new Authorizations(auths));

    // create table
    if (opts.createDestinationTable) {
      conn.tableOperations().create(opts.destination);
    }

    // Transform entries
    Scanner scanner = conn.createScanner(opts.source, opts.auths);
    scanner.setBatchSize(scanOpts.scanBatchSize);

    BatchWriterConfig bwConfig = batchOpts.getBatchWriterConfig();
    bwConfig.setDurability(opts.durability);
    BatchWriter writer = new EncryptedBatchWriter(conn, opts.destination, bwConfig, opts.encryptionConfig, opts.encryptionKeys);

    long count = 0;
    for (Entry<Key,Value> entry : scanner) {
      Mutation mutation = new Mutation(entry.getKey().getRow());
      mutation.put(entry.getKey().getColumnFamily(), entry.getKey().getColumnQualifier(), entry.getKey().getColumnVisibilityParsed(), entry.getKey()
          .getTimestamp(), entry.getValue());
      writer.addMutation(mutation);

      count++;
      if (count % 10000 == 0) {
        System.out.println(String.format("converted %d entries", count));
      }
    }

    writer.flush();
    writer.close();

    // delete table
    if (opts.deleteSourceTable)
      conn.tableOperations().delete(opts.source);
  }

}
