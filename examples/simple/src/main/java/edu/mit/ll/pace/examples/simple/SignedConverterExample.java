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

import java.security.Security;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.beust.jcommander.Parameter;

import edu.mit.ll.pace.examples.simple.Converters.SignatureConfigConverter;
import edu.mit.ll.pace.examples.simple.Converters.SignatureKeyContainerConverter;
import edu.mit.ll.pace.signature.SignatureConfig;
import edu.mit.ll.pace.signature.SignatureKeyContainer;
import edu.mit.ll.pace.signature.SignedBatchWriter;

/**
 * Demonstrates how to convert a table to signed form.
 */
public class SignedConverterExample {

  static class Opts extends ConverterOpts {
    @Parameter(names = {"--signature-config"}, description = "signature config file", required = true, converter = SignatureConfigConverter.class)
    SignatureConfig signatureConfig = null;
    @Parameter(names = {"--signature-keys"}, description = "signature key store", required = true, converter = SignatureKeyContainerConverter.class)
    SignatureKeyContainer signatureKeys = null;
  }

  // hidden constructor
  private SignedConverterExample() {}

  static {
    // Register Bouncy castle, as it will be used to parse some signature keys.
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public static void main(String[] args) throws Exception {
    Opts opts = new Opts();
    ScannerOpts scanOpts = new ScannerOpts();
    BatchWriterOpts batchOpts = new BatchWriterOpts();
    opts.parseArgs(SignedConverterExample.class.getName(), args, batchOpts, scanOpts);

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
    BatchWriter writer = new SignedBatchWriter(conn, opts.destination, bwConfig, opts.signatureConfig, opts.signatureKeys);

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
