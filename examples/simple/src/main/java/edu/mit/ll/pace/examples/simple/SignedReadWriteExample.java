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
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.accumulo.core.cli.ScannerOpts;
import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.BatchWriterConfig;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.accumulo.core.util.ByteArraySet;
import org.apache.hadoop.io.Text;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.beust.jcommander.Parameter;

import edu.mit.ll.pace.examples.simple.Converters.SignatureConfigConverter;
import edu.mit.ll.pace.examples.simple.Converters.SignatureKeyContainerConverter;
import edu.mit.ll.pace.signature.SignatureConfig;
import edu.mit.ll.pace.signature.SignatureKeyContainer;
import edu.mit.ll.pace.signature.SignedBatchWriter;
import edu.mit.ll.pace.signature.SignedScanner;

/**
 * Demonstrates how to write then read signed data.
 */
public class SignedReadWriteExample {

  private Connector conn;

  static {
    // Register Bouncy castle, as it will be used to parse some signature keys.
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  static class Opts extends ReadWriteOpts {
    @Parameter(names = {"--signature-config"}, description = "signature config file", required = true, converter = SignatureConfigConverter.class)
    SignatureConfig signatureConfig = null;
    @Parameter(names = {"--signature-keys"}, description = "signature key store", required = true, converter = SignatureKeyContainerConverter.class)
    SignatureKeyContainer signatureKeys = null;
  }

  // hidden constructor
  private SignedReadWriteExample() {}

  private void execute(Opts opts, ScannerOpts scanOpts) throws Exception {
    conn = opts.getConnector();

    // add the authorizations to the user
    Authorizations userAuthorizations = conn.securityOperations().getUserAuthorizations(opts.getPrincipal());
    ByteArraySet auths = new ByteArraySet(userAuthorizations.getAuthorizations());
    auths.addAll(opts.auths.getAuthorizations());
    if (!auths.isEmpty())
      conn.securityOperations().changeUserAuthorizations(opts.getPrincipal(), new Authorizations(auths));

    // create table
    if (opts.createtable) {
      SortedSet<Text> partitionKeys = new TreeSet<>();
      for (int i = Byte.MIN_VALUE; i < Byte.MAX_VALUE; i++)
        partitionKeys.add(new Text(new byte[] {(byte) i}));
      conn.tableOperations().create(opts.getTableName());
      conn.tableOperations().addSplits(opts.getTableName(), partitionKeys);
    }

    // send mutations
    createEntries(opts);

    // read entries
    if (opts.readEntries) {
      // Note that the user needs to have the authorizations for the specified scan authorizations
      // by an administrator first
      Scanner scanner = new SignedScanner(conn, opts.getTableName(), opts.auths, opts.signatureConfig, opts.signatureKeys);
      scanner.setBatchSize(scanOpts.scanBatchSize);
      for (Entry<Key,Value> entry : scanner)
        System.out.println(entry.getKey().toString() + " -> " + entry.getValue().toString());
    }

    // delete table
    if (opts.deletetable)
      conn.tableOperations().delete(opts.getTableName());
  }

  private void createEntries(Opts opts) throws Exception {
    if (opts.createEntries || opts.deleteEntries) {
      BatchWriterConfig cfg = new BatchWriterConfig();
      cfg.setDurability(opts.durability);
      BatchWriter writer = new SignedBatchWriter(conn, opts.getTableName(), cfg, opts.signatureConfig, opts.signatureKeys);
      ColumnVisibility cv = new ColumnVisibility(opts.auths.toString().replace(',', '|'));

      Text cf = new Text("datatypes");
      Text cq = new Text("xml");
      byte[] row = {'h', 'e', 'l', 'l', 'o', '\0'};
      byte[] value = {'w', 'o', 'r', 'l', 'd', '\0'};

      for (int i = 0; i < 10; i++) {
        row[row.length - 1] = (byte) i;
        Mutation m = new Mutation(new Text(row));
        if (opts.deleteEntries) {
          m.putDelete(cf, cq, cv);
        }
        if (opts.createEntries) {
          value[value.length - 1] = (byte) i;
          m.put(cf, cq, cv, new Value(value));
        }
        writer.addMutation(m);
      }
      writer.close();
    }
  }

  public static void main(String[] args) throws Exception {
    SignedReadWriteExample rwe = new SignedReadWriteExample();
    Opts opts = new Opts();
    ScannerOpts scanOpts = new ScannerOpts();
    opts.parseArgs(SignedReadWriteExample.class.getName(), args, scanOpts);
    rwe.execute(opts, scanOpts);
  }

}
