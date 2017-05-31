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

import java.util.Collections;
import java.util.Map.Entry;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.accumulo.core.client.BatchScanner;
import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.BatchWriterConfig;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.accumulo.core.util.ByteArraySet;
import org.apache.hadoop.io.Text;

import com.beust.jcommander.Parameter;

import edu.mit.ll.pace.encryption.EncryptedBatchScanner;
import edu.mit.ll.pace.encryption.EncryptedBatchWriter;
import edu.mit.ll.pace.encryption.EncryptionConfig;
import edu.mit.ll.pace.encryption.EncryptionKeyContainer;
import edu.mit.ll.pace.examples.simple.Converters.EncryptionConfigConverter;
import edu.mit.ll.pace.examples.simple.Converters.EncryptionKeyContainerConverter;

/**
 * Demonstrates how to write then read encrypted data.
 */
public class EncryptedReadWriteExample {

  private Connector conn;

  static class Opts extends ReadWriteOpts {
    @Parameter(names = {"--encryption-config"}, description = "encryption config file", required = true, converter = EncryptionConfigConverter.class)
    EncryptionConfig encryptionConfig = null;
    @Parameter(names = {"--encryption-keys"}, description = "encryption key store", required = true, converter = EncryptionKeyContainerConverter.class)
    EncryptionKeyContainer encryptionKeys = null;
  }

  // hidden constructor
  private EncryptedReadWriteExample() {}

  private void execute(Opts opts) throws Exception {
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
      BatchScanner scanner = new EncryptedBatchScanner(conn, opts.getTableName(), opts.auths, 1, opts.encryptionConfig, opts.encryptionKeys);
      scanner.setRanges(Collections.singletonList(new Range()));
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
      BatchWriter writer = new EncryptedBatchWriter(conn, opts.getTableName(), cfg, opts.encryptionConfig, opts.encryptionKeys);
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
    EncryptedReadWriteExample rwe = new EncryptedReadWriteExample();
    Opts opts = new Opts();
    opts.parseArgs(EncryptedReadWriteExample.class.getName(), args);
    rwe.execute(opts);
  }

}
