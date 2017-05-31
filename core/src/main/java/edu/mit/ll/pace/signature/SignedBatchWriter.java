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
package edu.mit.ll.pace.signature;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.Map.Entry;

import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.BatchWriterConfig;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.MutationsRejectedException;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.data.ColumnUpdate;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.ColumnVisibility;

import edu.mit.ll.pace.internal.MutableEntry;
import edu.mit.ll.pace.signature.SignatureConfig.Destination;

/**
 * Writes signed entries to Accumulo.
 */
public final class SignedBatchWriter implements BatchWriter {

  /**
   * A {@link BatchWriter} to use to write the data to Accumulo.
   */
  private final BatchWriter tableWriter;

  /**
   * A {@link BatchWriter} to use to write the data to Accumulo when signatures are stored in a separate table.
   */
  private final BatchWriter signatureTableWriter;

  /**
   * The {@link EntrySigner} that will handle signing for this instance.
   */
  private final EntrySigner signer;

  /**
   * The {@link EntrySigner} that will handle signing for this instance.
   */
  private final SignatureConfig signatureConfig;

  /**
   * Create an signed batch tableWriter.
   *
   * @param connector
   *          The connector for the Accumulo instance.
   * @param tableName
   *          Name of the table to write to.
   * @param batchConfig
   *          Configuration for a {@link BatchWriter}.
   * @param signatureConfig
   *          Configuration for the signatures.
   * @param keys
   *          Container with the keys to use for signatures.
   */
  public SignedBatchWriter(Connector connector, String tableName, BatchWriterConfig batchConfig, SignatureConfig signatureConfig, SignatureKeyContainer keys)
      throws TableNotFoundException {
    checkArgument(connector != null, "connector is null");
    checkArgument(tableName != null, "tableName is null");
    checkArgument(signatureConfig != null, "signatureConfig is null");
    checkArgument(keys != null, "keys is null");

    this.tableWriter = connector.createBatchWriter(tableName, batchConfig);
    this.signer = new EntrySigner(signatureConfig, keys);
    this.signatureConfig = signatureConfig;

    if (signatureConfig.destination == SignatureConfig.Destination.SEPARATE_TABLE) {
      this.signatureTableWriter = connector.createBatchWriter(signatureConfig.destinationTable, batchConfig);
    } else {
      this.signatureTableWriter = null;
    }
  }

  /**
   * Signs the given mutation and then write it to Accumulo.
   *
   * @param mutation
   *          The mutation to sign.
   */
  @Override
  public void addMutation(Mutation mutation) throws MutationsRejectedException {
    Mutation signedMutation = new Mutation(mutation.getRow());

    // Sign the entries.
    for (ColumnUpdate update : mutation.getUpdates()) {
      if (update.isDeleted()) {
        if (signatureConfig.destination == Destination.COLUMN_VISIBILITY) {
          throw new IllegalArgumentException("cannot delete entries when the signature is stored in the column visibility");
        }

        if (update.hasTimestamp()) {
          signedMutation.putDelete(update.getColumnFamily(), update.getColumnQualifier(), new ColumnVisibility(update.getColumnVisibility()),
              update.getTimestamp());
        } else {
          signedMutation.putDelete(update.getColumnFamily(), update.getColumnQualifier(), new ColumnVisibility(update.getColumnVisibility()));
        }
      } else {
        Entry<Key,Value> signedEntry = signer.sign(new MutableEntry(mutation.getRow(), update).toEntry(), update.hasTimestamp());
        Key signedKey = signedEntry.getKey();

        if (update.hasTimestamp()) {
          signedMutation.put(signedKey.getColumnFamily(), signedKey.getColumnQualifier(), signedKey.getColumnVisibilityParsed(), signedKey.getTimestamp(),
              signedEntry.getValue());
        } else {
          signedMutation.put(signedKey.getColumnFamily(), signedKey.getColumnQualifier(), signedKey.getColumnVisibilityParsed(), signedEntry.getValue());
        }
      }
    }

    // Write the signed mutations.
    if (signatureTableWriter != null) {
      tableWriter.addMutation(mutation);
      signatureTableWriter.addMutation(signedMutation);
    } else {
      tableWriter.addMutation(signedMutation);
    }
  }

  @Override
  public void addMutations(Iterable<Mutation> iterable) throws MutationsRejectedException {
    for (Mutation mutation : iterable) {
      addMutation(mutation);
    }
  }

  @Override
  public void flush() throws MutationsRejectedException {
    tableWriter.flush();
    if (signatureTableWriter != null) {
      signatureTableWriter.flush();
    }
  }

  @Override
  public void close() throws MutationsRejectedException {
    tableWriter.close();
    if (signatureTableWriter != null) {
      signatureTableWriter.close();
    }
  }
}
