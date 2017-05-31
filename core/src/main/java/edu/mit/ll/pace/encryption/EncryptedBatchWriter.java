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

import static com.google.common.base.Preconditions.checkArgument;

import org.apache.accumulo.core.client.BatchWriter;
import org.apache.accumulo.core.client.BatchWriterConfig;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.MutationsRejectedException;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.data.ColumnUpdate;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.security.ColumnVisibility;

import edu.mit.ll.pace.internal.MutableEntry;

/**
 * Writes encrypted entries to Accumulo.
 */
public final class EncryptedBatchWriter implements BatchWriter {

  /**
   * A {@link BatchWriter} to use to write the data to Accumulo.
   */
  private final BatchWriter writer;

  /**
   * The {@link EntryEncryptor} that will handle encryption for this instance.
   */
  private final EntryEncryptor encryptor;

  /**
   * Tracks whether entries written by this encrypted batch writer can be updated (i.e., deleted or changed).
   */
  private final boolean supportsDelete;

  /**
   * Create an encrypted batch writer.
   *
   * @param connector
   *          The connector for the Accumulo instance.
   * @param tableName
   *          Name of the table to write to.
   * @param batchConfig
   *          Configuration for a {@link BatchWriter}.
   * @param cryptoConfig
   *          Configuration for the encryption.
   * @param keys
   *          Container with the keys to use for encryption.
   * @throws TableNotFoundException
   *           Thrown if the table name is not found in the Accumulo instance.
   */
  public EncryptedBatchWriter(Connector connector, String tableName, BatchWriterConfig batchConfig, EncryptionConfig cryptoConfig, EncryptionKeyContainer keys)
      throws TableNotFoundException {
    checkArgument(connector != null, "connector is null");
    checkArgument(tableName != null, "tableName is null");
    checkArgument(cryptoConfig != null, "config is null");
    checkArgument(keys != null, "keys is null");

    this.writer = connector.createBatchWriter(tableName, batchConfig);
    this.encryptor = new EntryEncryptor(cryptoConfig, keys);
    this.supportsDelete = this.encryptor.canBeDeleteServerSide();
  }

  /**
   * Encrypt the given mutation and then write it to Accumulo.
   *
   * @param mutation
   *          The mutation to encrypt.
   * @throws EncryptionException
   *           The reason for the failure can be retrieved by calling {@link EncryptionException#getCause()}.
   */
  @Override
  public void addMutation(Mutation mutation) throws MutationsRejectedException {
    for (ColumnUpdate update : mutation.getUpdates()) {
      MutableEntry entry = new MutableEntry(mutation.getRow(), update);

      if (update.isDeleted()) {
        if (!supportsDelete) {
          throw new IllegalArgumentException("cannot delete entries when there are fields encrypted using non-deterministic encryption");
        }

        // Many keys might need to be deleted, one for each combination of key versions.
        for (Key deleteKey : encryptor.getDeleteKeys(entry.toKey())) {
          MutableEntry encryptedKey = new MutableEntry(deleteKey);

          Mutation encryptedMutation = new Mutation(encryptedKey.row);
          if (update.hasTimestamp()) {
            encryptedMutation.putDelete(encryptedKey.colF, encryptedKey.colQ, new ColumnVisibility(encryptedKey.colVis), encryptedKey.timestamp);
          } else {
            encryptedMutation.putDelete(encryptedKey.colF, encryptedKey.colQ, new ColumnVisibility(encryptedKey.colVis));
          }
          writer.addMutation(encryptedMutation);
        }
      } else {
        MutableEntry encryptedEntry = new MutableEntry(encryptor.encrypt(new MutableEntry(mutation.getRow(), update).toEntry()));

        Mutation encryptedMutation = new Mutation(encryptedEntry.row);
        if (update.hasTimestamp()) {
          encryptedMutation.put(encryptedEntry.colF, encryptedEntry.colQ, new ColumnVisibility(encryptedEntry.colVis), encryptedEntry.timestamp,
              encryptedEntry.value);
        } else {
          encryptedMutation.put(encryptedEntry.colF, encryptedEntry.colQ, new ColumnVisibility(encryptedEntry.colVis), encryptedEntry.value);
        }
        writer.addMutation(encryptedMutation);
      }
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
    writer.flush();
  }

  @Override
  public void close() throws MutationsRejectedException {
    writer.close();
  }
}
