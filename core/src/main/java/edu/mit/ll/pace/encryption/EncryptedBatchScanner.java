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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;

import org.apache.accumulo.core.client.BatchScanner;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.IteratorSetting;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.client.sample.SamplerConfiguration;
import org.apache.accumulo.core.data.Column;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.util.TextUtil;
import org.apache.hadoop.io.Text;

import edu.mit.ll.pace.ItemProcessingIterator;
import edu.mit.ll.pace.encryption.EntryEncryptor.ColumnFilterResult;

/**
 * Reads encrypted entries from Accumulo. As is the case for all {@link BatchScanner} instances, data is not guaranteed to be sorted.
 * <p>
 * It should be noted that while server side scan iterators can be set from this scanner ({@link #addScanIterator(IteratorSetting)},
 * {@link #clearScanIterators()}, {@link #removeScanIterator(String)}, and {@link #updateScanIteratorOption(String, String, String)}), the data will not be
 * decrypted on the server side. As such these server side will only be able to operate on unencrypted data and ciphertext, not decrypted plaintext.
 */
public final class EncryptedBatchScanner implements BatchScanner {

  /**
   * The underlying {@link BatchScanner} used to retrieve data from Accumulo.
   */
  private final BatchScanner scanner;

  /**
   * The {@link EntryEncryptor} that will handle decryption for this instance.
   */
  private final EntryEncryptor encryptor;

  /**
   * The set of ranges that an entry must match to be returned.
   * <p>
   * These are handled client side, as it was not possible to push this filtering to the server.
   */
  private List<Range> clientSideRanges = new ArrayList<>();

  /**
   * The set of columns that an entry must match to be returned.
   * <p>
   * These are handled client side, as it was not possible to push this filtering to the server.
   */
  private SortedSet<Column> clientSideColumnFilters = new TreeSet<>();

  /**
   * Create an encrypted batch scanner.
   *
   * @param connector
   *          The connector for the Accumulo instance.
   * @param tableName
   *          Name of the table to write to.
   * @param authorizations
   *          The authorizations this user has for querying Accumulo.
   * @param numQueryThreads
   *          Maximimum number of query threads to use for this scanner.
   * @param cryptoConfig
   *          Configuration for the decryption.
   * @param keys
   *          Container with the keys to use for decryption.
   * @throws TableNotFoundException
   *           Thrown if the table name is not found in the Accumulo instance.
   */
  public EncryptedBatchScanner(Connector connector, String tableName, Authorizations authorizations, int numQueryThreads, EncryptionConfig cryptoConfig,
      EncryptionKeyContainer keys) throws TableNotFoundException {
    checkArgument(connector != null, "connection is null");
    checkArgument(tableName != null, "tableName is null");
    checkArgument(authorizations != null, "authorizations is null");
    checkArgument(cryptoConfig != null, "config is null");
    checkArgument(keys != null, "keys is null");

    this.scanner = connector.createBatchScanner(tableName, authorizations, numQueryThreads);
    this.encryptor = new EntryEncryptor(cryptoConfig, keys);
  }

  /**
   * {@inheritDoc}
   * <p>
   * Automatically creates a set of server and client side ranges that most efficiently filter for the given ranges.
   *
   * @throws EncryptionException
   *           The reason for the failure can be retrieved by calling {@link EncryptionException#getCause()}.
   */
  @Override
  public void setRanges(Collection<Range> collection) {
    checkArgument(collection != null && collection.size() > 0, "ranges must be non null and contain at least 1 range");

    List<Range> serverSideRanges = new ArrayList<>();
    clientSideRanges = new ArrayList<>();

    // Transform the ranges as needed to deal with different encryption configurations.
    for (Range range : collection) {
      if (encryptor.transformRange(range, serverSideRanges)) {
        clientSideRanges.add(range);
      }
    }

    scanner.setRanges(serverSideRanges);
  }

  /**
   * {@inheritDoc}
   * <p>
   * Handles encryption of the search values as needed, filtering for the given column family on the server or client side as appropriate.
   *
   * @throws EncryptionException
   *           The reason for the failure can be retrieved by calling {@link EncryptionException#getCause()}.
   */
  @Override
  public void fetchColumnFamily(Text col) {
    checkArgument(col != null, "col is null");

    ColumnFilterResult search = encryptor.getColumnFamilyFilter(col);
    for (Column filter : search.serverSideFilters) {
      scanner.fetchColumnFamily(new Text(filter.getColumnFamily()));
    }
    if (search.needsClientSideFiltering) {
      clientSideColumnFilters.add(new Column(TextUtil.getBytes(col), null, null));
    }
  }

  /**
   * {@inheritDoc}
   * <p>
   * Handles encryption of the search values as needed, filtering for the given column on the server or client side as appropriate.
   *
   * @throws EncryptionException
   *           The reason for the failure can be retrieved by calling {@link EncryptionException#getCause()}.
   */
  @Override
  public void fetchColumn(Text colFam, Text colQual) {
    checkArgument(colFam != null, "colFam is null");
    checkArgument(colQual != null, "colQual is null");

    ColumnFilterResult search = encryptor.getColumnFilter(colFam, colQual);
    for (Column column : search.serverSideFilters) {
      if (column.getColumnQualifier() == null) {
        scanner.fetchColumnFamily(new Text(column.getColumnFamily()));
      } else {
        scanner.fetchColumn(new Text(column.getColumnFamily()), new Text(column.getColumnQualifier()));
      }
    }
    if (search.needsClientSideFiltering) {
      clientSideColumnFilters.add(new Column(TextUtil.getBytes(colFam), TextUtil.getBytes(colQual), null));
    }
  }

  /**
   * {@inheritDoc}
   *
   * @throws EncryptionException
   *           The reason for the failure can be retrieved by calling {@link EncryptionException#getCause()}.
   */
  @Override
  public void fetchColumn(IteratorSetting.Column column) {
    checkArgument(column != null, "Column is null");
    fetchColumn(column.getColumnFamily(), column.getColumnQualifier());
  }

  @Override
  public void clearColumns() {
    scanner.clearColumns();
    clientSideColumnFilters.clear();
  }

  /**
   * {@inheritDoc}
   * <p>
   * Returns a {@link edu.mit.ll.pace.ItemProcessingIterator}. This can be used to get the unprocessed items, allowing them to be deleted by a regular accumulo
   * writer.
   */
  @Override
  public ItemProcessingIterator<Entry<Key,Value>> iterator() {
    return new EncryptedScannerIterator(scanner.iterator(), encryptor, clientSideRanges, clientSideColumnFilters);
  }

  /* What remains are simply wrappers around BatchScanner. */

  @Override
  public void clearScanIterators() {
    scanner.clearScanIterators();
  }

  @Override
  public void close() {
    scanner.close();
  }

  @Override
  public Authorizations getAuthorizations() {
    return scanner.getAuthorizations();
  }

  @Override
  public void setSamplerConfiguration(SamplerConfiguration samplerConfiguration) {
    scanner.setSamplerConfiguration(samplerConfiguration);
  }

  @Override
  public SamplerConfiguration getSamplerConfiguration() {
    return scanner.getSamplerConfiguration();
  }

  @Override
  public void clearSamplerConfiguration() {
    scanner.clearSamplerConfiguration();
  }

  @Override
  public void setBatchTimeout(long l, TimeUnit timeUnit) {
    scanner.setBatchTimeout(l, timeUnit);
  }

  @Override
  public long getBatchTimeout(TimeUnit timeUnit) {
    return scanner.getBatchTimeout(timeUnit);
  }

  @Override
  public void setClassLoaderContext(String s) {
    scanner.setClassLoaderContext(s);
  }

  @Override
  public void clearClassLoaderContext() {
    scanner.clearClassLoaderContext();
  }

  @Override
  public String getClassLoaderContext() {
    return scanner.getClassLoaderContext();
  }

  @Override
  public void addScanIterator(IteratorSetting iteratorSetting) {
    scanner.addScanIterator(iteratorSetting);
  }

  @Override
  public void removeScanIterator(String s) {
    scanner.removeScanIterator(s);
  }

  @Override
  public void updateScanIteratorOption(String s, String s1, String s2) {
    scanner.updateScanIteratorOption(s, s1, s2);
  }

  @Override
  public void setTimeout(long l, TimeUnit timeUnit) {
    scanner.setTimeout(l, timeUnit);
  }

  @Override
  public long getTimeout(TimeUnit timeUnit) {
    return scanner.getTimeout(timeUnit);
  }
}
