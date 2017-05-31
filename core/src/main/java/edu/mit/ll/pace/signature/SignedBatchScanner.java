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

import java.util.Collection;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import org.apache.accumulo.core.client.BatchScanner;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.IteratorSetting;
import org.apache.accumulo.core.client.IteratorSetting.Column;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.client.sample.SamplerConfiguration;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.hadoop.io.Text;

import edu.mit.ll.pace.ItemProcessingIterator;

/**
 * Scanner that checks signatures on entries.
 */
public final class SignedBatchScanner implements BatchScanner {

  /**
   * The verifier to use.
   */
  private final EntrySigner verifier;

  /**
   * The underlying scanner used to retrieve data from Accumulo.
   */
  private final BatchScanner valueScanner;

  /**
   * The scanner to use to retrieve signatures.
   */
  private final BatchScanner signatureScanner;

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
   * @param signatureConfig
   *          Configuration for the decryption.
   * @param keys
   *          Container with the keys to use for decryption.
   */
  public SignedBatchScanner(Connector connector, String tableName, Authorizations authorizations, int numQueryThreads, SignatureConfig signatureConfig,
      SignatureKeyContainer keys) throws TableNotFoundException {
    checkArgument(connector != null, "connection is null");
    checkArgument(tableName != null, "tableName is null");
    checkArgument(authorizations != null, "authorizations is null");
    checkArgument(signatureConfig != null, "config is null");
    checkArgument(keys != null, "keys is null");

    this.valueScanner = connector.createBatchScanner(tableName, authorizations, numQueryThreads);
    this.verifier = new EntrySigner(signatureConfig, keys);

    if (signatureConfig.destination == SignatureConfig.Destination.SEPARATE_TABLE) {
      this.signatureScanner = connector.createBatchScanner(signatureConfig.destinationTable, authorizations, numQueryThreads);
    } else {
      this.signatureScanner = null;
    }
  }

  /**
   * {@inheritDoc}
   * <p>
   * Returns a {@link edu.mit.ll.pace.ItemProcessingIterator}. This can be used to get the unprocessed items, allowing them to be deleted by a regular accumulo
   * writer.
   */
  @Override
  public ItemProcessingIterator<Entry<Key,Value>> iterator() {
    if (signatureScanner != null) {
      return new SignedExternalScannerIterator(valueScanner.iterator(), signatureScanner.iterator(), verifier, false);
    } else {
      return new SignedInlineScannerIterator(valueScanner.iterator(), verifier);
    }
  }

  /**
   * {@inheritDoc}
   * <p>
   * This iterator is applied to both the table and the signature table. Changing the value will also affect the signature.
   */
  @Override
  public void addScanIterator(IteratorSetting cfg) {
    valueScanner.addScanIterator(cfg);
    if (signatureScanner != null) {
      signatureScanner.addScanIterator(cfg);
    }
  }

  @Override
  public void clearColumns() {
    valueScanner.clearColumns();
    if (signatureScanner != null) {
      signatureScanner.clearColumns();
    }
  }

  @Override
  public void clearScanIterators() {
    valueScanner.clearScanIterators();
    if (signatureScanner != null) {
      signatureScanner.clearScanIterators();
    }
  }

  @Override
  public void setRanges(Collection<Range> collection) {
    valueScanner.setRanges(collection);
    if (signatureScanner != null) {
      signatureScanner.setRanges(collection);
    }
  }

  @Override
  public void close() {
    valueScanner.close();
    if (signatureScanner != null) {
      signatureScanner.close();
    }
  }

  @Override
  public void fetchColumn(Column column) {
    valueScanner.fetchColumn(column);
    if (signatureScanner != null) {
      signatureScanner.fetchColumn(column);
    }
  }

  @Override
  public void fetchColumn(Text colFam, Text colQual) {
    valueScanner.fetchColumn(colFam, colQual);
    if (signatureScanner != null) {
      signatureScanner.fetchColumn(colFam, colQual);
    }
  }

  @Override
  public void fetchColumnFamily(Text col) {
    valueScanner.fetchColumnFamily(col);
    if (signatureScanner != null) {
      signatureScanner.fetchColumnFamily(col);
    }
  }

  @Override
  public Authorizations getAuthorizations() {
    return valueScanner.getAuthorizations();
  }

  @Override
  public void setSamplerConfiguration(SamplerConfiguration samplerConfiguration) {
    valueScanner.setSamplerConfiguration(samplerConfiguration);
    if (signatureScanner != null) {
      signatureScanner.setSamplerConfiguration(samplerConfiguration);
    }
  }

  @Override
  public SamplerConfiguration getSamplerConfiguration() {
    return valueScanner.getSamplerConfiguration();
  }

  @Override
  public void clearSamplerConfiguration() {
    valueScanner.clearSamplerConfiguration();
    if (signatureScanner != null) {
      signatureScanner.clearSamplerConfiguration();
    }
  }

  @Override
  public void setBatchTimeout(long l, TimeUnit timeUnit) {
    valueScanner.setBatchTimeout(l, timeUnit);
    if (signatureScanner != null) {
      signatureScanner.setBatchTimeout(l, timeUnit);
    }
  }

  @Override
  public long getBatchTimeout(TimeUnit timeUnit) {
    return valueScanner.getBatchTimeout(timeUnit);
  }

  @Override
  public void setClassLoaderContext(String s) {
    valueScanner.setClassLoaderContext(s);
    if (signatureScanner != null) {
      signatureScanner.setClassLoaderContext(s);
    }
  }

  @Override
  public void clearClassLoaderContext() {
    valueScanner.clearClassLoaderContext();
    if (signatureScanner != null) {
      signatureScanner.clearClassLoaderContext();
    }
  }

  @Override
  public String getClassLoaderContext() {
    return valueScanner.getClassLoaderContext();
  }

  @Override
  public long getTimeout(TimeUnit timeUnit) {
    return valueScanner.getTimeout(timeUnit);
  }

  @Override
  public void removeScanIterator(String iteratorName) {
    valueScanner.removeScanIterator(iteratorName);
    if (signatureScanner != null) {
      signatureScanner.removeScanIterator(iteratorName);
    }
  }

  @Override
  public void updateScanIteratorOption(String iteratorName, String key, String value) {
    valueScanner.updateScanIteratorOption(iteratorName, key, value);
    if (signatureScanner != null) {
      signatureScanner.updateScanIteratorOption(iteratorName, key, value);
    }
  }

  @Override
  public void setTimeout(long timeout, TimeUnit timeUnit) {
    valueScanner.setTimeout(timeout, timeUnit);
    if (signatureScanner != null) {
      signatureScanner.setTimeout(timeout, timeUnit);
    }
  }

}
