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
import static edu.mit.ll.pace.internal.Utils.EMPTY;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.accumulo.core.data.Column;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.PartialKey;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.accumulo.core.util.TextUtil;
import org.apache.hadoop.io.Text;

import com.google.common.collect.ImmutableSet;

import edu.mit.ll.pace.EntryField;
import edu.mit.ll.pace.internal.MutableEntry;

/**
 * Encrypts an Accumulo {@literal Entry<Key,Value>} based on the supplied configuration.
 */
public final class EntryEncryptor {

  /**
   * Result of encrypted filter operation.
   */
  public static final class ColumnFilterResult {

    /**
     * Server side filters.
     */
    public final Collection<Column> serverSideFilters;

    /**
     * Whether filtering also needs to happen client side.
     */
    public final boolean needsClientSideFiltering;

    /**
     * Constructor.
     *
     * @param serverSideFilters
     *          Server side filters.
     * @param needsClientSideFiltering
     *          Whether filtering also needs to happen client side.
     */
    private ColumnFilterResult(Collection<Column> serverSideFilters, boolean needsClientSideFiltering) {
      this.serverSideFilters = serverSideFilters;
      this.needsClientSideFiltering = needsClientSideFiltering;
    }
  }

  /**
   * A list of the {@link FieldEncryptor} objects that make up this entry encryptor.
   */
  private final List<FieldEncryptor> encryptors;

  /**
   * A map of destination fields to their respective {@link FieldEncryptor}.
   */
  private final Map<EntryField,FieldEncryptor> destinationMap;

  /**
   * A set of the fields used as sources by this encryptor.
   */
  private final Set<EntryField> sources;

  /**
   * Create an entry encryptor.
   *
   * @param config
   *          Configuration for the encryption.
   * @param keys
   *          Container with the keys to use for encryption.
   */
  public EntryEncryptor(EncryptionConfig config, EncryptionKeyContainer keys) {
    checkArgument(config != null, "config is null");
    checkArgument(keys != null, "keys is null");

    // Create the encryptors and their reverse-lookup.
    encryptors = new ArrayList<>(config.fieldEncryptorConfigs.size());
    destinationMap = new HashMap<>(config.fieldEncryptorConfigs.size());
    sources = new HashSet<>();

    for (FieldEncryptorConfig fieldEncryptorConfig : config.fieldEncryptorConfigs) {
      FieldEncryptor fieldEncryptor = new FieldEncryptor(fieldEncryptorConfig, keys);
      encryptors.add(fieldEncryptor);
      destinationMap.put(fieldEncryptorConfig.destination, fieldEncryptor);
      sources.addAll(fieldEncryptorConfig.sources);
    }
  }

  /**
   * Encrypt the given entry.
   *
   * @param entry
   *          Entry to encrypt.
   * @return Encrypted entry.
   */
  public Entry<Key,Value> encrypt(Entry<Key,Value> entry) {
    checkArgument(entry != null, "entry is null");

    MutableEntry wrapped = new MutableEntry(entry);
    MutableEntry result = new MutableEntry(entry);
    ColumnVisibility visibility = entry.getKey().getColumnVisibilityParsed();

    // Remove source fields that are encrypted but not replaced with encrypted data.
    // Ignore column visibility, timestamp, and delete as these are needed for correct parsing by Accumulo.
    for (EntryField source : sources) {
      switch (source) {
        case ROW:
        case COLUMN_FAMILY:
        case COLUMN_QUALIFIER:
        case VALUE:
          result.setBytes(source, EMPTY);
          break;
      }
    }

    // Encrypt the various fields.
    try {
      for (FieldEncryptor fieldEncryptor : encryptors) {
        fieldEncryptor.encrypt(wrapped, result, visibility);
      }
    } catch (IOException e) { // IO exceptions won't be thrown in practice as we are operating on in-memory streams.
      throw new EncryptionException(e);
    }

    return result.toEntry();
  }

  /**
   * Decrypt the given entry.
   *
   * @param entry
   *          entry to decrypt.
   * @return Decrypted entry.
   */
  public Entry<Key,Value> decrypt(Entry<Key,Value> entry) {
    checkArgument(entry != null, "entry is null");

    MutableEntry wrapped = new MutableEntry(entry);
    MutableEntry result = new MutableEntry(entry);
    ColumnVisibility visibility = entry.getKey().getColumnVisibilityParsed();

    // Decrypt the various fields.
    try {
      for (FieldEncryptor fieldEncryptor : encryptors) {
        fieldEncryptor.decrypt(wrapped, result, visibility);
      }
    } catch (IOException e) { // IO exceptions won't be thrown in practice as we are operating on in-memory streams.
      throw new EncryptionException(e);
    }

    return result.toEntry();
  }

  /**
   * Checks whether this entry encryptor results in an encrypted key that is searchable server-side.
   *
   * @return Whether entried can be updated.
   */
  public boolean canBeDeleteServerSide() {
    for (EntryField field : FieldEncryptorConfig.KEY_DESTINATION_FIELDS) {
      if (destinationMap.containsKey(field) && !destinationMap.get(field).canBeFilteredServerSide(FieldEncryptorConfig.KEY_SOURCE_FIELDS)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Given a key for deletion, generate the appropriate server side keys to delete.
   *
   * @param key
   *          Key to delete.
   * @return Set of encrypted keys to delete.
   */
  public Collection<Key> getDeleteKeys(Key key) {
    checkArgument(canBeDeleteServerSide(), "canBeDeleteServerSide is false");
    checkArgument(key != null, "key is null");
    MutableEntry searchKey = new MutableEntry(key);

    // Pair up the correct answers.
    Collection<byte[]> rowValues = getDeleteValues(searchKey, EntryField.ROW);
    Collection<byte[]> colFValues = getDeleteValues(searchKey, EntryField.COLUMN_FAMILY);
    Collection<byte[]> colQValues = getDeleteValues(searchKey, EntryField.COLUMN_QUALIFIER);

    return rowValues
        .stream()
        .flatMap(
            r -> colFValues.stream().flatMap(
                cf -> colQValues.stream().map(cq -> new Key(r, cf, cq, key.getColumnVisibilityData().getBackingArray(), key.getTimestamp(), true, true))))
        .collect(Collectors.toList());
  }

  /**
   * Get the delete values for the given field.
   *
   * @param key
   *          Key to pull values from.
   * @param field
   *          Field to get delete values for.
   * @return Values that needed to be deleted server side to delete the given key.
   */
  private Collection<byte[]> getDeleteValues(MutableEntry key, EntryField field) {
    if (!destinationMap.containsKey(field)) {
      if (!sources.contains(field)) {
        return Collections.singletonList(key.getBytes(field));
      } else {
        return Collections.singletonList(EMPTY);
      }
    } else {
      return destinationMap.get(field).getServerSideFilterValues(key, false);
    }
  }

  /**
   * Get the filter for the given value.
   *
   * @param col
   *          Column family to filter.
   * @return Results with columns to filter server ide and whether client side filtering is needed.
   */
  public ColumnFilterResult getColumnFamilyFilter(Text col) {
    checkArgument(col != null, "col is null");

    MutableEntry key = new MutableEntry();
    key.colF = TextUtil.getBytes(col);

    return getColumnFamilyFilter(key, ImmutableSet.of(EntryField.COLUMN_FAMILY));
  }

  /**
   * Get the filter for the given value.
   *
   * @param key
   *          Data to use to generate the possibly encrypted column family.
   * @param fields
   *          Set of fields available for encryption.
   * @return Results with columns to filter server ide and whether client side filtering is needed.
   */
  private ColumnFilterResult getColumnFamilyFilter(MutableEntry key, Set<EntryField> fields) {
    if (!destinationMap.containsKey(EntryField.COLUMN_FAMILY)) {
      if (!sources.contains(EntryField.COLUMN_FAMILY)) {
        return new ColumnFilterResult(Collections.singletonList(new Column(key.colF, null, null)), false);
      } else {
        return new ColumnFilterResult(Collections.singletonList(new Column(EMPTY, null, null)), true);
      }
    } else {
      FieldEncryptor encryptor = destinationMap.get(EntryField.COLUMN_FAMILY);
      if (encryptor.canBeFilteredServerSide(fields)) {
        return new ColumnFilterResult(encryptor.getServerSideFilterValues(key).stream().map(f -> new Column(f, null, null)).collect(Collectors.toList()), false);
      } else {
        return new ColumnFilterResult(new ArrayList<>(0), true);
      }
    }
  }

  /**
   * Get the filter for the given value.
   *
   * @param colFam
   *          Column family to filter.
   * @param colQual
   *          Column qualifier to filter.
   * @return A pair, with the left side being the set of columns to filter on the server side, and the right whether it is necessary to also filter on the
   *         client side.
   */
  public ColumnFilterResult getColumnFilter(Text colFam, Text colQual) {
    checkArgument(colFam != null, "colFam is null");
    checkArgument(colQual != null, "colQual is null");

    Set<EntryField> fields = ImmutableSet.of(EntryField.COLUMN_FAMILY, EntryField.COLUMN_QUALIFIER);
    MutableEntry key = new MutableEntry();
    key.colF = TextUtil.getBytes(colFam);
    key.colQ = TextUtil.getBytes(colQual);

    ColumnFilterResult familySearch = getColumnFamilyFilter(key, fields);

    if (!destinationMap.containsKey(EntryField.COLUMN_QUALIFIER)) {
      if (!sources.contains(EntryField.COLUMN_QUALIFIER)) {
        return new ColumnFilterResult(familySearch.serverSideFilters.stream().map(f -> new Column(f.getColumnFamily(), key.colQ, null))
            .collect(Collectors.toList()), familySearch.needsClientSideFiltering);
      } else {
        boolean serverSideOnly = destinationMap.containsKey(EntryField.COLUMN_FAMILY)
            && destinationMap.get(EntryField.COLUMN_FAMILY).canSearchFor(ImmutableSet.of(EntryField.COLUMN_FAMILY, EntryField.COLUMN_QUALIFIER));
        return new ColumnFilterResult(familySearch.serverSideFilters.stream().map(f -> new Column(f.getColumnFamily(), EMPTY, null))
            .collect(Collectors.toList()), !serverSideOnly);
      }
    } else {
      FieldEncryptor encryptor = destinationMap.get(EntryField.COLUMN_QUALIFIER);
      if (encryptor.canBeFilteredServerSide(fields)) {
        boolean serverSideOnly = !familySearch.needsClientSideFiltering
            || (!destinationMap.containsKey(EntryField.COLUMN_FAMILY) && sources.contains(EntryField.COLUMN_FAMILY) && encryptor.canSearchFor(ImmutableSet.of(
                EntryField.COLUMN_FAMILY, EntryField.COLUMN_QUALIFIER)));

        return new ColumnFilterResult(familySearch.serverSideFilters.stream()
            .flatMap(f -> encryptor.getServerSideFilterValues(key).stream().map(v -> new Column(f.getColumnFamily(), v, null))).collect(Collectors.toList()),
            !serverSideOnly);
      } else {
        boolean serverSideOnly = destinationMap.containsKey(EntryField.COLUMN_FAMILY)
            && destinationMap.get(EntryField.COLUMN_FAMILY).canSearchFor(ImmutableSet.of(EntryField.COLUMN_FAMILY, EntryField.COLUMN_QUALIFIER));

        return new ColumnFilterResult(familySearch.serverSideFilters.stream().map(f -> new Column(f.getColumnFamily(), null, null))
            .collect(Collectors.toList()), !serverSideOnly);
      }
    }
  }

  /**
   * Converts the range to a set of encrypted server side range queries.
   *
   * @param range
   *          Range to convert.
   * @param serverSideRanges
   *          List of server side filters.
   * @return Whether this range still needs to be searched for client side.
   */
  public boolean transformRange(Range range, Collection<Range> serverSideRanges) {
    checkArgument(range != null, "range is null");
    checkArgument(serverSideRanges != null, "serverSideRanges is null");

    // If only the value is encrypted, then the key can be searched server side.
    if (destinationMap.size() == 1 && destinationMap.containsKey(EntryField.VALUE)) {
      serverSideRanges.add(range);
      return false;
    }

    // If the range includes everything, it can be sent server side.
    if (range.isInfiniteStartKey() && range.isInfiniteStopKey()) {
      serverSideRanges.add(range);
      return false;
    }

    MutableEntry startKey = range.isInfiniteStartKey() ? new MutableEntry() : new MutableEntry(range.getStartKey());
    MutableEntry endKey = range.isInfiniteStopKey() ? new MutableEntry() : new MutableEntry(range.getEndKey());

    // Determine which set of fields are equal in both the start and end keys; these keys can be used as source values for deterministically encrypted fields.
    Set<EntryField> equalFields = new HashSet<>();
    EntryField followingKey = null;

    if (!range.isInfiniteStartKey() && !range.isInfiniteStopKey()) {
      for (EntryField field : FieldEncryptorConfig.KEY_SOURCE_FIELDS) {
        byte[] start = startKey.getBytes(field);
        byte[] end = endKey.getBytes(field);

        if (Arrays.equals(start, end)) {
          equalFields.add(field);
        } else if (!range.isEndKeyInclusive() && range.getStartKey().followingKey(toPartialKey(field)).equals(range.getEndKey())) {
          // TODO: This may actually be buggy. I'm not sure if it is possible to have this true twice, and if so how I should handle that.
          followingKey = field;
          break;
        }
      }

      if (followingKey != null) {
        equalFields.add(followingKey);
      }
    }

    // Generate server side filters.
    List<MutableEntry> startKeys = new ArrayList<>(), endKeys = new ArrayList<>();
    startKeys.add(new MutableEntry());
    endKeys.add(new MutableEntry());

    PartialKey prefix = null;
    boolean prefixHasVariance = range.isInfiniteStartKey() || range.isInfiniteStopKey(); // Infinite keys always give variance.

    for (EntryField field : EntryField.values()) {
      if (field == EntryField.VALUE) {
        continue;
      }

      if (!destinationMap.containsKey(field)) {
        if (!sources.contains(field)) {
          // Only plaintext fields that are not wiped (i.e., used as a source) will contribute to the filter.
          if (range.isInfiniteStartKey()) {
            for (MutableEntry entry : endKeys) {
              entry.setBytes(field, endKey.getBytes(field));
            }
          } else if (range.isInfiniteStopKey()) {
            for (MutableEntry entry : startKeys) {
              entry.setBytes(field, startKey.getBytes(field));
            }
          } else {
            if (!equalFields.contains(field)) {
              prefixHasVariance = true;
            }

            Iterator<MutableEntry> startKeyIterator = startKeys.iterator();
            Iterator<MutableEntry> endKeyIterator = endKeys.iterator();
            while (startKeyIterator.hasNext()) {
              switch (field) {
                case TIMESTAMP:
                  startKeyIterator.next().timestamp = startKey.timestamp;
                  endKeyIterator.next().timestamp = endKey.timestamp;
                  break;

                case DELETE:
                  startKeyIterator.next().delete = startKey.delete;
                  endKeyIterator.next().delete = endKey.delete;
                  break;

                default:
                  startKeyIterator.next().setBytes(field, startKey.getBytes(field));
                  endKeyIterator.next().setBytes(field, endKey.getBytes(field));
              }
            }
          }
        }
      } else { // Encrypted field.
        if (prefixHasVariance || !destinationMap.get(field).canBeFilteredServerSide(equalFields)) {
          appendServerSideRanges(serverSideRanges, range, startKeys, endKeys, prefix);
          return true;
        } else {
          startKeys = getServerSideFilterKeys(startKeys, field, startKey, false);
          endKeys = getServerSideFilterKeys(endKeys, field, startKey, field == followingKey);
        }
      }

      prefix = toPartialKey(field);
    }

    // Doesn't need a client side filter, as everything can be done server-side.
    Iterator<MutableEntry> startKeyIterator = startKeys.iterator();
    Iterator<MutableEntry> endKeyIterator = endKeys.iterator();
    while (startKeyIterator.hasNext()) {
      serverSideRanges.add(new Range(startKeyIterator.next().toKey(), range.isStartKeyInclusive(), endKeyIterator.next().toKey(), range.isEndKeyInclusive()));
    }
    return false;
  }

  /**
   * Append the server side filter keys for the given field to the existing filters.
   *
   * @param existingFilters
   *          Filters that are being added to.
   * @param field
   *          Field to add encrypted search for.
   * @param key
   *          Data to use for generated encrypted search.
   * @param followingKey
   *          Should the returned value be generated as in {@link Key#followingArray(byte[])}.
   * @return New list of server side filters.
   */
  private List<MutableEntry> getServerSideFilterKeys(List<MutableEntry> existingFilters, EntryField field, MutableEntry key, boolean followingKey) {
    List<MutableEntry> entries = new ArrayList<>();
    List<byte[]> values = destinationMap.get(field).getServerSideFilterValues(key, followingKey);

    for (MutableEntry entry : existingFilters) {
      for (byte[] value : values) {
        MutableEntry newItem = entry.cloneEntry();
        newItem.setBytes(field, value);
        entries.add(newItem);
      }
    }

    return entries;
  }

  /**
   * @param serverSideRanges
   *          List of server side filters.
   * @param originalRange
   *          Range to convert.
   * @param startKeys
   *          Set of start key filters.
   * @param endKeys
   *          Set of end key filters.
   * @param prefix
   *          What portion of the key are we filtering?
   */
  private void appendServerSideRanges(Collection<Range> serverSideRanges, Range originalRange, List<MutableEntry> startKeys, List<MutableEntry> endKeys,
      PartialKey prefix) {
    if (prefix == null) {
      serverSideRanges.add(new Range());
      return;
    }

    if (originalRange.isInfiniteStartKey()) {
      for (MutableEntry endKey : endKeys) {
        serverSideRanges.add(new Range(null, true, endKey.toKey().followingKey(prefix), false));
      }
    } else if (originalRange.isInfiniteStopKey()) {
      for (MutableEntry startKey : startKeys) {
        serverSideRanges.add(new Range(startKey.toKey(), true, null, true));
      }
    } else {
      Iterator<MutableEntry> startKeyIterator = startKeys.iterator();
      Iterator<MutableEntry> endKeyIterator = endKeys.iterator();
      while (startKeyIterator.hasNext()) {
        serverSideRanges.add(new Range(startKeyIterator.next().toKey(), true, endKeyIterator.next().toKey().followingKey(prefix), false));
      }
    }
  }

  /**
   * Converts the field to a partial key.
   *
   * @param field
   *          Field to transform.
   * @return The partial key that ends with this field.
   */
  private static PartialKey toPartialKey(EntryField field) {
    switch (field) {
      case ROW:
        return PartialKey.ROW;
      case COLUMN_FAMILY:
        return PartialKey.ROW_COLFAM;
      case COLUMN_QUALIFIER:
        return PartialKey.ROW_COLFAM_COLQUAL;
      case COLUMN_VISIBILITY:
        return PartialKey.ROW_COLFAM_COLQUAL_COLVIS;
      case TIMESTAMP:
        return PartialKey.ROW_COLFAM_COLQUAL_COLVIS_TIME;
      case DELETE:
        return PartialKey.ROW_COLFAM_COLQUAL_COLVIS_TIME_DEL;
      default:
        throw new IllegalArgumentException();
    }
  }

}
