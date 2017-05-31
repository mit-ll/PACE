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
import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;
import static edu.mit.ll.pace.internal.Utils.xor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.accumulo.core.security.ColumnVisibility.Node;
import org.apache.accumulo.core.security.ColumnVisibility.NodeType;
import org.apache.hadoop.io.WritableUtils;

import edu.mit.ll.pace.EntryField;
import edu.mit.ll.pace.IllegalKeyRequestException;
import edu.mit.ll.pace.encryption.EncryptionKeyContainer.KeyWithVersion;
import edu.mit.ll.pace.internal.MutableEntry;

/**
 * Encrypts an Accumulo field based on the supplied configuration.
 */
final class FieldEncryptor {

  /**
   * Secure random number generator.
   */
  private static final SecureRandom random = new SecureRandom();

  /**
   * Configuration for this encryptor.
   */
  private final FieldEncryptorConfig config;

  /**
   * The keys available to this encryptor.
   */
  private final EncryptionKeyContainer keys;

  /**
   * The value encryptor to use to encrypt data.
   */
  private final ValueEncryptorBase encryptor;

  /**
   * Creates a field encryptor.
   *
   * @param config
   *          Configuration for the encryption.
   * @param keys
   *          Container with the keys to use for encryption.
   */
  FieldEncryptor(FieldEncryptorConfig config, EncryptionKeyContainer keys) {
    checkArgument(config != null, "config is null");
    checkArgument(keys != null, "keys is null");

    this.config = config;
    this.keys = keys;

    this.encryptor = config.valueEncryptor.getInstance(config.provider);
  }

  /**
   * Encrypt the given entry.
   *
   * @param entry
   *          {@link MutableEntry} to encrypt.
   * @param result
   *          {@link MutableEntry} to write result to.
   * @param columnVisibility
   *          The parsed column visibility.
   * @throws IOException
   *           Not actually thrown.
   */
  void encrypt(MutableEntry entry, MutableEntry result, ColumnVisibility columnVisibility) throws IOException {
    // Put the data in a single byte array.
    byte[] data = concatData(entry);

    // Gets the key used to encrypt the data. Also write to the front of the ciphertext the metadata necessary to retrieve the key.
    ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
    DataOutput ciphertextOut = new DataOutputStream(ciphertextStream);

    // Encrypt the data, and write it to the result (first wrapping it if writing to the column visibility field).
    byte[] key = getKey(columnVisibility, ciphertextOut);
    ciphertextOut.write(encryptor.encrypt(key, data));
    byte[] ciphertext = ciphertextStream.toByteArray();
    result.setBytes(config.destination, ciphertext);
  }

  /**
   * Concat the data in preparation for it to be encrypted.
   *
   * @param entry
   *          Entry to pull data from.
   * @return Concatenated data.
   * @throws IOException
   *           Not actually thrown.
   */
  private byte[] concatData(MutableEntry entry) throws IOException {
    ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
    DataOutput dataOut = new DataOutputStream(dataStream);

    for (EntryField source : config.sources) {
      switch (source) {
        case ROW:
        case COLUMN_FAMILY:
        case COLUMN_QUALIFIER:
        case COLUMN_VISIBILITY:
        case VALUE:
          byte[] bytes = entry.getBytes(source);
          WritableUtils.writeVInt(dataOut, bytes.length);
          dataOut.write(bytes);
          break;

        default:
          throw new UnsupportedOperationException();
      }
    }
    return dataStream.toByteArray();
  }

  /**
   * Decrypt the given entry.
   *
   * @param entry
   *          {@link MutableEntry} to encrypt.
   * @param result
   *          {@link MutableEntry} to write result to.
   * @param columnVisibility
   *          The parsed column visibility.
   *
   * @throws IOException
   *           Not actually thrown.
   */
  void decrypt(MutableEntry entry, MutableEntry result, ColumnVisibility columnVisibility) throws IOException {
    ByteArrayInputStream ciphertextStream = new ByteArrayInputStream(entry.getBytes(config.destination));
    DataInput ciphertextIn = new DataInputStream(ciphertextStream);

    byte[] key = getKey(columnVisibility, ciphertextIn);
    byte[] ciphertext = new byte[ciphertextStream.available()];
    ciphertextIn.readFully(ciphertext);
    byte[] decryptedData = encryptor.decrypt(key, ciphertext);

    // Break apart the decrypted data.
    ByteArrayInputStream dataStream = new ByteArrayInputStream(decryptedData);
    DataInput dataIn = new DataInputStream(dataStream);

    for (EntryField source : config.sources) {
      switch (source) {
        case ROW:
        case COLUMN_FAMILY:
        case COLUMN_QUALIFIER:
        case COLUMN_VISIBILITY:
        case VALUE:
          int length = WritableUtils.readVInt(dataIn);
          byte[] bytes = new byte[length];
          dataIn.readFully(bytes);
          result.setBytes(source, bytes);
          break;

        // case TIMESTAMP:
        // result.timestamp = WritableUtils.readVLong(dataIn);
        // break;

        // case DELETE:
        // result.delete = dataIn.readBoolean();
        // break;

        default:
          throw new UnsupportedOperationException();
      }
    }
  }

  /**
   * Get a field encryption key for use in <strong>encrypting</strong> the field.
   * <p>
   * Any metadata needed to retrieve this key later should be written to the DataOuput object.
   *
   * @param visibility
   *          Visibility expression for the field.
   * @param out
   *          DataOutput object to write metadata to.
   * @return Field encryption key.
   * @throws IOException
   *           Not actually thrown.
   */
  private byte[] getKey(ColumnVisibility visibility, DataOutput out) throws IOException {
    if (config.encryptUsingVisibility) {
      byte[] key = new byte[config.keyLength];

      if (visibility.getParseTree().getType() != NodeType.EMPTY) {
        random.nextBytes(key);
        writeVisibilityShare(key, visibility.getParseTree(), visibility.getExpression(), out);
      }

      return key;
    } else {
      KeyWithVersion keyData = keys.getKey(config.keyId, config.keyLength);
      WritableUtils.writeVInt(out, keyData.version); // Write the version of the key being used as meta-data.
      return keyData.key;
    }
  }

  /**
   * Retrieve a field encryption key to use in <strong>decrypting</strong> the field.
   * <p>
   * Metadata can be read from the DataInput object. All meta-data that was written to the stream should be read out, regardless if it is used.
   *
   * @param visibility
   *          Visibility expression for the field.
   * @param in
   *          Stream from which metadata is read.
   * @return Field encryption key.
   * @throws IOException
   *           Not actually thrown.
   */
  private byte[] getKey(ColumnVisibility visibility, DataInput in) throws IOException {
    if (config.encryptUsingVisibility) {
      if (visibility.getParseTree().getType() != NodeType.EMPTY) {
        // Rebuild the key from the shares created based on the visibility expression.
        byte[] key = readVisibilityShare(visibility.getParseTree(), visibility.getExpression(), in, false);

        if (key == null) {
          throw new IllegalKeyRequestException();
        }
        return key;
      } else {
        return new byte[config.keyLength];
      }
    } else {
      int version = WritableUtils.readVInt(in);
      return keys.getKey(config.keyId, version, config.keyLength);
    }
  }

  /**
   * Encrypt the given share based on the current visibility node.
   * <p>
   * Metadata needed to later decrypt the share and the encrypted share are written to the DataOutput object.
   *
   * @param share
   *          Share of an encryption key to encrypt based on the visilbity expression.
   * @param node
   *          Visibility node to use in encrypting the share.
   * @param expression
   *          Visibility expression.
   * @param out
   *          Stream to which metadata is written.
   * @throws IOException
   *           Not actually thrown.
   */
  private void writeVisibilityShare(byte[] share, Node node, byte[] expression, DataOutput out) throws IOException {
    switch (node.getType()) {
      case TERM:
        // This is the only case we actually write to the stream. Encrypt the share with the attribute share.
        // The output format is "version || length || encrypted data"
        KeyWithVersion keyData = keys.getAttributeKey(new String(node.getTerm(expression).toArray(), VISIBILITY_CHARSET), config.keyId, config.keyLength);
        WritableUtils.writeVInt(out, keyData.version); // Key version is written to the metadata.

        byte[] encrypted;
        encrypted = encryptor.encrypt(keyData.key, share);
        WritableUtils.writeVInt(out, encrypted.length);
        out.write(encrypted);
        break;

      case AND:
        // Create random shares, with the final share being the original share xor'ed with each of the random shares.
        byte[] mask = new byte[share.length];
        for (int i = 0; i < node.getChildren().size(); i++) {
          if (i == (node.getChildren().size() - 1)) {
            writeVisibilityShare(xor(mask, share), node.getChildren().get(i), expression, out);
          } else {
            byte[] randomMask = new byte[share.length];
            random.nextBytes(randomMask);
            writeVisibilityShare(randomMask, node.getChildren().get(i), expression, out);
            xor(mask, randomMask);
          }
        }
        break;

      case OR:
        // Write the same share with each attribute share.
        for (Node child : node.getChildren()) {
          writeVisibilityShare(share, child, expression, out);
        }
        break;

      default:
        throw new UnsupportedOperationException();
    }
  }

  /**
   * Decrypt the given share based on the current visibility node.
   * <p>
   * This method must read all metadata that the corresponding call to {@link #writeVisibilityShare(byte[], Node, byte[], DataOutput)} wrote. This is necessary
   * regardless of whether the key retrieval is ongoing, successful, or failed.
   *
   * @param node
   *          Visibility node to use in decrypting the share.
   * @param expression
   *          Visibility expression.
   * @param in
   *          Stream from which metadata is read.
   * @param skipDecryption
   *          Tracks whether the call to this method is trying to regenerate the share.
   *          <p>
   *          This will be false if the share was already generated (i.e., from a different branch in an OR expression) or if there was an error in this branch
   *          (i.e., lacked the attribute key to decrypt a different share of an AND expression).
   * @return The decrypted share, or null if it could not be obtained.
   * @throws IOException
   *           Not actually thrown.
   */
  private byte[] readVisibilityShare(Node node, byte[] expression, DataInput in, boolean skipDecryption) throws IOException {
    byte[] share = null;

    switch (node.getType()) {
      case TERM:
        // This is the only case we actually read from the stream. Decrypt the share with the attribute share.
        // The input format is "version || length || encrypted data"
        int version = WritableUtils.readVInt(in);
        byte[] encrypted = new byte[WritableUtils.readVInt(in)];
        in.readFully(encrypted);

        if (!skipDecryption) {
          try {
            byte[] key = keys.getAttributeKey(new String(node.getTerm(expression).toArray(), VISIBILITY_CHARSET), config.keyId, version, config.keyLength);
            share = encryptor.decrypt(key, encrypted);
          } catch (IllegalKeyRequestException e) {
            // Swallow this error. The user does not have access to decrypt this sub-share, but it still may be possible for the user to decrypt another
            // sub-share that will give the same data. This error will be re-thrown if at the end of reading all shares the users does not have enough
            // data to reconstruct the original share.
          }
        }
        break;

      case AND:
        // Read random shares, with the final share being the original share xor'ed with each of the random shares.
        for (Node child : node.getChildren()) {
          byte[] mask = readVisibilityShare(child, expression, in, skipDecryption);

          // A single failure means this whole AND is a failure.
          if (!skipDecryption) {
            if (mask == null) {
              share = null;
              skipDecryption = true;
            } else {
              if (share == null) {
                share = mask;
              } else {
                xor(share, mask);
              }
            }
          }
        }
        break;

      case OR:
        // Read the share from multiple possible attribute shares. Only one share is needed.
        for (Node child : node.getChildren()) {
          byte[] tempKey = readVisibilityShare(child, expression, in, skipDecryption);
          if (!skipDecryption && tempKey != null) {
            share = tempKey;
            skipDecryption = true;
          }
        }
        break;

      default:
        throw new UnsupportedOperationException();
    }

    return share;
  }

  /**
   * Checks whether the field can be filtered server side.
   * <p>
   * A field can be filtered server side if two things hold:
   * <ol>
   * <li>It is encrypted deterministically.</li>
   * <li>All of this field encryptor's field sources are available for use.</li>
   * </ol>
   *
   * @param availableSources
   *          Fields available during encryption to pull data from.
   * @return Whether it is possible to generate a server side encryption for this item.
   */
  boolean canBeFilteredServerSide(Collection<EntryField> availableSources) {
    return config.valueEncryptor.isDeterministic() && availableSources.containsAll(config.sources);
  }

  /**
   * Checks the encrypted value created by this encryptor can be used to search for the given fields.
   * <p>
   * The fields can only be searched for if they are the same set as the sources for this field encryptor.
   *
   * @param fields
   *          Fields that need to be searched.
   * @return Whether this field's encrypted value can be used to search for the given fields.
   */
  boolean canSearchFor(Set<EntryField> fields) {
    return config.valueEncryptor.isDeterministic() && fields.equals(config.sources);
  }

  /**
   * Transform a value into a set of server side search terms. This method assumes that {@link #canBeFilteredServerSide(Collection)} was called, and that this
   * field is suitable for server side filtering.
   * <p>
   * This method will encrypt the data in the given key using ever version of that key available. For example, if key "ROW_KEY" has 3 versions, than this method
   * will encrypt the key with all 3 versions, resulting in 3 possible server side filter values for this encrypted field.
   *
   * @param key
   *          Data used to create the filter.
   * @return Keys containing the data for the server side filters.
   */
  List<byte[]> getServerSideFilterValues(MutableEntry key) {
    return getServerSideFilterValues(key, false);
  }

  /**
   * Transform a value into a set of server side search terms. This method assumes that {@link #canBeFilteredServerSide(Collection)} was called, and that this
   * field is suitable for server side filtering.
   * <p>
   * This method will encrypt the data in the given key using ever version of that key available. For example, if key "ROW_KEY" has 3 versions, than this method
   * will encrypt the key with all 3 versions, resulting in 3 possible server side filter values for this encrypted field.
   *
   * @param key
   *          Data used to create the filter.
   * @param followingKey
   *          Should the returned value be generated as in {@link Key#followingArray(byte[])}.
   * @return Keys containing the data for the server side filters.
   */
  List<byte[]> getServerSideFilterValues(MutableEntry key, boolean followingKey) {
    List<byte[]> filterValues = new ArrayList<>();

    for (KeyWithVersion keyData : keys.getKeys(config.keyId, config.keyLength)) {
      ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
      DataOutput ciphertextOut = new DataOutputStream(ciphertextStream);

      try {
        WritableUtils.writeVInt(ciphertextOut, keyData.version);
        ciphertextOut.write(encryptor.encrypt(keyData.key, concatData(key)));
        if (followingKey) {
          ciphertextOut.writeByte(0);
        }
      } catch (IOException e) { // IO exceptions won't be thrown in practice as we are operating on in-memory streams.
        throw new EncryptionException(e);
      }

      filterValues.add(ciphertextStream.toByteArray());
    }

    return filterValues;
  }

}
