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
import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.util.Map.Entry;

import org.apache.accumulo.core.data.ArrayByteSequence;
import org.apache.accumulo.core.data.ByteSequence;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.accumulo.core.security.VisibilityEvaluator;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.hadoop.io.WritableUtils;

import com.google.common.primitives.Longs;

import edu.mit.ll.pace.internal.MutableEntry;
import edu.mit.ll.pace.signature.SignatureConfig.Destination;
import edu.mit.ll.pace.signature.SignatureKeyContainer.PrivateKeyWithId;

/**
 * Signs an Accumulo {@literal Entry<Key,Value>} based on the supplied configuration.
 */
public final class EntrySigner {

  /**
   * Signature configuration.
   */
  private final SignatureConfig config;

  /**
   * Keys to use for signing and verifying.
   */
  private final SignatureKeyContainer keys;

  /**
   * Verifier for this instance.
   */
  private Signature signer;

  /**
   * The id of the signer.
   */
  private byte[] signerId;

  /**
   * Signer for this instance.
   */
  private Signature verifier;

  /**
   * Create an entry singer.
   *
   * @param config
   *          Configuration for the signing.
   * @param keys
   *          Container with the keys to use for signing.
   */
  public EntrySigner(SignatureConfig config, SignatureKeyContainer keys) {
    checkArgument(config != null, "config is null");
    checkArgument(keys != null, "keys is null");

    this.config = config;
    this.keys = keys;
  }

  /**
   * Sign the given entry.
   *
   * @param entry
   *          Entry to sign.
   * @return Signed update.
   * @throws SignatureException
   *           Thrown in signature creation fails.
   */
  public Entry<Key,Value> sign(Entry<Key,Value> entry, boolean hasTimestamp) {
    checkArgument(entry != null, "entry is null");
    checkArgument(!entry.getKey().isDeleted(), "cannot sign deleted entries");

    // Defer initialization of the signing algorithm until needed.
    if (signer == null) {
      signer = config.algorithm.getInstance(config.provider);

      try {
        PrivateKeyWithId keyData = keys.getSigningKey();
        signer.initSign(keyData.key);
        signerId = keyData.id;
      } catch (InvalidKeyException e) {
        throw new SignatureException(e);
      }
    }

    // If we are writing to the visibility field, we will need to replace the empty visibility with the default visibility.
    MutableEntry wrapped = new MutableEntry(entry);
    if (config.destination == Destination.COLUMN_VISIBILITY && wrapped.colVis.length == 0) {
      wrapped.colVis = config.defaultVisibility;
    }

    // Sign the entry.
    byte[] signature;
    try {
      signer.update(wrapped.row);
      signer.update(wrapped.colF);
      signer.update(wrapped.colQ);
      signer.update(wrapped.colVis);
      signer.update(hasTimestamp ? (byte) 0 : (byte) 1);
      if (hasTimestamp) {
        signer.update(Longs.toByteArray(wrapped.timestamp));
      }
      signer.update(wrapped.value);
      signature = signer.sign();
    } catch (java.security.SignatureException e) {
      throw new SignatureException(e);
    }

    // Create a stream with the signature data.
    try {
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      DataOutput out = new DataOutputStream(stream);

      WritableUtils.writeVInt(out, signerId.length);
      out.write(signerId);

      out.writeBoolean(hasTimestamp);

      WritableUtils.writeVInt(out, signature.length);
      out.write(signature);

      switch (config.destination) {
        case VALUE:
          out.write(wrapped.value);
          wrapped.value = stream.toByteArray();
          break;

        case COLUMN_VISIBILITY:
          wrapped.colVis = wrapVisibility(wrapped.colVis, stream.toByteArray());
          break;

        case SEPARATE_TABLE:
          wrapped.value = stream.toByteArray();
          break;

        default:
          throw new UnsupportedOperationException();
      }
    } catch (IOException e) { // IO exceptions won't be thrown in practice as we are operating on in-memory streams.
      throw new SignatureException(e);
    }

    return wrapped.toEntry();
  }

  /**
   * Verify the given entry.
   *
   * @param entry
   *          entry with signature to verify.
   * @return Verified entry with signature data removed.
   * @throws SignatureException
   *           Thrown if signature verification fails.
   */
  public Entry<Key,Value> verify(Entry<Key,Value> entry) {
    return verify(entry, null);
  }

  /**
   * Verify the given entry.
   *
   * @param entry
   *          entry to verify, potentially with the signature too.
   * @param signedEntry
   *          If the signature is stored in an entry in another table, then this entry is that signature entry, otherwise it is null.
   * @return Verified entry, with signature data removed as necessary.
   * @throws SignatureException
   *           Thrown if signature verification fails.
   */
  public Entry<Key,Value> verify(Entry<Key,Value> entry, Entry<Key,Value> signedEntry) {
    checkArgument(entry != null, "entry is null");
    checkArgument(!entry.getKey().isDeleted(), "cannot verify deleted entries");

    if (config.destination == SignatureConfig.Destination.SEPARATE_TABLE) {
      checkArgument(signedEntry != null, "signature is in a separate table, but signature entry is null");
    } else {
      checkArgument(signedEntry == null, "signature is not in a separate table, but separate signature entry given");
    }

    if (verifier == null) {
      verifier = config.algorithm.getInstance(config.provider);
    }

    MutableEntry wrapped = new MutableEntry(entry);
    ByteArrayInputStream stream;

    switch (config.destination) {
      case VALUE:
        stream = new ByteArrayInputStream(wrapped.value);
        break;

      case COLUMN_VISIBILITY:
        Pair<byte[],byte[]> signatureData = unwrapVisibility(new ColumnVisibility(wrapped.colVis));
        wrapped.colVis = signatureData.getLeft();
        stream = new ByteArrayInputStream(signatureData.getRight());
        break;

      case SEPARATE_TABLE:
        stream = new ByteArrayInputStream(signedEntry.getValue().get());
        break;

      default:
        throw new UnsupportedOperationException();
    }

    // Read the signature from the stream.
    byte[] signature;
    boolean hasTimestamp;
    try {
      DataInput in = new DataInputStream(stream);
      byte[] signerId = new byte[WritableUtils.readVInt(in)];
      in.readFully(signerId);
      verifier.initVerify(keys.getVerifyingKey(signerId));

      hasTimestamp = in.readBoolean();

      signature = new byte[WritableUtils.readVInt(in)];
      in.readFully(signature);

      // If we wrote to the value, extract the original value.
      if (config.destination == Destination.VALUE) {
        wrapped.value = new byte[stream.available()];
        in.readFully(wrapped.value);
      }
    } catch (IOException | InvalidKeyException e) { // IO exceptions won't be thrown in practice as we are operating on in-memory streams.
      throw new SignatureException(e);
    }

    // Generate and verify the signature.
    try {
      verifier.update(wrapped.row);
      verifier.update(wrapped.colF);
      verifier.update(wrapped.colQ);
      verifier.update(wrapped.colVis);
      verifier.update(hasTimestamp ? (byte) 0 : (byte) 1);
      if (hasTimestamp) {
        verifier.update(Longs.toByteArray(wrapped.timestamp));
      }
      verifier.update(wrapped.value);

      if (!verifier.verify(signature)) {
        throw new SignatureException("invalid signature found");
      }
    } catch (java.security.SignatureException e) {
      throw new SignatureException(e);
    }

    return wrapped.toEntry();
  }

  /**
   * Wrap the visibility field.
   * <p>
   * The resulting field will have the value {@literal colVis = (<originalColVis>)|data}. If the original column visibility value is empty, then the deafult
   * visibility value will be used in place of originalColVis.
   *
   * @param visibility
   *          The visibility data being wrapped.
   * @param data
   *          data to wrap into visibility.
   * @return Wrapped visibility.
   */
  private static byte[] wrapVisibility(byte[] visibility, byte[] data) throws IOException {
    ByteArrayOutputStream colVisStream = new ByteArrayOutputStream();
    DataOutput colVisOut = new DataOutputStream(colVisStream);

    colVisOut.writeByte((byte) '(');
    colVisOut.write(visibility);
    colVisOut.writeByte((byte) ')');
    colVisOut.writeByte((byte) '|');
    colVisOut.write(VisibilityEvaluator.escape(data, true));

    return colVisStream.toByteArray();
  }

  /**
   * Unwrap the visibility field.
   * <p>
   * Assumes the visibility field had previously been wrapped by a call to {@link #wrapVisibility(byte[], byte[])}. If the visibility is not in the form
   *
   *
   * @param visibility
   *          The visibility data.
   * @return The unwrapped visibility expression and data.
   */
  private static Pair<byte[],byte[]> unwrapVisibility(ColumnVisibility visibility) {
    ColumnVisibility.Node node = visibility.getParseTree();

    if (node.getType() != ColumnVisibility.NodeType.OR || node.getChildren().size() != 2) {
      throw new SignatureException("Invalid signature in the column visibility");
    }

    StringBuilder builder = new StringBuilder();
    ColumnVisibility.stringify(node.getChildren().get(0), visibility.getExpression(), builder);
    byte[] visibilityData = builder.toString().getBytes(VISIBILITY_CHARSET);

    byte[] wrappedData = unescape(node.getChildren().get(1).getTerm(visibility.getExpression())).toArray();
    return Pair.of(visibilityData, wrappedData);
  }

  /**
   * Unescape a visibility term.
   * <p>
   * Pulled from {@link VisibilityEvaluator} (line 49). This method is not public and could not be used directly.
   *
   * @param auth
   *          Term to transform.
   * @return The unescaped term.
   */
  private static ByteSequence unescape(ByteSequence auth) {
    int escapeCharCount = 0;
    for (int i = 0; i < auth.length(); i++) {
      byte b = auth.byteAt(i);
      if (b == '"' || b == '\\') {
        escapeCharCount++;
      }
    }

    if (escapeCharCount > 0) {
      if (escapeCharCount % 2 == 1) {
        throw new IllegalArgumentException("Illegal escape sequence in auth : " + auth);
      }

      byte[] unescapedCopy = new byte[auth.length() - escapeCharCount / 2];
      int pos = 0;
      for (int i = 0; i < auth.length(); i++) {
        byte b = auth.byteAt(i);
        if (b == '\\') {
          i++;
          b = auth.byteAt(i);
          if (b != '"' && b != '\\') {
            throw new IllegalArgumentException("Illegal escape sequence in auth : " + auth);
          }
        } else if (b == '"') {
          // should only see quote after a slash
          throw new IllegalArgumentException("Illegal escape sequence in auth : " + auth);
        }

        unescapedCopy[pos++] = b;
      }

      return new ArrayByteSequence(unescapedCopy);
    } else {
      return auth;
    }
  }

}
