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
package edu.mit.ll.pace.keymanagement;

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.mit.ll.pace.IllegalKeyRequestException;
import edu.mit.ll.pace.signature.SignatureKeyContainer;

/**
 * Key container.
 */
public final class LocalSignatureKeyContainer implements SignatureKeyContainer {

  /**
   * The version of the serialized data.
   */
  private static final int CURRENT_VERSION = 1;

  /**
   * The encoding to use in serializing IDs.
   */
  private static final Charset ENCODING_CHARSET = StandardCharsets.UTF_8;

  /**
   * The signing key for the key container.
   */
  private final PrivateKeyWithId signingKey;

  /**
   * Set of verification keys for testing signatures.
   */
  private final Map<ByteBuffer,PublicKey> verificationKeys = new HashMap<>();

  /**
   * Create a signature key container that only holds verification key.
   */
  public LocalSignatureKeyContainer() {
    signingKey = null;
  }

  /**
   * Create the signature key container that can sign using the given key.
   *
   * @param privateKey
   *          Private key to use for signing.
   * @param signingKeyId
   *          Identifier for the signing key.
   */
  private LocalSignatureKeyContainer(PrivateKey privateKey, byte[] signingKeyId) {
    checkArgument(privateKey != null, "private key is null");
    checkArgument(signingKeyId != null, "signingKeyId is null");
    checkArgument(signingKeyId.length != 0, "signingKeyId is empty");

    try {
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
      KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm());
      this.signingKey = new PrivateKeyWithId(keyFactory.generatePrivate(keySpec), signingKeyId.clone());
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) { // Won't be thrown, as we having a working algorithm and key spec.
      throw new IllegalStateException(e);
    }
  }

  /**
   * Create the signature key container that can sign using the given key.
   *
   * @param keyPair
   *          key pair for the signer.
   * @param signingKeyId
   *          Identifier for the signing key.
   */
  public LocalSignatureKeyContainer(KeyPair keyPair, byte[] signingKeyId) {
    this(keyPair.getPrivate(), signingKeyId);
    checkArgument(keyPair.getPublic() != null, "keyPair.getPublic() is null");
    addVerifierKey(keyPair.getPublic(), signingKeyId);
  }

  /**
   * Add a verifier key.
   *
   * @param verifierKey
   *          The public key used for verification.
   * @param id
   *          Id of the key.
   */
  public void addVerifierKey(PublicKey verifierKey, byte[] id) {
    checkArgument(signingKey != null, "signingKey is null");
    checkArgument(id != null, "id is null");
    checkArgument(id.length != 0, "id is empty");
    addVerifierKey(verifierKey, id, true);
  }

  /**
   * Add a verifier key.
   *
   * @param verifierKey
   *          The public key used for verification.
   * @param id
   *          Id of the key.
   * @param copy
   *          Whether to copy the key.
   */
  private void addVerifierKey(PublicKey verifierKey, byte[] id, boolean copy) {
    checkArgument(verifierKey != null, "verifierKey is null");
    checkArgument(id != null, "id is null");
    checkArgument(id.length != 0, "id is empty");

    if (copy) {
      try {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(verifierKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance(verifierKey.getAlgorithm());
        this.verificationKeys.put(ByteBuffer.wrap(id.clone()), keyFactory.generatePublic(keySpec));
      } catch (InvalidKeySpecException | NoSuchAlgorithmException e) { // Won't be thrown, as we having a working algorithm and key spec.
        throw new IllegalStateException(e);
      }
    } else {
      this.verificationKeys.put(ByteBuffer.wrap(id), verifierKey);
    }
  }

  @Override
  public PrivateKeyWithId getSigningKey() {
    if (signingKey == null) {
      throw new IllegalKeyRequestException("no signing key available");
    }
    return signingKey;
  }

  @Override
  public PublicKey getVerifyingKey(byte[] id) {
    checkArgument(id != null, "id is null");
    checkArgument(id.length != 0, "id is empty");

    PublicKey verificationKey = verificationKeys.get(ByteBuffer.wrap(id));
    if (verificationKey == null) {
      throw new IllegalKeyRequestException("no verification key for {id=" + new String(id, ENCODING_CHARSET) + "}");
    }
    return verificationKey;
  }

  /**
   * Write the signature key container to the writer.
   *
   * @param out
   *          Output writer.
   */
  public void write(Writer out) throws IOException {
    Gson gson = new GsonBuilder().enableComplexMapKeySerialization().setPrettyPrinting().create();

    JsonObject data = new JsonObject();
    data.addProperty("version", CURRENT_VERSION);

    if (signingKey != null) {
      JsonObject signingKeyContainer = new JsonObject();
      signingKeyContainer.addProperty("keyId", new String(signingKey.id, ENCODING_CHARSET));
      signingKeyContainer.addProperty("algorithm", signingKey.key.getAlgorithm());
      signingKeyContainer.addProperty("key", Base64.getEncoder().encodeToString(signingKey.key.getEncoded()));
      data.add("signingKey", signingKeyContainer);
    }

    JsonArray keys = new JsonArray();
    for (Entry<ByteBuffer,PublicKey> entry : verificationKeys.entrySet()) {
      JsonObject key = new JsonObject();
      key.addProperty("keyId", new String(entry.getKey().array(), ENCODING_CHARSET));
      key.addProperty("algorithm", entry.getValue().getAlgorithm());
      key.addProperty("key", Base64.getEncoder().encodeToString(entry.getValue().getEncoded()));
      keys.add(key);
    }
    data.add("verificationKeys", keys);

    gson.toJson(data, out);
    out.flush();
  }

  /**
   * Read the signature key container from the reader.
   *
   * @param in
   *          Input reader.
   * @return Parsed signature key container.
   */
  public static LocalSignatureKeyContainer read(Reader in) throws InvalidKeySpecException, NoSuchAlgorithmException {
    LocalSignatureKeyContainer container;
    JsonParser parser = new JsonParser();

    JsonObject data = parser.parse(in).getAsJsonObject();
    int version = data.getAsJsonPrimitive("version").getAsInt();

    switch (version) {
      case 1:
        if (data.has("signingKey")) {
          JsonObject signingKeyContainer = data.getAsJsonObject("signingKey").getAsJsonObject();
          KeyFactory factory = KeyFactory.getInstance(signingKeyContainer.getAsJsonPrimitive("algorithm").getAsString());
          container = new LocalSignatureKeyContainer(factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(
              signingKeyContainer.getAsJsonPrimitive("key").getAsString()))), signingKeyContainer.getAsJsonPrimitive("keyId").getAsString()
              .getBytes(ENCODING_CHARSET));
        } else {
          container = new LocalSignatureKeyContainer();
        }

        JsonArray keys = data.getAsJsonArray("verificationKeys");
        for (int i = 0; i < keys.size(); i++) {
          JsonObject key = keys.get(i).getAsJsonObject();
          KeyFactory factory = KeyFactory.getInstance(key.getAsJsonPrimitive("algorithm").getAsString());
          container.addVerifierKey(factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(key.getAsJsonPrimitive("key").getAsString()))), key
              .getAsJsonPrimitive("keyId").getAsString().getBytes(ENCODING_CHARSET), false);
        }
        break;

      default:
        throw new UnsupportedOperationException("unsupported file version");
    }

    return container;
  }

}
