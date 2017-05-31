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
package edu.mit.ll.pace.harness;

import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.accumulo.core.security.Authorizations;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import edu.mit.ll.pace.encryption.EncryptionKeyContainer;
import edu.mit.ll.pace.keymanagement.LocalEncryptionKeyContainer;
import edu.mit.ll.pace.keymanagement.LocalSignatureKeyContainer;
import edu.mit.ll.pace.signature.SignatureKeyContainer;
import edu.mit.ll.pace.signature.ValueSigner;

public final class User {

  /**
   * Identity of the user.
   */
  public final String id;

  /**
   * Password for the user.
   */
  public final String password;

  /**
   * The user's Accumulo authorizations.
   */
  public final Authorizations authorizations;

  /**
   * Encryption keys for the user.
   */
  public final EncryptionKeyContainer encryptionKeys;

  /**
   * Encryption keys for the user.
   */
  public final Map<ValueSigner,SignatureKeyContainer> signatureKeys;

  /**
   * Create the user.
   *
   * @param id
   *          Identity of the user.
   * @param authorizations
   *          The user's Accumulo authorizations.
   * @param password
   *          Password for the user.
   * @param encryptionKeys
   *          Encryption keys for the user.
   * @param signatureKeys
   *          Signature keys for the user.
   */
  private User(String id, String password, Authorizations authorizations, EncryptionKeyContainer encryptionKeys,
      Map<ValueSigner,SignatureKeyContainer> signatureKeys) {
    this.id = id;
    this.password = password;
    this.authorizations = authorizations;
    this.encryptionKeys = encryptionKeys;
    this.signatureKeys = signatureKeys;
  }

  /**
   * Parse the user from a JSON object.
   *
   * @param userObject
   *          JSON object to parse.
   * @return The parsed user object.
   */
  static User parseJson(JsonObject userObject) throws InvalidKeySpecException, NoSuchAlgorithmException {
    String id = userObject.getAsJsonPrimitive("id").getAsString();
    String password = userObject.getAsJsonPrimitive("password").getAsString();

    JsonArray authArray = userObject.getAsJsonArray("authorizations");
    String[] auths = new String[authArray.size()];
    for (int i = 0; i < auths.length; i++) {
      auths[i] = authArray.get(i).getAsString();
    }

    EncryptionKeyContainer encryptionKeys = LocalEncryptionKeyContainer.read(new InputStreamReader(User.class.getResourceAsStream(userObject
        .getAsJsonPrimitive("encryptionKeys").getAsString())));

    Map<ValueSigner,SignatureKeyContainer> signatureKeys = new HashMap<>();
    for (Entry<String,JsonElement> entry : userObject.getAsJsonObject("signatureKeys").entrySet()) {
      signatureKeys.put(ValueSigner.valueOf(entry.getKey()),
          LocalSignatureKeyContainer.read(new InputStreamReader(User.class.getResourceAsStream(entry.getValue().getAsJsonPrimitive().getAsString()))));
    }

    return new User(id, password, new Authorizations(auths), encryptionKeys, signatureKeys);
  }

  /**
   * The user list.
   */
  private static Map<String,User> users;

  /**
   * Get the user list.
   *
   * @return User list.
   */
  synchronized static Map<String,User> getUsers() {
    if (users == null) {
      users = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

      // Register Bouncy castle, as it will be used to generate signature keys.
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new BouncyCastleProvider());
      }

      // Parse the users.
      JsonParser parser = new JsonParser();
      JsonArray config = parser.parse(new InputStreamReader(AccumuloInstance.class.getResourceAsStream("users.json"))).getAsJsonObject()
          .getAsJsonArray("users");

      for (JsonElement userElement : config) {
        try {
          User user = User.parseJson(userElement.getAsJsonObject());
          users.put(user.id, user);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
          throw new IllegalStateException(e);
        }
      }
    }

    return users;
  }

}
