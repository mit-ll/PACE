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

import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;
import static edu.mit.ll.pace.test.TestUtils.getResourceAsStream;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.security.Security;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.List;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.ColumnVisibility;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ini4j.Ini;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.ImmutableSet;

import edu.mit.ll.pace.EntryField;
import edu.mit.ll.pace.IllegalKeyRequestException;
import edu.mit.ll.pace.internal.MutableEntry;

/**
 * Test {@link FieldEncryptor}.
 */
public class FieldEncryptorTest {

  /**
   * The mock key container, filled with several keys.
   */
  private static EncryptionKeyContainer keys = new MockEncryptionKeyContainer(Pair.of("SIV", 2), Pair.of("GCM", 2), Pair.of("identity1", 1), Pair.of(
      "identity2", 2), Pair.of("secret", 2), Pair.of("top secret", 1), Pair.of("admin", 1));

  @BeforeClass
  public static void registerBouncyCastle() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void constructorExceptionTests() throws Exception {
    try {
      new FieldEncryptor(null, keys);
      fail("config must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getEncryptor("gcm.ini", null); // Implicitly tests a good config, but a null key set.
      fail("keys must not be null");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void encryptTest() throws Exception {
    MutableEntry original = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false), new Value(new byte[] {6})));
    MutableEntry empty = new MutableEntry();
    ColumnVisibility visibility = new ColumnVisibility("secret");

    // gcmEncryptor
    MutableEntry encrypted = new MutableEntry();
    FieldEncryptor encryptor = getEncryptor("gcm.ini");

    encryptor.encrypt(original, encrypted, visibility);
    assertThat("row was not encrypted and should not be set", encrypted.row, is(empty.row));
    assertThat("colFamily was not encrypted and should not be set", encrypted.colF, is(empty.colF));
    assertThat("colQualifier was not encrypted and should not be set", encrypted.colQ, is(empty.colQ));
    assertThat("colVisibility was not encrypted and should not be set", encrypted.colVis, is(empty.colVis));
    assertThat("timestamp was not encrypted and should not be set", encrypted.timestamp, is(empty.timestamp));
    assertThat("delete was not encrypted and should not be set", encrypted.delete, is(empty.delete));
    assertThat("value was encrypted and should be different", encrypted.value, is(not(original.value)));

    // gcmCEABACEncryptor
    encrypted = new MutableEntry();
    encryptor = getEncryptor("gcmCEABAC.ini");

    encryptor.encrypt(original, encrypted, visibility);
    assertThat("row was not encrypted and should not be set", encrypted.row, is(empty.row));
    assertThat("colFamily was not encrypted and should not be set", encrypted.colF, is(empty.colF));
    assertThat("colQualifier was not encrypted and should not be set", encrypted.colQ, is(empty.colQ));
    assertThat("colVisibility was not encrypted and should not be set", encrypted.colVis, is(empty.colVis));
    assertThat("timestamp was not encrypted and should not be set", encrypted.timestamp, is(empty.timestamp));
    assertThat("delete was not encrypted and should not be set", encrypted.delete, is(empty.delete));
    assertThat("value was encrypted and should be different", encrypted.value, is(not(original.value)));

    // sivEncryptor
    encrypted = new MutableEntry();
    encryptor = getEncryptor("siv.ini");

    encryptor.encrypt(original, encrypted, visibility);
    assertThat("row was encrypted and should be different", encrypted.row, is(not(original.row)));
    assertThat("colFamily was not encrypted and should not be set", encrypted.colF, is(empty.colF));
    assertThat("colQualifier was not encrypted and should not be set", encrypted.colQ, is(empty.colQ));
    assertThat("colVisibility was not encrypted and should not be set", encrypted.colVis, is(empty.colVis));
    assertThat("timestamp was not encrypted and should not be set", encrypted.timestamp, is(empty.timestamp));
    assertThat("delete was not encrypted and should not be set", encrypted.delete, is(empty.delete));
    assertThat("value was not encrypted and should not be set", encrypted.value, is(empty.value));

    // allEncryptor
    encrypted = new MutableEntry();
    encryptor = getEncryptor("all.ini");

    encryptor.encrypt(original, encrypted, visibility);
    assertThat("row was encrypted and should not be different", encrypted.row, is(not(original.row)));
    assertThat("colFamily was encrypted and should not be different", encrypted.colF, is(not(original.colF)));
    assertThat("colQualifier was encrypted and should not be different", encrypted.colQ, is(not(original.colQ)));
    assertThat("colVisibility was encrypted and should be different", encrypted.colVis, is(not(original.colVis)));
    assertThat("timestamp was encrypted and should not be different", encrypted.timestamp, is(empty.timestamp));
    assertThat("delete was encrypted, but  and should not be different", encrypted.delete, is(empty.delete));
    assertThat("value was encrypted and should not be different", encrypted.value, is(not(original.value)));
  }

  @Test
  public void encryptedFieldStructureTest() throws Exception {
    MutableEntry original1 = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false), new Value(new byte[] {6, 7, 8})));
    MutableEntry original2 = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {9}, new byte[] {10, 11}, new byte[] {12, 13, 14},
        "abcde".getBytes(VISIBILITY_CHARSET), (long) 15, true), new Value(new byte[] {16, 17})));
    ColumnVisibility visibility = new ColumnVisibility("secret");

    // Encrypt value with version 1 key.
    MutableEntry encrypted = new MutableEntry();
    FieldEncryptor encryptor = getEncryptor("identity1.ini"); // Uses a key with version = 1.
    IdentityEncryptor.replaceValueEncryptorWithIdentityFunction(encryptor);

    encryptor.encrypt(original1, encrypted, visibility);
    assertThat("encrypted structure is (key version, length, data)", encrypted.value, is(new byte[] {1, 3, 6, 7, 8}));

    encryptor.encrypt(original2, encrypted, visibility);
    assertThat("encrypted structure is (key version, length, data)", encrypted.value, is(new byte[] {1, 2, 16, 17}));

    // Encrypt value with version 2 key.
    encrypted = new MutableEntry();
    encryptor = getEncryptor("identity2.ini"); // Uses a key with version = 2.
    IdentityEncryptor.replaceValueEncryptorWithIdentityFunction(encryptor);

    encryptor.encrypt(original1, encrypted, visibility);
    assertThat("encrypted structure is (key version, length, data)", encrypted.value, is(new byte[] {2, 3, 6, 7, 8}));

    // Encrypt all values into single field.
    encrypted = new MutableEntry();
    encryptor = getEncryptor("identityAll.ini");
    IdentityEncryptor.replaceValueEncryptorWithIdentityFunction(encryptor);

    encryptor.encrypt(original1, encrypted, visibility);
    assertThat("encrypted structure is (key version, foreach field [length, data])", encrypted.row, is(new byte[] {2, 1, 1, 1, 2, 1, 3, 6, 115, 101, 99, 114,
        101, 116}));

    encryptor.encrypt(original2, encrypted, visibility);
    assertThat("encrypted structure is (key version, foreach field [length, data])", encrypted.row, is(new byte[] {2, 1, 9, 2, 10, 11, 3, 12, 13, 14, 5, 97,
        98, 99, 100, 101}));
  }

  @Test
  public void encryptDecryptTest() throws Exception {
    MutableEntry original = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false), new Value(new byte[] {6})));
    MutableEntry empty = new MutableEntry();
    ColumnVisibility visibility = new ColumnVisibility("secret");

    // gcmEncryptor
    MutableEntry encrypted = new MutableEntry();
    MutableEntry decrypted = new MutableEntry();
    FieldEncryptor encryptor = getEncryptor("gcm.ini");

    encryptor.encrypt(original, encrypted, visibility);
    encryptor.decrypt(encrypted, decrypted, visibility);
    assertThat("row was not encrypted and should not be set", decrypted.row, is(empty.row));
    assertThat("colFamily was not encrypted and should not be set", decrypted.colF, is(empty.colF));
    assertThat("colQualifier was not encrypted and should not be set", decrypted.colQ, is(empty.colQ));
    assertThat("colVisibility was not encrypted and should not be set", decrypted.colVis, is(empty.colVis));
    assertThat("timestamp was not encrypted and should not be set", decrypted.timestamp, is(empty.timestamp));
    assertThat("delete was not encrypted and should not be set", decrypted.delete, is(empty.delete));
    assertThat("value was encrypted and should be set", decrypted.value, is(original.value));

    // gcmCEABACEncryptor
    encrypted = new MutableEntry();
    decrypted = new MutableEntry();
    encryptor = getEncryptor("gcmCEABAC.ini");

    encryptor.encrypt(original, encrypted, visibility);
    encryptor.decrypt(encrypted, decrypted, visibility);
    assertThat("row was not encrypted and should not be set", decrypted.row, is(empty.row));
    assertThat("colFamily was not encrypted and should not be set", decrypted.colF, is(empty.colF));
    assertThat("colQualifier was not encrypted and should not be set", decrypted.colQ, is(empty.colQ));
    assertThat("colVisibility was not encrypted and should not be set", decrypted.colVis, is(empty.colVis));
    assertThat("timestamp was not encrypted and should not be set", decrypted.timestamp, is(empty.timestamp));
    assertThat("delete was not encrypted and should not be set", decrypted.delete, is(empty.delete));
    assertThat("value was encrypted and should be set", decrypted.value, is(original.value));

    // sivEncryptor
    encrypted = new MutableEntry();
    decrypted = new MutableEntry();
    encryptor = getEncryptor("siv.ini");

    encryptor.encrypt(original, encrypted, visibility);
    encryptor.decrypt(encrypted, decrypted, visibility);
    assertThat("row was encrypted and should be set", decrypted.row, is(original.row));
    assertThat("colFamily was not encrypted and should not be set", decrypted.colF, is(empty.colF));
    assertThat("colQualifier was not encrypted and should not be set", decrypted.colQ, is(empty.colQ));
    assertThat("colVisibility was not encrypted and should not be set", decrypted.colVis, is(empty.colVis));
    assertThat("timestamp was not encrypted and should not be set", decrypted.timestamp, is(empty.timestamp));
    assertThat("delete was not encrypted and should not be set", decrypted.delete, is(empty.delete));
    assertThat("value was not encrypted and should not be set", decrypted.value, is(empty.value));

    // allEncryptor
    encrypted = new MutableEntry();
    decrypted = new MutableEntry();
    encryptor = getEncryptor("all.ini");

    encryptor.encrypt(original, encrypted, visibility);
    encryptor.decrypt(encrypted, decrypted, visibility);
    assertThat("row was encrypted and should be set", decrypted.row, is(original.row));
    assertThat("colFamily was encrypted and should be set", decrypted.colF, is(original.colF));
    assertThat("colQualifier was encrypted and should be set", decrypted.colQ, is(original.colQ));
    assertThat("colVisibility was encrypted and should be set", decrypted.colVis, is(original.colVis));
    assertThat("timestamp was not encrypted and should not be set", decrypted.timestamp, is(empty.timestamp));
    assertThat("delete was not encrypted and should not be set", decrypted.delete, is(empty.delete));
    assertThat("value was not encrypted and should not be set", decrypted.value, is(empty.value));
  }

  @Test
  public void encryptDecryptCEABACTest() throws Exception {
    MutableEntry original = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false), new Value(new byte[] {6})));
    MutableEntry encrypted = new MutableEntry();
    MutableEntry decrypted = new MutableEntry();

    FieldEncryptor encryptor = getEncryptor("gcmCEABAC.ini");
    MockEncryptionKeyContainer empty = new MockEncryptionKeyContainer();
    MockEncryptionKeyContainer secretOnly = new MockEncryptionKeyContainer(Pair.of("secret", 2));
    MockEncryptionKeyContainer topSecretOnly = new MockEncryptionKeyContainer(Pair.of("top secret", 1));
    MockEncryptionKeyContainer secretAndAdminOnly = new MockEncryptionKeyContainer(Pair.of("secret", 2), Pair.of("admin", 1));

    // empty
    ColumnVisibility visibility = new ColumnVisibility("");
    original.colVis = visibility.getExpression();
    encryptor.encrypt(original, encrypted, visibility);

    getEncryptor("gcmCEABAC.ini", empty).decrypt(encrypted, decrypted, visibility);
    assertThat("no keys should be needed to decrypt the value", decrypted.value, is(original.value));

    // secret | top secret
    visibility = new ColumnVisibility("secret|\"top secret\"");
    original.colVis = visibility.getExpression();
    encryptor.encrypt(original, encrypted, visibility);

    try {
      getEncryptor("gcmCEABAC.ini", empty).decrypt(encrypted, decrypted, visibility);
      fail("empty keys should not decrypt data");
    } catch (IllegalKeyRequestException e) { /* expected */}

    getEncryptor("gcmCEABAC.ini", secretOnly).decrypt(encrypted, decrypted, visibility);
    assertThat("secret should be sufficient", decrypted.value, is(original.value));

    getEncryptor("gcmCEABAC.ini", topSecretOnly).decrypt(encrypted, decrypted, visibility);
    assertThat("top secret should be sufficient", decrypted.value, is(original.value));

    // secret & top secret
    visibility = new ColumnVisibility("secret&\"top secret\"");
    original.colVis = visibility.getExpression();
    encryptor.encrypt(original, encrypted, visibility);

    try {
      getEncryptor("gcmCEABAC.ini", empty).decrypt(encrypted, decrypted, visibility);
      fail("empty keys should not decrypt data");
    } catch (IllegalKeyRequestException e) { /* expected */}

    try {
      getEncryptor("gcmCEABAC.ini", secretOnly).decrypt(encrypted, decrypted, visibility);
      fail("secret keys should not decrypt data");
    } catch (IllegalKeyRequestException e) { /* expected */}

    try {
      getEncryptor("gcmCEABAC.ini", topSecretOnly).decrypt(encrypted, decrypted, visibility);
      fail("top secret keys should not decrypt data");
    } catch (IllegalKeyRequestException e) { /* expected */}

    getEncryptor("gcmCEABAC.ini", keys).decrypt(encrypted, decrypted, visibility);
    assertThat("secret and topSecret should be sufficient", decrypted.value, is(original.value));

    // top secret | (secret & admin)
    visibility = new ColumnVisibility("\"top secret\"|(secret&admin)");
    original.colVis = visibility.getExpression();
    encryptor.encrypt(original, encrypted, visibility);

    getEncryptor("gcmCEABAC.ini", topSecretOnly).decrypt(encrypted, decrypted, visibility);
    assertThat("topSecret should be sufficient", decrypted.value, is(original.value));

    try {
      getEncryptor("gcmCEABAC.ini", secretOnly).decrypt(encrypted, decrypted, visibility);
      fail("secret keys should not decrypt data");
    } catch (IllegalKeyRequestException e) { /* expected */}

    getEncryptor("gcmCEABAC.ini", secretAndAdminOnly).decrypt(encrypted, decrypted, visibility);
    assertThat("secret and admin should be sufficient", decrypted.value, is(original.value));
  }

  @Test
  public void keyVersioningTest() throws Exception {
    MutableEntry original = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false), new Value(new byte[] {6})));
    ColumnVisibility visibility = new ColumnVisibility("secret");
    MutableEntry encrypted = new MutableEntry();
    MutableEntry decrypted = new MutableEntry();

    getEncryptor("gcm.ini", new MockEncryptionKeyContainer(Pair.of("GCM", 1))).encrypt(original, encrypted, visibility);
    getEncryptor("gcm.ini", new MockEncryptionKeyContainer(Pair.of("GCM", 2))).decrypt(encrypted, decrypted, visibility);
    assertThat("value was decrypted with proper key", decrypted.value, is(original.value));
  }

  @Test
  public void canBeFilteredServerSideTest() throws Exception {
    assertThat("non-deterministic algorithms can't be filtered server side", getEncryptor("gcm.ini").canBeFilteredServerSide(ImmutableSet.of(EntryField.ROW)),
        is(false));
    assertThat("Visibility can't be filtered server side", getEncryptor("gcmCEABAC.ini").canBeFilteredServerSide(ImmutableSet.of(EntryField.ROW)), is(false));
    assertThat("appropriate columns must be available", getEncryptor("siv.ini").canBeFilteredServerSide(ImmutableSet.of(EntryField.COLUMN_FAMILY)), is(false));
    assertThat("deterministic encryption with correct fields should work", getEncryptor("siv.ini").canBeFilteredServerSide(ImmutableSet.of(EntryField.ROW)),
        is(true));
  }

  @Test
  public void canSearchForTest() throws Exception {
    assertThat("non-deterministic algorithms can't be searched server side", getEncryptor("gcm.ini").canSearchFor(ImmutableSet.of(EntryField.ROW)), is(false));
    assertThat("Visibility can't be filtered server side", getEncryptor("gcmCEABAC.ini").canSearchFor(ImmutableSet.of(EntryField.ROW)), is(false));
    assertThat("appropriate columns must be available", getEncryptor("siv.ini").canSearchFor(ImmutableSet.of(EntryField.ROW, EntryField.COLUMN_FAMILY)),
        is(false));
    assertThat("deterministic encryption with correct fields should work", getEncryptor("siv.ini").canSearchFor(ImmutableSet.of(EntryField.ROW)), is(true));
  }

  @Test
  public void getServerSideFilterValuesTest() throws Exception {
    MutableEntry original = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false), new Value(new byte[] {6})));
    ColumnVisibility visibility = new ColumnVisibility("secret");

    MutableEntry encryptedV1 = new MutableEntry();
    getEncryptor("siv.ini", new MockEncryptionKeyContainer(Pair.of("SIV", 1))).encrypt(original, encryptedV1, visibility);

    MutableEntry encryptedV2 = new MutableEntry();
    getEncryptor("siv.ini", new MockEncryptionKeyContainer(Pair.of("SIV", 2))).encrypt(original, encryptedV2, visibility);

    List<byte[]> searchKeys = getEncryptor("siv.ini", new MockEncryptionKeyContainer(Pair.of("SIV", 2))).getServerSideFilterValues(original);
    assertThat("encrypted values for each version available", searchKeys, containsInAnyOrder(encryptedV1.row, encryptedV2.row));
  }

  /**
   * Get an encryptor. The default set of keys will be used.
   *
   * @param resource
   *          Resource file containing the configuration.
   * @return FieldEncryptor.
   */
  private FieldEncryptor getEncryptor(String resource) throws Exception {
    return getEncryptor(resource, keys);
  }

  /**
   * Get an encryptor.
   *
   * @param resource
   *          Resource file containing the configuration.
   * @param keys
   *          Keys to use for the encryptor.
   * @return FieldEncryptor.
   */
  private FieldEncryptor getEncryptor(String resource, EncryptionKeyContainer keys) throws Exception {
    Ini ini = new Ini(getResourceAsStream(this.getClass(), resource));
    return new FieldEncryptor(new FieldEncryptorConfigBuilder().readFromIni(ini.values().iterator().next()).build(), keys);
  }

}
