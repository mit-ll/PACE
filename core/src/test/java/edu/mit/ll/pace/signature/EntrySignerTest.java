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

import static edu.mit.ll.pace.internal.Utils.EMPTY;
import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;
import static edu.mit.ll.pace.test.TestUtils.getResourceAsStream;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.mit.ll.pace.internal.MutableEntry;
import edu.mit.ll.pace.internal.Utils;
import edu.mit.ll.pace.test.Matchers;

/**
 * Tests for {@link EntrySigner}
 */
public class EntrySignerTest {

  private Map<ValueSigner,SignatureKeyContainer> aliceKeyContainers = new HashMap<>();
  private Map<ValueSigner,SignatureKeyContainer> bobKeyContainers = new HashMap<>();

  public EntrySignerTest() throws NoSuchAlgorithmException {
    aliceKeyContainers = MockSignatureKeyContainer.getContainers("alice", "alice", "bob");
    bobKeyContainers = MockSignatureKeyContainer.getContainers("bob", "alice", "bob");
  }

  @BeforeClass
  public static void setupBouncyCastle() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void constructorExceptionTests() throws Exception {
    try {
      new EntrySigner(null, aliceKeyContainers.get(ValueSigner.RSA_PSS));
      fail("config must not be null");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getSigner("config1.ini", null); // Implicitly tests a good config, but a null key set.
      fail("keys must not be null");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void nullEntryTest() throws Exception {
    EntrySigner signer = getSigner("config1.ini", aliceKeyContainers.get(ValueSigner.RSA_PSS));

    try {
      signer.sign(null, true);
      fail("cannot call sign with a null entry");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      signer.verify(null);
      fail("cannot call verify with a null value");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      signer.verify(null, null);
      fail("cannot call verify with a null value");
    } catch (IllegalArgumentException e) { /* expected */}

    Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, "secret".getBytes(VISIBILITY_CHARSET),
        (long) 5, false), new Value(new byte[] {6}));

    try {
      getSigner("config2.ini", aliceKeyContainers.get(ValueSigner.RSA_PKCS1)).verify(entry, entry);
      fail("cannot call verify with a non-null signature entry if not needed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      getSigner("config3.ini", aliceKeyContainers.get(ValueSigner.ECDSA)).verify(entry, null);
      fail("cannot call verify with a null signature value when needed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void signVerifyInValueTest() throws Exception {
    MutableEntry entry = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false), new Value(new byte[] {6})));

    MutableEntry signed;
    Entry<Key,Value> verified;

    EntrySigner signer = getSigner("config1.ini", aliceKeyContainers.get(ValueSigner.RSA_PSS));
    EntrySigner verifier = getSigner("config1.ini", bobKeyContainers.get(ValueSigner.RSA_PSS));

    signed = new MutableEntry(signer.sign(entry.toEntry(), true));
    assertThat("row should not have changed", signed.row, is(entry.row));
    assertThat("colFamily should not have changed", signed.colF, is(entry.colF));
    assertThat("colQualifier should not have changed", signed.colQ, is(entry.colQ));
    assertThat("colVisibility should not have changed", signed.colVis, is(entry.colVis));
    assertThat("timestamp should not have changed", signed.timestamp, is(entry.timestamp));
    assertThat("delete should not have changed", signed.delete, is(entry.delete));
    assertThat("value should have changed", signed.value, is(not(entry.value)));

    verified = verifier.verify(signed.toEntry());
    assertThat("original and verified records are the same.", verified, Matchers.equalTo(entry.toEntry()));
  }

  @Test
  public void signVerifyInVisibilityTest() throws Exception {
    MutableEntry entry = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false), new Value(new byte[] {6})));

    MutableEntry signed;
    Entry<Key,Value> verified;

    // Sign to column visibility
    EntrySigner signer = getSigner("config2.ini", aliceKeyContainers.get(ValueSigner.RSA_PKCS1));
    EntrySigner verifier = getSigner("config2.ini", bobKeyContainers.get(ValueSigner.RSA_PKCS1));

    signed = new MutableEntry(signer.sign(entry.toEntry(), true));
    assertThat("row should not have changed", signed.row, is(entry.row));
    assertThat("colFamily should not have changed", signed.colF, is(entry.colF));
    assertThat("colQualifier should not have changed", signed.colQ, is(entry.colQ));
    assertThat("colVisibility should have changed", signed.colVis, is(not(entry.colVis)));
    assertThat("colVisibility is wrapped", new String(signed.colVis, Utils.VISIBILITY_CHARSET), startsWith("(secret)"));
    assertThat("timestamp should not have changed", signed.timestamp, is(entry.timestamp));
    assertThat("delete should not have changed", signed.delete, is(entry.delete));
    assertThat("value should not have changed", signed.value, is(entry.value));

    verified = verifier.verify(signed.toEntry());
    assertThat("original and verified records are the same.", verified, Matchers.equalTo(entry.toEntry()));

    // Sign to column visibility with default visibility
    MutableEntry entry2 = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3}, EMPTY, (long) 5, false),
        new Value(new byte[] {6})));

    signed = new MutableEntry(signer.sign(entry2.toEntry(), true));
    assertThat("row should not have changed", signed.row, is(entry2.row));
    assertThat("colFamily should not have changed", signed.colF, is(entry.colF));
    assertThat("colQualifier should not have changed", signed.colQ, is(entry.colQ));
    assertThat("colVisibility should have changed", signed.colVis, is(not(entry.colVis)));
    assertThat("colVisibility uses the default visibility", new String(signed.colVis, Utils.VISIBILITY_CHARSET), startsWith("(default)"));
    assertThat("timestamp should not have changed", signed.timestamp, is(entry.timestamp));
    assertThat("delete should not have changed", signed.delete, is(entry.delete));
    assertThat("value should not have changed", signed.value, is(entry.value));

    MutableEntry verifiedEntry = new MutableEntry(verifier.verify(signed.toEntry()));
    assertThat("row should not have changed", verifiedEntry.row, is(entry2.row));
    assertThat("colFamily should not have changed", verifiedEntry.colF, is(entry.colF));
    assertThat("colQualifier should not have changed", verifiedEntry.colQ, is(entry.colQ));
    assertThat("colVisibility should have changed to the default visibility", verifiedEntry.colVis, is("default".getBytes(Utils.VISIBILITY_CHARSET)));
    assertThat("timestamp should not have changed", verifiedEntry.timestamp, is(entry.timestamp));
    assertThat("delete should not have changed", verifiedEntry.delete, is(entry.delete));
    assertThat("value should not have changed", verifiedEntry.value, is(entry.value));
  }

  @Test
  public void signVerifyInSeparateTableTest() throws Exception {
    MutableEntry entry = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 5, false), new Value(new byte[] {6})));

    MutableEntry signed;
    Entry<Key,Value> verified;

    EntrySigner signer = getSigner("config3.ini", aliceKeyContainers.get(ValueSigner.ECDSA));
    EntrySigner verifier = getSigner("config3.ini", bobKeyContainers.get(ValueSigner.ECDSA));

    signed = new MutableEntry(signer.sign(entry.toEntry(), true));
    assertThat("row should not have changed", signed.row, is(entry.row));
    assertThat("colFamily should not have changed", signed.colF, is(entry.colF));
    assertThat("colQualifier should not have changed", signed.colQ, is(entry.colQ));
    assertThat("colVisibility should not have changed", signed.colVis, is(entry.colVis));
    assertThat("timestamp should not have changed", signed.timestamp, is(entry.timestamp));
    assertThat("delete should not have changed", signed.delete, is(entry.delete));
    assertThat("value should have changed", signed.value, is(not(entry.value)));

    verified = verifier.verify(entry.toEntry(), signed.toEntry());
    assertThat("original and verified records are the same.", verified, Matchers.equalTo(entry.toEntry()));
  }

  @Test
  public void hasNoTimestampTest() throws Exception {
    MutableEntry entry = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 0, false), new Value(new byte[] {6})));
    MutableEntry signed;

    EntrySigner signer = getSigner("config1.ini", aliceKeyContainers.get(ValueSigner.RSA_PSS));
    EntrySigner verifier = getSigner("config1.ini", bobKeyContainers.get(ValueSigner.RSA_PSS));

    try {
      signed = new MutableEntry(signer.sign(entry.toEntry(), true));
      signed.timestamp = 1000L;
      verifier.verify(signed.toEntry());
      fail("changing the timestamp should cause the signature to fail");
    } catch (SignatureException e) { /* expected */}

    signed = new MutableEntry(signer.sign(entry.toEntry(), false));
    signed.timestamp = 1000L;
    verifier.verify(signed.toEntry());
  }

  @Test
  public void badSignatureTest() throws Exception {
    MutableEntry entry = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 0, false), new Value(new byte[] {6})));
    Entry<Key,Value> signed;

    // Sign to value;
    EntrySigner signer = getSigner("config3.ini", aliceKeyContainers.get(ValueSigner.ECDSA));
    EntrySigner verifier = getSigner("config3.ini", bobKeyContainers.get(ValueSigner.ECDSA));

    signed = signer.sign(entry.toEntry(), true);
    entry.value = new byte[] {7};

    try {
      verifier.verify(entry.toEntry(), signed);
      fail("bad signature should thrown an exception");
    } catch (SignatureException e) { /* expected */}
  }

  @Test
  public void signVerifyDeleteException() throws Exception {
    MutableEntry entry = new MutableEntry(new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(VISIBILITY_CHARSET), (long) 0, true), new Value(new byte[] {6})));

    EntrySigner signer = getSigner("config1.ini", aliceKeyContainers.get(ValueSigner.RSA_PSS));
    EntrySigner verifier = getSigner("config1.ini", bobKeyContainers.get(ValueSigner.RSA_PSS));

    try {
      signer.sign(entry.toEntry(), true);
      fail("cannot sign deleted entries");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      verifier.verify(entry.toEntry());
      fail("cannot verify deleted entries");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  /**
   * Get a signer.
   *
   * @param resource
   *          Resource file containing the configuration.
   * @param keys
   *          Keys to use for the signer.
   * @return EntrySigner.
   */
  private EntrySigner getSigner(String resource, SignatureKeyContainer keys) throws Exception {
    return new EntrySigner(new SignatureConfigBuilder().readFromFile(new InputStreamReader(getResourceAsStream(this.getClass(), resource))).build(), keys);
  }

}
