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

import static edu.mit.ll.pace.internal.Utils.VISIBILITY_CHARSET;
import static edu.mit.ll.pace.test.Matchers.equalTo;
import static edu.mit.ll.pace.test.TestUtils.getResourceAsStream;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.Random;

import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Value;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.mit.ll.pace.internal.Utils;
import edu.mit.ll.pace.test.Matchers;

/**
 * Tests for {@link SignedInlineScannerIterator}
 */
public class SignedIteratorTest {

  private Map<ValueSigner,SignatureKeyContainer> aliceKeyContainers = new HashMap<>();
  private Map<ValueSigner,SignatureKeyContainer> bobKeyContainers = new HashMap<>();

  public SignedIteratorTest() throws NoSuchAlgorithmException {
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
  public void iteratorValueTest() throws Exception {
    Random random = new Random();
    List<Entry<Key,Value>> entries = new ArrayList<>();

    for (int i = 0; i < 100; i++) {
      byte[] bytes = new byte[32 * 4];
      random.nextBytes(bytes);
      entries.add(new SimpleImmutableEntry<>(new Key(Arrays.copyOfRange(bytes, 0, 32), Arrays.copyOfRange(bytes, 32, 64), Arrays.copyOfRange(bytes, 64, 96),
          "secret".getBytes(VISIBILITY_CHARSET), (long) 0, false), new Value(Arrays.copyOfRange(bytes, 96, 128))));
    }

    EntrySigner signer = getSigner("config1.ini", aliceKeyContainers.get(ValueSigner.RSA_PSS));
    List<Entry<Key,Value>> signedEntries = new ArrayList<>(entries.size());
    for (Entry<Key,Value> entry : entries) {
      signedEntries.add(signer.sign(entry, true));
    }

    EntrySigner verifier = getSigner("config1.ini", bobKeyContainers.get(ValueSigner.RSA_PSS));
    Iterator<Entry<Key,Value>> entriesIterator = entries.iterator();
    Iterator<Entry<Key,Value>> signedIterator = new SignedInlineScannerIterator(signedEntries.iterator(), verifier);

    while (entriesIterator.hasNext()) {
      assertThat("should return all entries", signedIterator.hasNext(), is(true));
      assertThat("should return same entry", entriesIterator.next(), equalTo(signedIterator.next()));
    }
    assertThat("should not return any more entries", signedIterator.hasNext(), is(false));
  }

  @Test
  public void iteratorColVisTest() throws Exception {
    Random random = new Random();
    List<Entry<Key,Value>> entries = new ArrayList<>();

    for (int i = 0; i < 100; i++) {
      byte[] bytes = new byte[32 * 4];
      random.nextBytes(bytes);
      entries.add(new SimpleImmutableEntry<>(new Key(Arrays.copyOfRange(bytes, 0, 32), Arrays.copyOfRange(bytes, 32, 64), Arrays.copyOfRange(bytes, 64, 96),
          "secret".getBytes(VISIBILITY_CHARSET), (long) 0, false), new Value(Arrays.copyOfRange(bytes, 96, 128))));
    }

    EntrySigner signer = getSigner("config2.ini", aliceKeyContainers.get(ValueSigner.RSA_PKCS1));
    List<Entry<Key,Value>> signedEntries = new ArrayList<>(entries.size());
    for (Entry<Key,Value> entry : entries) {
      signedEntries.add(signer.sign(entry, true));
    }

    EntrySigner verifier = getSigner("config2.ini", bobKeyContainers.get(ValueSigner.RSA_PKCS1));
    Iterator<Entry<Key,Value>> entriesIterator = entries.iterator();
    SignedInlineScannerIterator signedIterator = new SignedInlineScannerIterator(signedEntries.iterator(), verifier);

    while (entriesIterator.hasNext()) {
      assertThat("should return all entries", signedIterator.hasNext(), is(true));
      assertThat("should return same entry", entriesIterator.next(), equalTo(signedIterator.next()));
    }
    assertThat("should not return any more entries", signedIterator.hasNext(), is(false));
  }

  @Test
  public void iteratorTableTest() throws Exception {
    Random random = new Random();

    List<Entry<Key,Value>> entries = new ArrayList<>();

    for (int i = 0; i < 100; i++) {
      byte[] bytes = new byte[32 * 4];
      random.nextBytes(bytes);
      entries.add(new SimpleImmutableEntry<>(new Key(Arrays.copyOfRange(bytes, 0, 32), Arrays.copyOfRange(bytes, 32, 64), Arrays.copyOfRange(bytes, 64, 96),
          "secret".getBytes(VISIBILITY_CHARSET), (long) 0, false), new Value(Arrays.copyOfRange(bytes, 96, 128))));
    }

    EntrySigner signer = getSigner("config3.ini", aliceKeyContainers.get(ValueSigner.ECDSA));
    List<Entry<Key,Value>> signedEntries = new ArrayList<>(entries.size());
    for (Entry<Key,Value> entry : entries) {
      signedEntries.add(signer.sign(entry, true));
    }

    EntrySigner verifier = getSigner("config3.ini", bobKeyContainers.get(ValueSigner.ECDSA));
    Iterator<Entry<Key,Value>> entriesIterator = entries.iterator();
    SignedExternalScannerIterator signedIterator = new SignedExternalScannerIterator(entries.iterator(), signedEntries.iterator(), verifier, true);

    while (entriesIterator.hasNext()) {
      assertThat("should return all entries", signedIterator.hasNext(), is(true));
      assertThat("should return same entry", entriesIterator.next(), equalTo(signedIterator.next()));
    }
    assertThat("should not return any more entries", signedIterator.hasNext(), is(false));

    // Sign to separate table, with signatures in a different order than the entries.
    signedEntries = new ArrayList<>(entries.size());
    for (Entry<Key,Value> entry : entries) {
      signedEntries.add(signer.sign(entry, true));
    }
    Collections.shuffle(signedEntries);

    entriesIterator = entries.iterator();
    signedIterator = new SignedExternalScannerIterator(entries.iterator(), signedEntries.iterator(), verifier, false);

    while (entriesIterator.hasNext()) {
      assertThat("should return all entries", signedIterator.hasNext(), is(true));
      assertThat("should return same entry", entriesIterator.next(), equalTo(signedIterator.next()));
    }
    assertThat("should not return any more entries", signedIterator.hasNext(), is(false));
  }

  @Test
  public void internalUnprocessedTest() throws Exception {
    EntrySigner signer = getSigner("config1.ini", aliceKeyContainers.get(ValueSigner.RSA_PSS));
    EntrySigner verifier = getSigner("config1.ini", bobKeyContainers.get(ValueSigner.RSA_PSS));

    List<Entry<Key,Value>> entries = new ArrayList<>();
    byte[] row = new byte[] {1};
    Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(row, new byte[] {2}, new byte[] {3}, "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false,
        false), new Value(new byte[] {4}));

    entries.add(signer.sign(entry, true));
    SignedInlineScannerIterator iterator = new SignedInlineScannerIterator(entries.iterator(), verifier);

    iterator.next();
    assertThat("unprocessed item is correct", iterator.unprocessed(), Matchers.equalTo(entries.get(0)));
  }

  @Test
  public void internalUnprocessedException() throws Exception {
    EntrySigner signer = getSigner("config1.ini", aliceKeyContainers.get(ValueSigner.RSA_PSS));
    EntrySigner verifier = getSigner("config1.ini", bobKeyContainers.get(ValueSigner.RSA_PSS));

    List<Entry<Key,Value>> entries = new ArrayList<>();
    byte[] row = new byte[] {1};
    Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(row, new byte[] {2}, new byte[] {3}, "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false,
        false), new Value(new byte[] {4}));

    entries.add(signer.sign(entry, true));
    SignedInlineScannerIterator iterator = new SignedInlineScannerIterator(entries.iterator(), verifier);

    try {
      iterator.unprocessed();
      fail("cannot call unprocessed before calling next()");
    } catch (NoSuchElementException e) { /* expected */}

    try {
      iterator.hasNext();
      iterator.unprocessed();
      fail("cannot call unprocessed before calling next()");
    } catch (NoSuchElementException e) { /* expected */}
  }

  @Test
  public void externalUnprocessedTest() throws Exception {
    EntrySigner signer = getSigner("config3.ini", aliceKeyContainers.get(ValueSigner.ECDSA));
    EntrySigner verifier = getSigner("config3.ini", bobKeyContainers.get(ValueSigner.ECDSA));

    List<Entry<Key,Value>> entries = new ArrayList<>();
    List<Entry<Key,Value>> signedEntries = new ArrayList<>();

    byte[] row = new byte[] {1};
    Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(row, new byte[] {2}, new byte[] {3}, "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false,
        false), new Value(new byte[] {4}));

    entries.add(entry);
    signedEntries.add(signer.sign(entry, true));

    SignedExternalScannerIterator iterator = new SignedExternalScannerIterator(entries.iterator(), signedEntries.iterator(), verifier, true);

    iterator.next();
    assertThat("unprocessed item is correct", iterator.unprocessed(), Matchers.equalTo(entries.get(0)));
  }

  @Test
  public void externalUnprocessedException() throws Exception {
    EntrySigner signer = getSigner("config3.ini", aliceKeyContainers.get(ValueSigner.ECDSA));
    EntrySigner verifier = getSigner("config3.ini", bobKeyContainers.get(ValueSigner.ECDSA));

    List<Entry<Key,Value>> entries = new ArrayList<>();
    List<Entry<Key,Value>> signedEntries = new ArrayList<>();

    byte[] row = new byte[] {1};
    Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(row, new byte[] {2}, new byte[] {3}, "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false,
        false), new Value(new byte[] {4}));

    entries.add(entry);
    signedEntries.add(signer.sign(entry, true));

    SignedExternalScannerIterator iterator = new SignedExternalScannerIterator(entries.iterator(), signedEntries.iterator(), verifier, true);

    try {
      iterator.unprocessed();
      fail("cannot call unprocessed before calling next()");
    } catch (NoSuchElementException e) { /* expected */}

    try {
      iterator.hasNext();
      iterator.unprocessed();
      fail("cannot call unprocessed before calling next()");
    } catch (NoSuchElementException e) { /* expected */}
  }

  @Test
  public void iteratorRemoveFailsTest() {
    try {
      new SignedInlineScannerIterator(null, null).remove();
      fail("removal is not allowed");
    } catch (UnsupportedOperationException e) { /* expected */}

    try {
      new SignedExternalScannerIterator(null, null, null, true).remove();
      fail("removal is not allowed");
    } catch (UnsupportedOperationException e) { /* expected */}
  }

  @Test
  public void missingSignatureTest() throws Exception {
    Random random = new Random();
    List<Entry<Key,Value>> entries = new ArrayList<>();

    for (int i = 0; i < 100; i++) {
      byte[] bytes = new byte[32 * 4];
      random.nextBytes(bytes);
      entries.add(new SimpleImmutableEntry<>(new Key(Arrays.copyOfRange(bytes, 0, 32), Arrays.copyOfRange(bytes, 32, 64), Arrays.copyOfRange(bytes, 64, 96),
          "secret".getBytes(VISIBILITY_CHARSET), (long) 0, false), new Value(Arrays.copyOfRange(bytes, 96, 128))));
    }

    EntrySigner signer = getSigner("config3.ini", aliceKeyContainers.get(ValueSigner.ECDSA));
    List<Entry<Key,Value>> signedEntries = new ArrayList<>(entries.size());
    for (Entry<Key,Value> entry : entries) {
      signedEntries.add(signer.sign(entry, true));
    }

    EntrySigner verifier = getSigner("config3.ini", bobKeyContainers.get(ValueSigner.ECDSA));
    signedEntries.remove(9);
    SignedExternalScannerIterator signedIterator = new SignedExternalScannerIterator(entries.iterator(), signedEntries.iterator(), verifier, true);

    try {
      while (signedIterator.hasNext()) {
        signedIterator.next();
      }
      fail("missing signature should cause an exception");
    } catch (SignatureException e) { /* expected */}

    // Missing signature is the first signature.
    signedEntries = new ArrayList<>(entries.size());
    for (Entry<Key,Value> entry : entries) {
      signedEntries.add(signer.sign(entry, true));
    }
    signedEntries.remove(0);
    signedIterator = new SignedExternalScannerIterator(entries.iterator(), signedEntries.iterator(), verifier, true);

    try {
      while (signedIterator.hasNext()) {
        signedIterator.next();
      }
      fail("missing signature should cause an exception");
    } catch (SignatureException e) { /* expected */}

    // Missing signature is in the middle of the table.
    signedEntries = new ArrayList<>(entries.size());
    for (Entry<Key,Value> entry : entries) {
      signedEntries.add(signer.sign(entry, true));
    }
    signedEntries.remove(5);
    Collections.shuffle(signedEntries);
    signedIterator = new SignedExternalScannerIterator(entries.iterator(), signedEntries.iterator(), verifier, false);

    try {
      while (signedIterator.hasNext()) {
        signedIterator.next();
      }
      fail("missing signature should cause an exception");
    } catch (SignatureException e) { /* expected */}
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
