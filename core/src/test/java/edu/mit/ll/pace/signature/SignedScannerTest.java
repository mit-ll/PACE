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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.IteratorSetting;
import org.apache.accumulo.core.client.IteratorSetting.Column;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.client.sample.SamplerConfiguration;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.hadoop.io.Text;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import edu.mit.ll.pace.internal.Utils;
import edu.mit.ll.pace.test.Matchers;
import edu.mit.ll.pace.test.TestUtils;

/**
 * Test {@link SignedScanner}.
 */
public class SignedScannerTest {

  private final static String TEST_TABLE = "test";
  private final static String SIG_TABLE = "sigs";

  private final static Authorizations authorizations = new Authorizations("admin", "secret", "top secret");

  private Map<ValueSigner,SignatureKeyContainer> aliceKeyContainers = new HashMap<>();

  @Mock
  private Connector mockConnector;

  @Mock
  private Scanner mockScanner;

  @Mock
  private Scanner mockSignatureScanner;

  @Rule
  public MockitoRule mockitoRule = MockitoJUnit.rule();

  public SignedScannerTest() throws NoSuchAlgorithmException {
    aliceKeyContainers = MockSignatureKeyContainer.getContainers("alice", "alice");
  }

  @BeforeClass
  public static void setupBouncyCastle() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void badConstructorTest() throws Exception {
    try {
      new SignedScanner(null, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
      fail("null connector not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new SignedScanner(mockConnector, null, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
      fail("null table name not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new SignedScanner(mockConnector, TEST_TABLE, null, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
      fail("null authorizations not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new SignedScanner(mockConnector, TEST_TABLE, authorizations, null, aliceKeyContainers.get(ValueSigner.RSA_PSS));
      fail("null crypto config not allowed");
    } catch (IllegalArgumentException e) { /* expected */}

    try {
      new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), null);
      fail("null key container not allowed");
    } catch (IllegalArgumentException e) { /* expected */}
  }

  @Test
  public void constructorTest() throws Exception {
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
    verify(mockConnector).createScanner(TEST_TABLE, authorizations);
    verify(mockConnector, never()).createScanner(SIG_TABLE, authorizations);
  }

  @Test
  public void constructorExternalTest() throws Exception {
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
    verify(mockConnector).createScanner(TEST_TABLE, authorizations);
    verify(mockConnector).createScanner(SIG_TABLE, authorizations);
  }

  @Test
  public void iteratorTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);

    EntrySigner signer = new EntrySigner(getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
    List<Entry<Key,Value>> entries = new ArrayList<>();
    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));
    entries.add(signer.sign(entry, true));
    entries.add(signer.sign(entry2, true));
    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());

    Scanner scanner = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS));
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    Iterator<Entry<Key,Value>> iterator = scanner.iterator();
    assertThat("correct item", iterator.next(), Matchers.equalTo(entry));
    assertThat("correct item", iterator.next(), Matchers.equalTo(entry2));
  }

  @Test
  public void iteratorExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);

    EntrySigner signer = new EntrySigner(getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.ECDSA));
    List<Entry<Key,Value>> entries = new ArrayList<>();
    List<Entry<Key,Value>> signedEntries = new ArrayList<>();

    Map.Entry<Key,Value> entry = new SimpleImmutableEntry<>(new Key(new byte[] {1}, new byte[] {2}, new byte[] {3},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {4}));
    Map.Entry<Key,Value> entry2 = new SimpleImmutableEntry<>(new Key(new byte[] {5}, new byte[] {6}, new byte[] {7},
        "secret".getBytes(Utils.VISIBILITY_CHARSET), 0, false, false), new Value(new byte[] {8}));

    entries.add(entry);
    entries.add(entry2);
    signedEntries.add(signer.sign(entry, true));
    signedEntries.add(signer.sign(entry2, true));

    when(mockScanner.iterator()).thenReturn(entries.iterator()).thenReturn(entries.iterator());
    when(mockSignatureScanner.iterator()).thenReturn(signedEntries.iterator()).thenReturn(signedEntries.iterator());

    Scanner scanner = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.ECDSA));
    assertThat("has correct number of elements", scanner, iterableWithSize(2));

    Iterator<Entry<Key,Value>> iterator = scanner.iterator();
    assertThat("correct item", iterator.next(), Matchers.equalTo(entry));
    assertThat("correct item", iterator.next(), Matchers.equalTo(entry2));
  }

  @Test
  public void addScanIteratorTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    IteratorSetting test = new IteratorSetting(10, "test", "test2");
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).addScanIterator(test);
    verify(mockScanner).addScanIterator(test);
  }

  @Test
  public void addScanIteratorExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    IteratorSetting test = new IteratorSetting(10, "test", "test2");
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).addScanIterator(test);
    verify(mockScanner).addScanIterator(test);
    verify(mockSignatureScanner).addScanIterator(test);
  }

  @Test
  public void clearColumns() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).clearColumns();
    verify(mockScanner).clearColumns();
  }

  @Test
  public void clearExternalColumns() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).clearColumns();
    verify(mockScanner).clearColumns();
    verify(mockSignatureScanner).clearColumns();
  }

  @Test
  public void clearScanIteratorsTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).clearScanIterators();
    verify(mockScanner).clearScanIterators();
  }

  @Test
  public void clearScanIteratorsExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).clearScanIterators();
    verify(mockScanner).clearScanIterators();
    verify(mockSignatureScanner).clearScanIterators();
  }

  @Test
  public void closeTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).close();
    verify(mockScanner).close();
  }

  @Test
  public void closeExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).close();
    verify(mockScanner).close();
    verify(mockSignatureScanner).close();
  }

  @Test
  public void fetchColumnTest() throws Exception {
    Column column = new Column(new Text(new byte[] {1}), new Text(new byte[] {2}));
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).fetchColumn(column);
    verify(mockScanner).fetchColumn(column);
  }

  @Test
  public void fetchColumnExternalTest() throws Exception {
    Column column = new Column(new Text(new byte[] {1}), new Text(new byte[] {2}));
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).fetchColumn(column);
    verify(mockScanner).fetchColumn(column);
    verify(mockSignatureScanner).fetchColumn(column);
  }

  @Test
  public void fetchColumn2Test() throws Exception {
    Text colF = new Text(new byte[] {1}), colQ = new Text(new byte[] {2});
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).fetchColumn(colF, colQ);
    verify(mockScanner).fetchColumn(colF, colQ);
  }

  @Test
  public void fetchColumn2ExternalTest() throws Exception {
    Text colF = new Text(new byte[] {1}), colQ = new Text(new byte[] {2});
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).fetchColumn(colF, colQ);
    verify(mockScanner).fetchColumn(colF, colQ);
    verify(mockSignatureScanner).fetchColumn(colF, colQ);
  }

  @Test
  public void fetchColumnFamilyTest() throws Exception {
    Text colF = new Text(new byte[] {1});
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).fetchColumnFamily(colF);
    verify(mockScanner).fetchColumnFamily(colF);
  }

  @Test
  public void fetchColumnFamilyExternalTest() throws Exception {
    Text colF = new Text(new byte[] {1});
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).fetchColumnFamily(colF);
    verify(mockScanner).fetchColumnFamily(colF);
    verify(mockSignatureScanner).fetchColumnFamily(colF);
  }

  @Test
  public void getAuthorizationsTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockScanner.getAuthorizations()).thenReturn(authorizations);
    Authorizations auths = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .getAuthorizations();
    verify(mockScanner).getAuthorizations();
    assertThat("correct authorizations returned", auths, equalTo(authorizations));
  }

  @Test
  public void getSamplerConfigurationTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    SamplerConfiguration config = new SamplerConfiguration("test");
    when(mockScanner.getSamplerConfiguration()).thenReturn(config);
    SamplerConfiguration value = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"),
        aliceKeyContainers.get(ValueSigner.RSA_PSS)).getSamplerConfiguration();
    verify(mockScanner).getSamplerConfiguration();
    assertThat("correct config returned", value, equalTo(config));
  }

  @Test
  public void setSamplerConfigurationTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    SamplerConfiguration config = new SamplerConfiguration("test");
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .setSamplerConfiguration(config);
    verify(mockScanner).setSamplerConfiguration(config);
  }

  @Test
  public void setSamplerConfigurationExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    SamplerConfiguration config = new SamplerConfiguration("test");
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .setSamplerConfiguration(config);
    verify(mockScanner).setSamplerConfiguration(config);
    verify(mockSignatureScanner).setSamplerConfiguration(config);
  }

  @Test
  public void clearSamplerConfigurationTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .clearSamplerConfiguration();
    verify(mockScanner).clearSamplerConfiguration();
  }

  @Test
  public void clearSamplerConfigurationExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .clearSamplerConfiguration();
    verify(mockScanner).clearSamplerConfiguration();
    verify(mockSignatureScanner).clearSamplerConfiguration();
  }

  @Test
  public void setBatchTimeoutTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setBatchTimeout(5L,
        TimeUnit.DAYS);
    verify(mockScanner).setBatchTimeout(5L, TimeUnit.DAYS);
  }

  @Test
  public void setBatchTimeoutExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setBatchTimeout(5L,
        TimeUnit.DAYS);
    verify(mockScanner).setBatchTimeout(5L, TimeUnit.DAYS);
    verify(mockSignatureScanner).setBatchTimeout(5L, TimeUnit.DAYS);
  }

  @Test
  public void getBatchTimeoutTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockScanner.getBatchTimeout(TimeUnit.DAYS)).thenReturn(5L);
    long value = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .getBatchTimeout(TimeUnit.DAYS);
    verify(mockScanner).getBatchTimeout(TimeUnit.DAYS);
    assertThat("correct timeout returned", value, is(5L));
  }

  @Test
  public void setClassLoaderContextTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .setClassLoaderContext("test");
    verify(mockScanner).setClassLoaderContext("test");
  }

  @Test
  public void setClassLoaderContextExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .setClassLoaderContext("test");
    verify(mockScanner).setClassLoaderContext("test");
    verify(mockSignatureScanner).setClassLoaderContext("test");
  }

  @Test
  public void clearClassLoaderContextTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .clearClassLoaderContext();
    verify(mockScanner).clearClassLoaderContext();
  }

  @Test
  public void clearClassLoaderContextExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .clearClassLoaderContext();
    verify(mockScanner).clearClassLoaderContext();
    verify(mockSignatureScanner).clearClassLoaderContext();
  }

  @Test
  public void getClassLoaderContextTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockScanner.getClassLoaderContext()).thenReturn("test");
    String value = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .getClassLoaderContext();
    verify(mockScanner).getClassLoaderContext();
    assertThat("correct class loader context returned", value, is("test"));
  }

  @Test
  public void getTimeoutTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockScanner.getTimeout(TimeUnit.DAYS)).thenReturn(5L);
    Long value = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .getTimeout(TimeUnit.DAYS);
    verify(mockScanner).getTimeout(TimeUnit.DAYS);
    assertThat("correct timeout returned", value, is(5L));
  }

  @Test
  public void removeScanIteratorTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .removeScanIterator("test");
    verify(mockScanner).removeScanIterator("test");
  }

  @Test
  public void removeScanIteratorExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .removeScanIterator("test");
    verify(mockScanner).removeScanIterator("test");
    verify(mockSignatureScanner).removeScanIterator("test");
  }

  @Test
  public void updateScanIteratorOptionTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .updateScanIteratorOption("test", "a", "b");
    verify(mockScanner).updateScanIteratorOption("test", "a", "b");
  }

  @Test
  public void updateScanIteratorOptionExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .updateScanIteratorOption("test", "a", "b");
    verify(mockScanner).updateScanIteratorOption("test", "a", "b");
    verify(mockSignatureScanner).updateScanIteratorOption("test", "a", "b");
  }

  @Test
  public void setTimeoutTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setTimeout(5L,
        TimeUnit.DAYS);
    verify(mockScanner).setTimeout(5L, TimeUnit.DAYS);
  }

  @Test
  public void setTimeoutExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setTimeout(5L,
        TimeUnit.DAYS);
    verify(mockScanner).setTimeout(5L, TimeUnit.DAYS);
    verify(mockSignatureScanner).setTimeout(5L, TimeUnit.DAYS);
  }

  @Test
  public void disableIsolationTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).disableIsolation();
    verify(mockScanner).disableIsolation();
  }

  @Test
  public void disableIsolationExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).disableIsolation();
    verify(mockScanner).disableIsolation();
    verify(mockSignatureScanner).disableIsolation();
  }

  @Test
  public void enableIsolationTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).enableIsolation();
    verify(mockScanner).enableIsolation();
  }

  @Test
  public void enableIsolationExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).enableIsolation();
    verify(mockScanner).enableIsolation();
    verify(mockSignatureScanner).enableIsolation();
  }

  @Test
  public void setBatchSizeTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setBatchSize(5);
    verify(mockScanner).setBatchSize(5);
  }

  @Test
  public void setBatchSizeExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setBatchSize(5);
    verify(mockScanner).setBatchSize(5);
    verify(mockSignatureScanner).setBatchSize(5);
  }

  @Test
  public void getBatchSizeTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockScanner.getBatchSize()).thenReturn(5);
    int value = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .getBatchSize();
    verify(mockScanner).getBatchSize();
    assertThat("correct batch size returned", value, is(5));
  }

  @Test
  public void setRangeTest() throws Exception {
    Range range = new Range("test");
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setRange(range);
    verify(mockScanner).setRange(range);
  }

  @Test
  public void setRangeExternalTest() throws Exception {
    Range range = new Range("test");
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setRange(range);
    verify(mockScanner).setRange(range);
    verify(mockSignatureScanner).setRange(range);
  }

  @Test
  public void getRangeTest() throws Exception {
    Range range = new Range("test");
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockScanner.getRange()).thenReturn(range);
    Range value = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .getRange();
    verify(mockScanner).getRange();
    assertThat("correct range returned", value, equalTo(range));
  }

  @Test
  public void setReadaheadThresholdTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .setReadaheadThreshold(5L);
    verify(mockScanner).setReadaheadThreshold(5L);
  }

  @Test
  public void setReadaheadThresholdExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .setReadaheadThreshold(5L);
    verify(mockScanner).setReadaheadThreshold(5L);
    verify(mockSignatureScanner).setReadaheadThreshold(5L);
  }

  @Test
  public void getReadaheadThresholdTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockScanner.getReadaheadThreshold()).thenReturn(5L);
    long value = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .getReadaheadThreshold();
    verify(mockScanner).getReadaheadThreshold();
    assertThat("correct threshold returned", value, is(5L));
  }

  @Test
  @SuppressWarnings("deprecation")
  public void setTimeOutTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setTimeOut(5);
    verify(mockScanner).setTimeOut(5);
  }

  @Test
  @SuppressWarnings("deprecation")
  public void setTimeOutExternalTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockConnector.createScanner(SIG_TABLE, authorizations)).thenReturn(mockSignatureScanner);
    new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config3.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS)).setTimeOut(5);
    verify(mockScanner).setTimeOut(5);
    verify(mockSignatureScanner).setTimeOut(5);
  }

  @Test
  @SuppressWarnings("deprecation")
  public void getTimeOutTest() throws Exception {
    when(mockConnector.createScanner(TEST_TABLE, authorizations)).thenReturn(mockScanner);
    when(mockScanner.getTimeOut()).thenReturn(5);
    int value = new SignedScanner(mockConnector, TEST_TABLE, authorizations, getConfig("config1.ini"), aliceKeyContainers.get(ValueSigner.RSA_PSS))
        .getTimeOut();
    verify(mockScanner).getTimeOut();
    assertThat("correct timeout returned", value, is(5));
  }

  /**
   * Get an signor config.
   *
   * @param resource
   *          Resource file containing the configuration.
   * @return EncryptionConfig.
   */
  private SignatureConfig getConfig(String resource) throws Exception {
    return new SignatureConfigBuilder().readFromFile(new InputStreamReader(TestUtils.getResourceAsStream(this.getClass(), resource))).build();
  }

}
