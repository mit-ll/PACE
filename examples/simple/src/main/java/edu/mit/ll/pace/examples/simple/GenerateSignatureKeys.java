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
package edu.mit.ll.pace.examples.simple;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.apache.accumulo.core.cli.Help;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.FileConverter;

import edu.mit.ll.pace.keymanagement.LocalSignatureKeyContainer;
import edu.mit.ll.pace.signature.ValueSigner;

public class GenerateSignatureKeys {

  /**
   * The encoding to use in serializing IDs.
   */
  private static final Charset ENCODING_CHARSET = StandardCharsets.UTF_8;

  private static TreeSet<String> VALID_ALGORITHMS = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
  static {
    for (ValueSigner signer : ValueSigner.values()) {
      VALID_ALGORITHMS.add(signer.getKeyGenerationAlgorithm());
    }
  }

  static class KeyArgs {
    final String userId;
    final String algorithm;
    final int keyLength;

    KeyArgs(String userName, String algorithm, int keyLength) {
      this.userId = userName;
      this.algorithm = algorithm;
      this.keyLength = keyLength;
    }
  }

  public static class KeyArgsConverter implements IStringConverter<KeyArgs> {
    @Override
    public KeyArgs convert(String value) {
      String[] args = value.split("(?<!\\\\)\\|");
      if (args.length != 3) {
        throw new IllegalArgumentException("invalid key description: " + value);
      }

      if (!VALID_ALGORITHMS.contains(args[1])) {
        throw new IllegalArgumentException("invalid algorithm: " + value + ". Choose one of (" + StringUtils.join(VALID_ALGORITHMS, ",") + ").");
      }

      return new KeyArgs(args[0], args[1], Integer.parseInt(args[2]));
    }
  }

  static class Opts extends Help {
    @Parameter(
        names = {"--key"},
        description = "List of key pairs that should be created. The format of this variable is \"userId|algorithm|length\". Algorithm is one of"
            + " {RSA,DSA,ECDSA}, and key length is an appropriate length for the given algorithm. A key container will be created for each key listed this way,"
            + "with each container containing public keys for all other keys created.", converter = KeyArgsConverter.class)
    List<KeyArgs> keyList = new ArrayList<>();
    @Parameter(names = {"--key-dir"}, description = "directory to store the generated key store", converter = FileConverter.class, required = true)
    File keyStoreDirectory = null;
    @Parameter(names = {"--public-key-file"}, description = "the location of file containing all public keys", converter = FileConverter.class)
    File publicKeyFile = null;
    @Parameter(names = {"--update"}, description = "if set, will update the key stores in the given directories to include the current set of public keys")
    boolean update = false;
  }

  public static void main(String[] args) {
    // Register Bouncy castle, as it will be used to generate signature keys.
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    Opts opts = new Opts();
    opts.parseArgs(GenerateSignatureKeys.class.getName(), args);

    // Add public keys from the file.
    Set<Pair<byte[],PublicKey>> publicKeys = new TreeSet<>();
    if (opts.publicKeyFile != null && opts.publicKeyFile.exists()) {
      try {
        InputStream inputStream = new FileInputStream(opts.publicKeyFile);
        DataInput input = new DataInputStream(inputStream);
        int count = input.readInt();

        for (int i = 0; i < count; i++) {
          byte[] keyId = new byte[input.readInt()];
          input.readFully(keyId);
          byte[] algorithm = new byte[input.readInt()];
          input.readFully(algorithm);
          byte[] keyData = new byte[input.readInt()];
          input.readFully(keyData);

          KeyFactory factory = KeyFactory.getInstance(new String(algorithm, ENCODING_CHARSET));
          publicKeys.add(Pair.of(keyId, factory.generatePublic(new X509EncodedKeySpec(keyData))));
        }

        inputStream.close();
      } catch (InvalidKeySpecException | IOException | NoSuchAlgorithmException e) {
        throw new IllegalArgumentException("public key file is invalid", e);
      }
    }

    // Read in the existing key pairs
    List<LocalSignatureKeyContainer> containers = new ArrayList<>();
    if (opts.update) {
      for (File storeFile : FileUtils.listFiles(opts.keyStoreDirectory, new String[] {"keys"}, false)) {
        try {
          containers.add(LocalSignatureKeyContainer.read(new FileReader(storeFile)));
        } catch (Exception e) {
          System.out.println("ignoring file—unable to parse a signature key store from file " + storeFile.getPath());
          // Ignore exceptions, as directory might contain files that are not key key containers.
        }
      }
    }

    // Generate new key pairs.
    for (KeyArgs keyArg : opts.keyList) {
      try {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(keyArg.algorithm);
        gen.initialize(keyArg.keyLength);

        KeyPair pair = gen.generateKeyPair();
        byte[] keyId = String.format("%s_%s", keyArg.userId, gen.getAlgorithm()).getBytes(ENCODING_CHARSET);
        containers.add(new LocalSignatureKeyContainer(pair, keyId));
        publicKeys.add(Pair.of(keyId, pair.getPublic()));
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalArgumentException("invalid algorithm", e);
      }
    }

    // Write public keys to the public key file.
    if (opts.publicKeyFile != null) {
      try {
        if (!opts.publicKeyFile.exists()) {
          if (!opts.publicKeyFile.createNewFile()) {
            throw new IllegalArgumentException("unable to create file " + opts.publicKeyFile.toPath().toAbsolutePath().toString());
          }
        }

        OutputStream outputStream = new FileOutputStream(opts.publicKeyFile);
        DataOutput output = new DataOutputStream(outputStream);
        output.writeInt(publicKeys.size());

        for (Pair<byte[],PublicKey> publicKey : publicKeys) {
          byte[] keyId = publicKey.getLeft();
          output.writeInt(keyId.length);
          output.write(keyId);

          PublicKey key = publicKey.getRight();
          byte[] algorithm = key.getAlgorithm().getBytes(ENCODING_CHARSET);
          output.writeInt(algorithm.length);
          output.write(algorithm);

          byte[] keyData = key.getEncoded();
          output.writeInt(keyData.length);
          output.write(keyData);
        }

        outputStream.close();
      } catch (IOException e) {
        throw new IllegalArgumentException("bad public key file", e);
      }
    }

    // Add the public keys to each container, then write to disk.
    if (!opts.keyStoreDirectory.exists()) {
      if (!opts.keyStoreDirectory.mkdirs()) {
        throw new IllegalArgumentException("unable to create store directory " + opts.keyStoreDirectory.toPath().toAbsolutePath().toString());
      }
    }

    for (LocalSignatureKeyContainer container : containers) {
      for (Pair<byte[],PublicKey> publicKey : publicKeys) {
        container.addVerifierKey(publicKey.getRight(), publicKey.getLeft());
      }

      Path fileName = null;
      try {
        fileName = Paths.get(opts.keyStoreDirectory.getAbsolutePath(), new String(container.getSigningKey().id, ENCODING_CHARSET) + ".keys");
        FileWriter writer = new FileWriter(fileName.toFile());
        container.write(writer);
        writer.close();
      } catch (IOException e) {
        throw new IllegalArgumentException("unable to create file with name: " + fileName.toString(), e);
      }
    }
  }

}
