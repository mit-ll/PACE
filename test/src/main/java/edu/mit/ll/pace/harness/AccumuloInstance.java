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

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.apache.accumulo.core.client.AccumuloException;
import org.apache.accumulo.core.client.AccumuloSecurityException;
import org.apache.accumulo.core.client.Connector;
import org.apache.accumulo.core.client.Instance;
import org.apache.accumulo.core.client.TableExistsException;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.client.ZooKeeperInstance;
import org.apache.accumulo.core.client.admin.SecurityOperations;
import org.apache.accumulo.core.client.admin.TableOperations;
import org.apache.accumulo.core.client.security.tokens.PasswordToken;
import org.apache.accumulo.core.security.TablePermission;
import org.apache.accumulo.minicluster.MiniAccumuloCluster;
import org.apache.commons.io.FileUtils;

import com.google.common.io.Files;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Class that wraps an Accumulo instance setup for testing.
 */
public class AccumuloInstance {

  /**
   * Name of the admin user.
   */
  private static String adminUsername = "root";

  /**
   * Name of the admin user.
   */
  private static String adminPassword = "rootPassword";

  /**
   * Zookeeper instance used to get connections.
   */
  private static Instance instance;

  /**
   * The directory storing the mini Accumulo instance.
   */
  private static File tempDirectory;

  /**
   * MiniAccumuloCluster that is spun up to provide an Accumulo instance.
   */
  private static MiniAccumuloCluster cluster;

  /**
   * The number of entities that have called {@link #setup()} on this method.
   */
  private static int instanceCount = 0;

  /**
   * Setup the Accumulo instance.
   */
  public static synchronized void setup() throws AccumuloException, AccumuloSecurityException, InterruptedException, InvalidKeySpecException, IOException,
      NoSuchAlgorithmException {
    if (instance != null) {
      instanceCount++;
      return;
    }

    // Read the configuration.
    JsonParser parser = new JsonParser();
    JsonObject config = parser.parse(new InputStreamReader(AccumuloInstance.class.getResourceAsStream("accumulo.json"))).getAsJsonObject();
    String configType = config.getAsJsonPrimitive("type").getAsString();

    JsonObject adminConfig = config.getAsJsonObject("admin");
    adminUsername = adminConfig.getAsJsonPrimitive("username").getAsString();
    adminPassword = adminConfig.getAsJsonPrimitive("password").getAsString();

    // Instantiate the data based on the configuration.
    switch (configType) {
      case "AccumuloInstance":
        String instanceName = config.getAsJsonPrimitive("instanceName").getAsString();
        String zookeepers = config.getAsJsonPrimitive("zooKeepers").getAsString();
        instance = new ZooKeeperInstance(instanceName, zookeepers);
        break;

      case "MiniAccumuloCluster":
        tempDirectory = Files.createTempDir();
        tempDirectory.deleteOnExit();

        cluster = new MiniAccumuloCluster(tempDirectory, adminPassword);
        cluster.start();
        instance = new ZooKeeperInstance(cluster.getInstanceName(), cluster.getZooKeepers());

        Connector connector = getConnector();
        SecurityOperations secOps = connector.securityOperations();
        for (User user : User.getUsers().values()) {
          secOps.createLocalUser(user.id, new PasswordToken(user.password));
          secOps.changeUserAuthorizations(user.id, user.authorizations);
        }
        break;

      default:
        throw new IllegalStateException("invalid accumulo configuration type");
    }

    instanceCount++;
  }

  /**
   * Teardown the current accumulo instance.
   */
  public static synchronized void teardown() throws InterruptedException, IOException {
    instanceCount--;
    if (instanceCount > 0) {
      return;
    }

    if (cluster != null) {
      cluster.stop();
      FileUtils.deleteDirectory(tempDirectory);
    }

    instance = null;
    cluster = null;
    tempDirectory = null;
  }

  /**
   * Get an Accumulo instance.
   *
   * @return The Accumulo instance.
   */
  public static synchronized Instance getInstance() {
    return instance;
  }

  /**
   * Get a connector for root.
   *
   * @return An Accumulo connector.
   */
  public static synchronized Connector getConnector() throws AccumuloException, AccumuloSecurityException {
    return instance.getConnector(adminUsername, new PasswordToken(adminPassword));
  }

  /**
   * Get a connector for the given user.
   *
   * @param user
   *          User to get connector for.
   * @return An Accumulo connector.
   */
  public static synchronized Connector getConnector(String user) throws AccumuloException, AccumuloSecurityException {
    return instance.getConnector(getUser(user).id, new PasswordToken(getUser(user).password));
  }

  /**
   * Get a user.
   *
   * @param user
   *          The user name.
   * @return The user object.
   */
  public static synchronized User getUser(String user) {
    return User.getUsers().get(user);
  }

  /**
   * Creates a table and gives all users read-write access to that table.
   *
   * @param tableName
   *          name of the table.
   */
  public static synchronized void createTable(String tableName) throws AccumuloException, AccumuloSecurityException, TableExistsException {
    Connector connector = getConnector();
    TableOperations tableOps = connector.tableOperations();
    tableOps.create(tableName);

    SecurityOperations secOps = connector.securityOperations();
    for (User user : User.getUsers().values()) {
      secOps.grantTablePermission(user.id, tableName, TablePermission.READ);
      secOps.grantTablePermission(user.id, tableName, TablePermission.WRITE);
      secOps.grantTablePermission(user.id, tableName, TablePermission.BULK_IMPORT);
    }
  }

  /**
   * Delete the indicated table.
   *
   * @param tableName
   *          Name of the table to delete.
   */
  public static synchronized void deleteTable(String tableName) throws AccumuloException, AccumuloSecurityException, TableNotFoundException {
    Connector connector = getConnector();
    TableOperations tableOps = connector.tableOperations();
    tableOps.delete(tableName);
  }

  /**
   * Clear the indicated table.
   *
   * @param tableName
   *          Name of the table to clear.
   */
  public static synchronized void clearTable(String tableName) throws AccumuloException, AccumuloSecurityException, TableNotFoundException {
    Connector connector = getConnector();
    TableOperations tableOps = connector.tableOperations();
    tableOps.deleteRows(tableName, null, null);
  }
}
