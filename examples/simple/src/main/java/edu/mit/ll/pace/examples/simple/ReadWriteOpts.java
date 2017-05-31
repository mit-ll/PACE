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

import org.apache.accumulo.core.cli.ClientOnDefaultTable;
import org.apache.accumulo.core.client.Durability;
import org.apache.accumulo.core.security.Authorizations;

import com.beust.jcommander.Parameter;

import edu.mit.ll.pace.examples.simple.Converters.DurabilityConverter;

/**
 * Opts for the read/write examples.
 */
class ReadWriteOpts extends ClientOnDefaultTable {
  // defaults
  private static final String DEFAULT_AUTHS = "secret,default";
  private static final String DEFAULT_TABLE_NAME = "test";

  @Parameter(names = {"-C", "--createtable"}, description = "create table before doing anything")
  boolean createtable = false;
  @Parameter(names = {"-D", "--deletetable"}, description = "delete table when finished")
  boolean deletetable = false;
  @Parameter(names = {"-c", "--create"}, description = "create entries before any deletes")
  boolean createEntries = false;
  @Parameter(names = {"-r", "--read"}, description = "read entries after any creates/deletes")
  boolean readEntries = false;
  @Parameter(names = {"-d", "--delete"}, description = "delete entries after any creates")
  boolean deleteEntries = false;
  @Parameter(names = {"--durability"}, description = "durability used for writes (none, log, flush or sync)", converter = DurabilityConverter.class)
  Durability durability = Durability.DEFAULT;

  public ReadWriteOpts() {
    super(DEFAULT_TABLE_NAME);
    this.auths = new Authorizations(DEFAULT_AUTHS.split(","));
  }
}
