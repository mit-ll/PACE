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

import org.apache.accumulo.core.cli.ClientOpts;
import org.apache.accumulo.core.client.Durability;

import com.beust.jcommander.Parameter;

import edu.mit.ll.pace.examples.simple.Converters.DurabilityConverter;

/**
 * Opts for the read/write examples.
 */
class ConverterOpts extends ClientOpts {
  @Parameter(names = {"--source"}, description = "source table", required = true)
  String source;
  @Parameter(names = {"--destination"}, description = "destination table", required = true)
  String destination;
  @Parameter(names = {"-C", "--createtable"}, description = "create destination table")
  boolean createDestinationTable = false;
  @Parameter(names = {"-D", "--deletetable"}, description = "delete source table when finished")
  boolean deleteSourceTable = false;
  @Parameter(names = {"--durability"}, description = "durability used for writes (none, log, flush or sync)", converter = DurabilityConverter.class)
  Durability durability = Durability.DEFAULT;
}
