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
package edu.mit.ll.pace.authentication;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;
import static org.junit.Assert.assertThat;

import org.apache.accumulo.core.data.Key;
import org.apache.hadoop.io.Text;
import org.junit.Test;

import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

/**
 * Tests for {@link SkipList}.
 */
public class SkipListTest {

  private static final SkipListElement APPLE = new SkipListElement(new Key(new Text("Apple")), new byte[] {1});
  private static final SkipListElement BANANA = new SkipListElement(new Key(new Text("Banana")), new byte[] {2});
  private static final SkipListElement CHERRY = new SkipListElement(new Key(new Text("Cherry")), new byte[] {3});
  private static final SkipListElement DAIKON = new SkipListElement(new Key(new Text("Daikon")), new byte[] {4});
  private static final SkipListElement EGGPLANT = new SkipListElement(new Key(new Text("Eggplant")), new byte[] {5});
  private static final SkipListElement FIG = new SkipListElement(new Key(new Text("Fig")), new byte[] {6});
  private final Random rand = new Random();

  @Test
  public void testInsert() {
    SkipList list = new SkipList();

    list.insert(BANANA, rand.nextInt(4) + 1);
    assertThat("map is correct", list, contains(BANANA));

    list.insert(DAIKON, rand.nextInt(4) + 1);
    assertThat("map is correct", list, contains(BANANA, DAIKON));

    list.insert(APPLE, rand.nextInt(4) + 1);
    assertThat("map is correct", list, contains(APPLE, BANANA, DAIKON));

    list.insert(CHERRY, rand.nextInt(4) + 1);
    assertThat("map is correct", list, contains(APPLE, BANANA, CHERRY, DAIKON));

    assertThat("map is correct", list, contains(APPLE, BANANA, CHERRY, DAIKON));
  }

  @Test
  public void testContains() {
    SkipList list = new SkipList();
    list.insert(BANANA, rand.nextInt(4) + 1);
    list.insert(APPLE, rand.nextInt(4) + 1);
    list.insert(DAIKON, rand.nextInt(4) + 1);

    assertThat("apple is in the list", list.search(APPLE.key).success(), is(true));
    assertThat("banana is in the list", list.search(BANANA.key).success(), is(true));
    assertThat("cherry is not in the list", list.search(CHERRY.key).success(), is(false));
    assertThat("daikon is in the list", list.search(DAIKON.key).success(), is(true));
  }

  @Test
  public void testRange() {
    SkipList list = new SkipList();
    list.insert(APPLE, rand.nextInt(4) + 1);
    list.insert(BANANA, rand.nextInt(4) + 1);
    list.insert(CHERRY, rand.nextInt(4) + 1);
    list.insert(DAIKON, rand.nextInt(4) + 1);
    list.insert(EGGPLANT, rand.nextInt(4) + 1);
    list.insert(FIG, rand.nextInt(4) + 1);

    List<String> result = list.inclusiveRange(BANANA.key, EGGPLANT.key).getFound().stream().map(node -> node.getElement().key.getRow().toString())
        .collect(Collectors.toList());

    assertThat("banana was found", result.contains("Banana"), is(true));
    assertThat("cherry was found", result.contains("Cherry"), is(true));
    assertThat("daikon was found", result.contains("Daikon"), is(true));
    assertThat("eggplant was found", result.contains("Eggplant"), is(true));
    assertThat("apple was not found", result.contains("Apple"), is(false));
    assertThat("fig was not found", result.contains("Fig"), is(false));
  }
}
