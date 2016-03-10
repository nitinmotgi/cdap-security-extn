/*
 * Copyright © 2016 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package co.cask.cdap.security.authorization.sentry.binding;

import com.google.common.collect.Lists;
import org.apache.hadoop.security.GroupMappingServiceProvider;

import java.io.IOException;
import java.util.List;

public class MockGroupMappingServiceProvider implements GroupMappingServiceProvider {

  public MockGroupMappingServiceProvider() {
  }

  @Override
  public List<String> getGroups(String group) throws IOException {
    return Lists.newArrayList(group);
  }

  @Override
  public void cacheGroupsRefresh() throws IOException {
  }

  @Override
  public void cacheGroupsAdd(List<String> groups) throws IOException {
  }
}
