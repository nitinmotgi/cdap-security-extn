/*
 * Copyright 2016 Cask Data, Inc.
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

package co.cask.cdap.security.authorization.sentry.model;

import javax.annotation.Nullable;

/**
 * Represents authorizable resources.
 */
public interface Authorizable extends org.apache.sentry.core.common.Authorizable {

  /**
   * Enum of different {@link Authorizable}
   */
  enum AuthorizableType {
    INSTANCE,
    NAMESPACE,
    ARTIFACT,
    APPLICATION,
    PROGRAM,
    DATASET,
    DATASET_MODULE,
    DATASET_TYPE,
    STREAM,
    SECUREKEY
  }

  AuthorizableType getAuthzType();

  /**
   * @return the sub type of the entity, if any or null
   */
  @Nullable
  String getSubType();
}
