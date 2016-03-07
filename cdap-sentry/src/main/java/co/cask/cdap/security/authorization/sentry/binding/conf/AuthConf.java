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

package co.cask.cdap.security.authorization.sentry.binding.conf;

import co.cask.cdap.security.authorization.sentry.policy.SimplePolicyEngine;
import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.provider.common.HadoopGroupResourceAuthorizationProvider;
import org.apache.sentry.provider.db.generic.SentryGenericProviderBackend;

import java.net.URL;

/**
 * Authorization Configurations used for Sentry binding
 */
public class AuthConf extends Configuration {

  // sentry-site.xml path
  public static final String SENTRY_SITE_URL = "sentry.cdap.site.url";
  // cdap instance name to be used in sentry for example: cdap
  public static final String SERVICE_INSTANCE_NAME = "sentry.cdap.service.instance";
  // cdap username to be used in sentry for example: cdap
  public static final String SERVICE_USER_NAME = "sentry.cdap.service.user.name";

  /**
   * Config setting definitions
   */
  public enum AuthzConfVars {
    AUTHZ_PROVIDER("sentry.cdap.provider", HadoopGroupResourceAuthorizationProvider.class.getName()),
    //TODO: This might not be even needed. At the end of integration remove it if there's no use for it.
    AUTHZ_PROVIDER_RESOURCE("sentry.cdap.provider.resource", ""),
    AUTHZ_PROVIDER_BACKEND("sentry.cdap.provider.backend", SentryGenericProviderBackend.class.getName()),
    AUTHZ_POLICY_ENGINE("sentry.kafka.policy.engine", SimplePolicyEngine.class.getName()),
    // if no instanceName or username is provided 'cdap' will be used
    AUTHZ_INSTANCE_NAME(SERVICE_INSTANCE_NAME, "cdap"),
    AUTHZ_SERVICE_USER_NAME(SERVICE_USER_NAME, "cdap");

    private final String varName;
    private final String defaultVal;

    AuthzConfVars(String varName, String defaultVal) {
      this.varName = varName;
      this.defaultVal = defaultVal;
    }

    public String getVar() {
      return varName;
    }

    public String getDefault() {
      return defaultVal;
    }

    public static String getDefault(String varName) {
      for (AuthzConfVars oneVar : AuthzConfVars.values()) {
        if (oneVar.getVar().equalsIgnoreCase(varName)) {
          return oneVar.getDefault();
        }
      }
      return null;
    }
  }

  public AuthConf(URL kafkaAuthzSiteURL) {
    super(true);
    addResource(kafkaAuthzSiteURL);
  }

  @Override
  public String get(String varName) {
    return get(varName, AuthzConfVars.getDefault(varName));
  }
}