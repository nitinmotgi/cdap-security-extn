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

package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.proto.element.EntityType;
import co.cask.cdap.proto.id.ApplicationId;
import co.cask.cdap.proto.id.ArtifactId;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.DatasetModuleId;
import co.cask.cdap.proto.id.DatasetTypeId;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.InstanceId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.ProgramId;
import co.cask.cdap.proto.id.SecureKeyId;
import co.cask.cdap.proto.id.StreamId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf.AuthzConfVars;
import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import co.cask.cdap.security.authorization.sentry.model.Application;
import co.cask.cdap.security.authorization.sentry.model.Artifact;
import co.cask.cdap.security.authorization.sentry.model.Authorizable;
import co.cask.cdap.security.authorization.sentry.model.Dataset;
import co.cask.cdap.security.authorization.sentry.model.DatasetModule;
import co.cask.cdap.security.authorization.sentry.model.DatasetType;
import co.cask.cdap.security.authorization.sentry.model.Instance;
import co.cask.cdap.security.authorization.sentry.model.Namespace;
import co.cask.cdap.security.authorization.sentry.model.Program;
import co.cask.cdap.security.authorization.sentry.model.SecureKey;
import co.cask.cdap.security.authorization.sentry.model.Stream;
import co.cask.cdap.security.authorization.sentry.policy.ModelAuthorizables;
import co.cask.cdap.security.authorization.sentry.policy.PrivilegeValidator;
import co.cask.cdap.security.spi.authorization.AlreadyExistsException;
import co.cask.cdap.security.spi.authorization.BadRequestException;
import co.cask.cdap.security.spi.authorization.NotFoundException;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;
import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.policy.common.PolicyEngine;
import org.apache.sentry.provider.common.AuthorizationProvider;
import org.apache.sentry.provider.common.ProviderBackend;
import org.apache.sentry.provider.db.SentryAccessDeniedException;
import org.apache.sentry.provider.db.SentryAlreadyExistsException;
import org.apache.sentry.provider.db.SentryInvalidInputException;
import org.apache.sentry.provider.db.SentryNoSuchObjectException;
import org.apache.sentry.provider.db.SentryThriftAPIMismatchException;
import org.apache.sentry.provider.db.generic.SentryGenericProviderBackend;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClient;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClientFactory;
import org.apache.sentry.provider.db.generic.service.thrift.TAuthorizable;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryGrantOption;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryPrivilege;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryRole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;

/**
 * This class instantiate the {@link AuthorizationProvider} configured in {@link AuthConf} and is responsible for
 * performing different authorization operation on CDAP entities by mapping them to authorizables
 * {@link #toSentryAuthorizables(EntityId)}
 */
class AuthBinding {
  private static final Logger LOG = LoggerFactory.getLogger(AuthBinding.class);
  private static final String COMPONENT_NAME = "cdap";
  private final AuthConf authConf;
  private final AuthorizationProvider authProvider;
  private final String instanceName;
  private final String sentryAdminGroup;

  // Cache for principal to groups the principal is part of
  private final LoadingCache<Principal, Set<String>> groupCache;
  // Cache for group to set of roles the group is part of
  private final LoadingCache<String, Set<Role>> roleCache;
  // Cache for role to set of policies for the role
  private final LoadingCache<Role, Set<WildcardPolicy>> policyCache;

  AuthBinding(String sentrySite, final String instanceName, final String sentryAdminGroup,
              int cacheTtlSecs, int cacheMaxEntries) {
    this.authConf = initAuthzConf(sentrySite);
    this.instanceName = instanceName;
    this.authProvider = createAuthProvider();
    this.sentryAdminGroup = sentryAdminGroup;

    groupCache = CacheBuilder.newBuilder()
      .expireAfterWrite(cacheTtlSecs, TimeUnit.SECONDS)
      .maximumSize(cacheMaxEntries)
      .build(new CacheLoader<Principal, Set<String>>() {
        @SuppressWarnings("NullableProblems")
        @Override
        public Set<String> load(Principal principal) throws Exception {
          LOG.trace("Group cache miss for principal {}", principal);
          return fetchGroups(principal);
        }
      });

    roleCache = CacheBuilder.newBuilder()
      .expireAfterWrite(cacheTtlSecs, TimeUnit.SECONDS)
      .maximumSize(cacheMaxEntries)
      .build(new CacheLoader<String, Set<Role>>() {
        @SuppressWarnings("NullableProblems")
        @Override
        public Set<Role> load(final String group) throws Exception {
          LOG.trace("Role cache miss for group {}", group);
          return fetchRoles(group);
        }
      });

    policyCache = CacheBuilder.newBuilder()
      .expireAfterWrite(cacheTtlSecs, TimeUnit.SECONDS)
      .maximumSize(cacheMaxEntries)
      .build(new CacheLoader<Role, Set<WildcardPolicy>>() {
        @SuppressWarnings("NullableProblems")
        @Override
        public Set<WildcardPolicy> load(final Role role) throws Exception {
          LOG.trace("Policy cache miss for role {}", role);
          return fetchPolicies(role);
        }
      });
  }

  /**
   * @return policies for the given principal
   */
  Set<WildcardPolicy> getPolicies(Principal principal) throws Exception {
    Set<Role> roles = getRoles(principal, sentryAdminGroup);

    Set<WildcardPolicy> policies = new HashSet<>();
    for (Role role : roles) {
      Set<WildcardPolicy> policy = policyCache.get(role);
      policies.addAll(policy);
    }
    return Collections.unmodifiableSet(policies);
  }

  /**
   * Grants the specified {@link Action actions} on the specified {@link EntityId} to the specified {@link Role} as the
   * {@link #sentryAdminGroup}. This is used to grant privileges to the dot role created for an entity.
   *
   * @param entityId the entity on which the actions need to be granted
   * @param role the role to which the actions need to granted
   * @param actions the actions which need to be granted
   * @throws Exception when there is any exception while running the client command to grant
   */
  void grant(EntityId entityId, Role role, Set<Action> actions) throws Exception {
    grant(entityId, role, actions, sentryAdminGroup);
  }

  /**
   * Grants the specified {@link Action actions} on the specified {@link EntityId} to the specified {@link Role} as the
   * {@link #sentryAdminGroup}.
   *
   * @param entityId the entity on which the actions need to be granted
   * @param role the role to which the actions need to granted
   * @param actions the actions which need to be granted
   * @param requestingUser the user executing this operation
   * @throws Exception when there is any exception while running the client command to grant for user
   */
  void grant(final EntityId entityId, final Role role, Set<Action> actions,
             final String requestingUser) throws Exception {
    if (!roleExists(role)) {
      throw new NotFoundException(role);
    }
    LOG.debug("Granting actions {} on entity {} for role {}; Requesting user: {}",
              actions, entityId, role, requestingUser);
    for (final Action action : actions) {
      execute(new Command<Void>() {
        @Override
        public Void run(SentryGenericServiceClient client) throws Exception {
          client.grantPrivilege(requestingUser, role.getName(), COMPONENT_NAME, toTSentryPrivilege(entityId, action));
          return null;
        }
      });
    }
  }

  /**
   * Revokes a {@link Role role's} authorization to perform a set of {@link Action actions} on
   * an {@link EntityId}.
   *
   * @param entityId the {@link EntityId} whose {@link Action actions} are to be revoked
   * @param role the {@link Role} from which the actions needs to be revoked
   * @param actions the set of {@link Action actions} to revoke
   * @param requestingUser the user executing this operation
   * @throws Exception if there was any exception while running the client command for dropping privileges
   */
  void revoke(final EntityId entityId, final Role role, Set<Action> actions,
              final String requestingUser) throws Exception {
    if (!roleExists(role)) {
      throw new NotFoundException(role);
    }
    LOG.debug("Revoking actions {} on entity {} from role {}; Requesting user: {}",
              actions, entityId, role, requestingUser);
    for (final Action action : actions) {
      execute(new Command<Void>() {
        @Override
        public Void run(SentryGenericServiceClient client) throws Exception {
          client.revokePrivilege(requestingUser, role.getName(), COMPONENT_NAME, toTSentryPrivilege(entityId, action));
          return null;
        }
      });
    }
  }

  /**
   * Revoke all privileges on a CDAP entity. This is a privileged operation executed either to clean up orphaned
   * privileges on an entity before creating it, or to revoke all privileges on an entity once the entity is deleted.
   * This operation is executed as the {@link #sentryAdminGroup}.
   *
   * @param entityId the {@link EntityId} on which all privileges have to be revoked
   * @throws Exception if there was any exception while running the client command for dropping privileges
   */
  void revoke(EntityId entityId) throws Exception {
    revoke(entityId, sentryAdminGroup);
  }

  /**
   * Revokes all {@link Principal principals'} authorization to perform any {@link Action} on the given
   * {@link EntityId}.
   *
   * @param entityId the {@link EntityId} on which all {@link Action actions} are to be revoked
   * @param requestingUser the user executing this operation
   * @throws Exception if there was any exception while running the client command for dropping privileges
   */
  private void revoke(EntityId entityId, final String requestingUser) throws Exception {
    Set<Role> allRoles = listAllRoles();
    final List<TSentryPrivilege> allPrivileges = getAllPrivileges(allRoles);
    final List<TAuthorizable> tAuthorizables = toTAuthorizable(entityId);
    LOG.debug("Revoking all actions for all users from entity {}; Requesting user: {}", entityId, requestingUser);
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        for (TSentryPrivilege curPrivileges : allPrivileges) {
          if (tAuthorizables.equals(curPrivileges.getAuthorizables())) {
            // if the privilege is on same authorizables then drop it
            client.dropPrivilege(requestingUser, COMPONENT_NAME, curPrivileges);
          }
        }
        return null;
      }
    });
  }

  /**
   * Lists {@link Privilege privileges} for the given {@link Principal}
   *
   * @param principal the principal for which the privileges has to be listed
   * @return {@link Set} of {@link Privilege privilege} for the given principal
   * @throws Exception if there was any exception while running the client command getting roles and privileges
   */
  Set<Privilege> listPrivileges(Principal principal) throws Exception {
    Set<Role> roles = getRoles(principal, sentryAdminGroup);
    LOG.debug("Listing all privileges for {};", principal);
    List<TSentryPrivilege> allPrivileges = getAllPrivileges(roles);
    return toPrivileges(allPrivileges);
  }

  @VisibleForTesting
  Set<Privilege> toPrivileges(Collection<TSentryPrivilege> allPrivileges) {
    Set<Privilege> privileges = new HashSet<>();
    for (TSentryPrivilege sentryPrivilege : allPrivileges) {
      List<TAuthorizable> authorizables = sentryPrivilege.getAuthorizables();
      if (authorizables.isEmpty()) {
        continue;
      }
      EntityId parent = null;
      for (TAuthorizable authorizable : authorizables) {
        parent = toEntityId(authorizable, parent);
      }
      privileges.add(new Privilege(parent, Action.valueOf(sentryPrivilege.getAction().toUpperCase())));
    }
    return Collections.unmodifiableSet(privileges);
  }

  /**
   * Creates a role as a {@link #sentryAdminGroup}. This is necessary for creating an entity role to automatically
   * grant privileges to a {@link Principal} when he successfully creates an entity.
   *
   * @param role the role to create
   * @throws AlreadyExistsException if the role already exists
   * @throws Exception if there was any exception while running the client command for creating the role
   */
  void createRole(Role role) throws Exception {
    createRole(role, sentryAdminGroup);
  }

  /**
   * Creates the specified role.
   *
   * @param role the role to be created
   * @param requestingUser the user executing this operation
   * @throws Exception if there was any exception while running the client command for creating role for user
   */
  void createRole(final Role role, final String requestingUser) throws Exception {
    if (roleExists(role)) {
      throw new AlreadyExistsException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.createRole(requestingUser, role.getName(), COMPONENT_NAME);
        LOG.debug("Created role {}; Requesting user: {}", role, requestingUser);
        return null;
      }
    });
  }

  /**
   * Drops the specified role as the {@link #sentryAdminGroup}. This is used to drop the dot role created for an entity
   * when it was first created.
   *
   * @param role the role to drop
   * @throws Exception if there was any exception while running the client command for dropping the role
   */
  void dropRole(Role role) throws Exception {
    dropRole(role, sentryAdminGroup);
  }

  /**
   * Drops the given role.
   *
   * @param role the role to dropped
   * @param requestingUser the user executing this operation
   * @throws Exception if there was any exception while running the client command for dropping the role for user
   */
  void dropRole(final Role role, final String requestingUser) throws Exception {
    if (!roleExists(role)) {
      throw new NotFoundException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.dropRole(requestingUser, role.getName(), COMPONENT_NAME);
        LOG.debug("Dropped role {}; Requesting user: {}", role, requestingUser);
        return null;
      }
    });
  }

  /**
   * Lists roles for the given principal
   *
   * @param principal the principal for which roles need to be listed
   * @param requestingUser the user executing this operation
   * @return {@link Set} of {@link Role} to which this principal belongs to
   * @throws Exception if there was any exception while running the client command for listing roles
   */
  Set<Role> listRolesForGroup(Principal principal, final String requestingUser) throws Exception {
    return getRoles(principal, requestingUser);
  }

  /**
   * Lists all roles
   *
   * @return {@link Set} of all {@link Role}
   * @throws Exception if there were any exception while running client commdn to listing all roles
   */
  Set<Role> listAllRoles() throws Exception {
    return getRoles(null, sentryAdminGroup);
  }

  /**
   * Adds the specified role to the specified {@link Principal group} as the {@link #sentryAdminGroup}. This is used
   * to add the dot role for an entity to the creator when the entity is first created.
   *
   * @param role the dot role to add to the group
   * @param principal the group to add the dot role to
   * @throws Exception if there was any exception while running the client command for adding role to group
   */
  void addRoleToGroup(Role role, Principal principal) throws Exception {
    addRoleToGroup(role, principal, sentryAdminGroup);
  }

  /**
   * Add a role to group principal
   *
   * @param role the role which needs to be added to the group principal
   * @param principal the group principal to which the role needs to be added
   * @param requestingUser the user executing this operation
   * @throws Exception if there was any exception while running the client command for adding role to group
   */
  void addRoleToGroup(final Role role, final Principal principal,
                      final String requestingUser) throws Exception {
    if (!roleExists(role)) {
      throw new NotFoundException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.addRoleToGroups(requestingUser, role.getName(), COMPONENT_NAME,
                               ImmutableSet.of(principal.getName()));
        LOG.debug("Added role {} to group {} for the requested user {}", role, principal, requestingUser);
        return null;
      }
    });
  }

  /**
   * Removed a role from group principal
   *
   * @param role the role which needs to be removed to the group principal
   * @param principal the group principal to which the role needs to be removed
   * @param requestingUser the user executing this operation
   * @throws Exception if there was exception while running the client command to remove role from group
   */
  void removeRoleFromGroup(final Role role, final Principal principal,
                           final String requestingUser) throws Exception {
    if (!roleExists(role)) {
      throw new NotFoundException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.deleteRoleToGroups(requestingUser, role.getName(), COMPONENT_NAME,
                                  ImmutableSet.of(principal.getName()));
        LOG.debug("Dropped role {} from group {} for the requested user {}", role, principal, requestingUser);
        return null;
      }
    });
  }

  /**
   * Maps the given {@link EntityId} to {@link Authorizable}. To see a valid set of {@link Authorizable}
   * please see {@link PrivilegeValidator} which is responsible for validating these authorizables positions and action.
   *
   * @param entityId the {@link EntityId} which needs to be mapped to list of {@link Authorizable}
   * @return a {@link List} of {@link Authorizable} which represents the given {@link EntityId}
   */
  @VisibleForTesting
  List<org.apache.sentry.core.common.Authorizable> toSentryAuthorizables(final EntityId entityId) {
    List<org.apache.sentry.core.common.Authorizable> authorizables = new LinkedList<>();
    toAuthorizables(entityId, authorizables);
    return authorizables;
  }

  private Set<Role> getRoles(@Nullable final Principal principal, final String requestingUser) throws Exception {
    // if the specified principal is non-null and is a role, then we just return a singleton set containing that role
    if (principal != null && Principal.PrincipalType.ROLE == principal.getType()) {
      return Collections.singleton(new Role(principal.getName()));
    }

    Set<Role> roles;
    if (principal == null) {
      roles = new HashSet<>();
      Set<TSentryRole> tSentryRoles = execute(new Command<Set<TSentryRole>>() {
        @Override
        public Set<TSentryRole> run(SentryGenericServiceClient client) throws Exception {
          return client.listAllRoles(requestingUser, COMPONENT_NAME);
        }
      });
      for (TSentryRole tSentryRole : tSentryRoles) {
        roles.add(new Role(tSentryRole.getRoleName()));
      }
      LOG.debug("Listed all roles {}; Requesting user: {}", roles, requestingUser);
    } else {
      if (principal.getType().equals(Principal.PrincipalType.USER)) {
        // for a user get all the groups and their roles
        Set<String> groups = groupCache.get(principal);
        LOG.debug("Got groups {} for principal {}", groups, principal);
        roles = new HashSet<>();
        for (String group : groups) {
          roles.addAll(roleCache.get(group));
        }
      } else if (principal.getType().equals(Principal.PrincipalType.GROUP)) {
        roles = roleCache.get(principal.getName());
      } else {
        throw new IllegalArgumentException(String.format("Cannot list roles for %s. Roles can only listed for %s or %s",
                                                         principal, Principal.PrincipalType.USER,
                                                         Principal.PrincipalType.GROUP));
      }
      LOG.debug("Listed roles {} for principal {}; Requesting user: {}", roles, principal, requestingUser);
    }
    return Collections.unmodifiableSet(roles);
  }

  /**
   * Checks if the given role exists
   *
   * @param role the role to be checked for existence
   * @return {@code true} if the specified role exists, {@code false} otherwise
   * @throws Exception if there were any exception while running client command to check role existence
   */
  private boolean roleExists(Role role) throws Exception {
    Set<Role> roles = listAllRoles();
    // Sentry lowercases all roles, so while checking for existence, lower case the role as well
    Role lowerCaseRole = new Role(role.getName().toLowerCase());
    return roles.contains(lowerCaseRole);
  }

  private AuthConf initAuthzConf(String sentrySite) {
    if (Strings.isNullOrEmpty(sentrySite)) {
      throw new IllegalArgumentException(String.format("The value for %s is null or empty. Please configure it to " +
                                                         "the absolute path of sentry-site.xml in cdap-site.xml",
                                                       AuthConf.SENTRY_SITE_URL));
    }
    AuthConf authConf;
    try {
      authConf = sentrySite.startsWith("file://") ? new AuthConf(new URL(sentrySite)) :
        new AuthConf(new URL("file://" + sentrySite));
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(String.format("The path provided for sentry-site.xml in property %s is " +
                                                         "invalid. Please configure it to the absolute path of " +
                                                         "sentry-site.xml in cdap-site.xml",
                                                       AuthConf.SENTRY_SITE_URL), e);
    }
    return authConf;
  }

  /**
   * Instantiate the configured {@link AuthorizationProvider}
   *
   * @return {@link AuthorizationProvider} configured in {@link AuthConf}
   */
  private AuthorizationProvider createAuthProvider() {

    String authProviderName = authConf.get(AuthzConfVars.AUTHZ_PROVIDER.getVar(),
                                           AuthzConfVars.AUTHZ_PROVIDER.getDefault());

    String providerBackendName = authConf.get(AuthzConfVars.AUTHZ_PROVIDER_BACKEND.getVar(),
                                              AuthzConfVars.AUTHZ_PROVIDER_BACKEND.getDefault());

    String policyEngineName = authConf.get(AuthzConfVars.AUTHZ_POLICY_ENGINE.getVar(),
                                           AuthzConfVars.AUTHZ_POLICY_ENGINE.getDefault());

    String resourceName = authConf.get(AuthzConfVars.AUTHZ_PROVIDER_RESOURCE.getVar(),
                                       AuthzConfVars.AUTHZ_PROVIDER_RESOURCE.getDefault());

    LOG.debug("Trying to instantiate authorization provider {}, with provider backend {}, policy engine {} and " +
                "resource {}",
              authProviderName, providerBackendName, policyEngineName, resourceName);

    // Instantiate the configured providerBackend
    try {
      // get the current context classloader
      ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

      if (resourceName != null && resourceName.startsWith("classpath:")) {
        String resourceFileName = resourceName.substring("classpath:".length());
        URL resource = classLoader.getResource(resourceFileName);
        Preconditions.checkState(resource != null, "Resource %s could not be loaded from authorizer classloader",
                                 resourceFileName);
        resourceName = resource.getPath();
      }

      // instantiate the configured provider backend
      Class<?> providerBackendClass = classLoader.loadClass(providerBackendName);
      Constructor<?> providerBackendConstructor = providerBackendClass.getDeclaredConstructor(Configuration.class,
                                                                                              String.class);
      providerBackendConstructor.setAccessible(true);
      ProviderBackend providerBackend = (ProviderBackend) providerBackendConstructor.newInstance(authConf,
                                                                                                 resourceName);
      if (providerBackend instanceof SentryGenericProviderBackend) {
        ((SentryGenericProviderBackend) providerBackend).setComponentType(COMPONENT_NAME);
        ((SentryGenericProviderBackend) providerBackend).setServiceName(instanceName);
      }

      // instantiate the configured policy engine
      Class<?> policyEngineClass = classLoader.loadClass(policyEngineName);
      Constructor<?> policyEngineConstructor = policyEngineClass.getDeclaredConstructor(ProviderBackend.class);
      policyEngineConstructor.setAccessible(true);
      PolicyEngine policyEngine = (PolicyEngine) policyEngineConstructor.newInstance(providerBackend);

      // Instantiate the configured authz provider
      Class<?> authProviderClass = classLoader.loadClass(authProviderName);
      Constructor<?> authzProviderConstructor = authProviderClass.getDeclaredConstructor(
        Configuration.class, String.class, PolicyEngine.class);
      authzProviderConstructor.setAccessible(true);
      return (AuthorizationProvider) authzProviderConstructor.newInstance(authConf, resourceName, policyEngine);
    } catch (Exception e) {
      throw Throwables.propagate(e);
    }
  }

  private List<TSentryPrivilege> getAllPrivileges(final Set<Role> roles) throws Exception {
    return execute(new Command<List<TSentryPrivilege>>() {
      @Override
      public List<TSentryPrivilege> run(SentryGenericServiceClient client) throws Exception {
        final List<TSentryPrivilege> tSentryPrivileges = new ArrayList<>();
        for (Role role : roles) {
          tSentryPrivileges.addAll(client.listPrivilegesByRoleName(sentryAdminGroup, role.getName(),
                                                                   COMPONENT_NAME, instanceName));
        }
        return Collections.unmodifiableList(tSentryPrivileges);
      }
    });
  }

  @VisibleForTesting
  TSentryPrivilege toTSentryPrivilege(EntityId entityId, Action action) {
    List<TAuthorizable> tAuthorizables = toTAuthorizable(entityId);
    TSentryPrivilege tSentryPrivilege = new TSentryPrivilege(COMPONENT_NAME, instanceName,
                                                             tAuthorizables, action.name());
    // CDAP-9029 Set grant options to true so that sentry will allow the privileges to be passed on to some other user
    // Setting it true for all privileges gives to a user is fine as we don't rely on this setting. While doing
    // grant CDAP enforces ADMIN on the entity.
    tSentryPrivilege.setGrantOption(TSentryGrantOption.TRUE);
    return tSentryPrivilege;
  }

  /**
   * Performs revoke as sentry admin. This is needed since in sentry revoke is kind of role
   * management command and can only be done by sentry admin group. In CDAP when a revoke is done
   * CDAP already checks that the user who is requesting revoke has ADMIN on the entity.
   * @throws Exception if there was any exception while running the client command to revoke the role
   */
  void revoke(final EntityId entityId, final Role role, Set<Action> actions)
    throws Exception {
    revoke(entityId, role, actions, sentryAdminGroup);
  }

  private List<TAuthorizable> toTAuthorizable(EntityId entityId) {
    List<org.apache.sentry.core.common.Authorizable> authorizables = toSentryAuthorizables(entityId);
    List<TAuthorizable> tAuthorizables = new ArrayList<>();
    for (org.apache.sentry.core.common.Authorizable authorizable : authorizables) {
      tAuthorizables.add(new TAuthorizable(authorizable.getTypeName(), authorizable.getName()));
    }
    return tAuthorizables;
  }

  private <T> T execute(Command<T> cmd) throws Exception {
    try {
      SentryGenericServiceClient client = getClient();
      try {
        return cmd.run(client);
      } finally {
        client.close();
      }
    } catch (Exception e) {
      // map sentry exceptions to appropriate cdap-security exceptions
      if (e instanceof SentryAccessDeniedException) {
        throw new UnauthorizedException(e.getMessage());
      } else if (e instanceof SentryNoSuchObjectException) {
        throw new NotFoundException(e.getMessage());
      } else if (e instanceof SentryAlreadyExistsException) {
        throw new AlreadyExistsException(e.getMessage());
      } else if (e instanceof SentryInvalidInputException || e instanceof SentryThriftAPIMismatchException) {
        throw new BadRequestException(e.getMessage());
      } else {
        throw e;
      }
    }
  }

  /**
   * A Command is a closure used to pass a block of code from individual functions to execute, which centralizes
   * connection error handling. Command is parameterized on the return type of the function.
   */
  private interface Command<T> {
    T run(SentryGenericServiceClient client) throws Exception;
  }

  private SentryGenericServiceClient getClient() throws Exception {
    // TODO: Cache the client
    return SentryGenericServiceClientFactory.create(authConf);
  }

  /**
   * Maps a {@link TAuthorizable sentry authorizable} to {@link EntityId}
   *
   * @param tAuthorizable the TAuthorizable which needs to be mapped to entity
   * @param parent the parent entity of this TAuthorizable
   * @return {@link EntityId} for the given {@link TAuthorizable}
   */
  private EntityId toEntityId(TAuthorizable tAuthorizable, @Nullable EntityId parent) {
    Authorizable authorizable = ModelAuthorizables.from(tAuthorizable.getType(), tAuthorizable.getName());
    switch (Authorizable.AuthorizableType.valueOf(tAuthorizable.getType())) {
      case INSTANCE:
        return new InstanceId(instanceName);
      case NAMESPACE:
        Namespace namespace = (Namespace) authorizable;
        return new NamespaceId(namespace.getName());
      case ARTIFACT:
        Artifact artifact = (Artifact) authorizable;
        assertNonNullParent(parent, Authorizable.AuthorizableType.ARTIFACT);
        // TODO: this method will be remmoved CDAP-12100
        //noinspection ConstantConditions
        return ((NamespaceId) parent).artifact(artifact.getArtifactName(), artifact.getArtifactVersion());
      case APPLICATION:
        Application application = (Application) authorizable;
        assertNonNullParent(parent, Authorizable.AuthorizableType.APPLICATION);
        return ((NamespaceId) parent).app(application.getName());
      case PROGRAM:
        Program program = (Program) authorizable;
        assertNonNullParent(parent, Authorizable.AuthorizableType.PROGRAM);
        ApplicationId applicationId = (ApplicationId) parent;
        // TODO: this method will be remmoved CDAP-12100
        //noinspection ConstantConditions
        return applicationId.program(program.getProgramType(), program.getProgramName());
      case DATASET:
        Dataset dataset = (Dataset) authorizable;
        assertNonNullParent(parent, Authorizable.AuthorizableType.DATASET);
        return ((NamespaceId) parent).dataset(dataset.getName());
      case DATASET_MODULE:
        DatasetModule datasetModule = (DatasetModule) authorizable;
        assertNonNullParent(parent, Authorizable.AuthorizableType.DATASET_MODULE);
        return ((NamespaceId) parent).datasetModule(datasetModule.getName());
      case DATASET_TYPE:
        DatasetType datasetType = (DatasetType) authorizable;
        assertNonNullParent(parent, Authorizable.AuthorizableType.DATASET_TYPE);
        return ((NamespaceId) parent).datasetType(datasetType.getName());
      case STREAM:
        Stream stream = (Stream) authorizable;
        assertNonNullParent(parent, Authorizable.AuthorizableType.STREAM);
        return ((NamespaceId) parent).stream(stream.getName());
      case SECUREKEY:
        SecureKey secureKey = (SecureKey) authorizable;
        assertNonNullParent(parent, Authorizable.AuthorizableType.SECUREKEY);
        return ((NamespaceId) parent).secureKey(secureKey.getName());
      default:
        throw new IllegalArgumentException(String.format("Sentry Authorizable %s has invalid type %s",
                                                         tAuthorizable.getName(), tAuthorizable.getType()));
    }
  }

  private void assertNonNullParent(EntityId parent, Authorizable.AuthorizableType authorizableType) {
    Preconditions.checkNotNull(parent, "%s must have a parent", authorizableType);
  }

  /**
   * Maps {@link EntityId} to a {@link List} of {@link Authorizable}
   * by recursively working its way from a given entity.
   *
   * @param entityId {@link EntityId} the entity which needs to be mapped to a list of authorizables
   * @param authorizables {@link List} of {@link Authorizable} to
   * add authorizables to
   */
  void toAuthorizables(EntityId entityId, List<? super Authorizable> authorizables) {
    EntityType entityType = entityId.getEntityType();
    switch (entityType) {
      case INSTANCE:
        authorizables.add(new Instance(((InstanceId) entityId).getInstance()));
        break;
      case NAMESPACE:
        toAuthorizables(new InstanceId(instanceName), authorizables);
        authorizables.add(new Namespace(((NamespaceId) entityId).getNamespace()));
        break;
      case ARTIFACT:
        ArtifactId artifactId = (ArtifactId) entityId;
        toAuthorizables(artifactId.getParent(), authorizables);
        authorizables.add(new Artifact(artifactId.getArtifact(), artifactId.getVersion()));
        break;
      case APPLICATION:
        ApplicationId applicationId = (ApplicationId) entityId;
        toAuthorizables(applicationId.getParent(), authorizables);
        authorizables.add(new Application(applicationId.getApplication()));
        break;
      case DATASET:
        DatasetId dataset = (DatasetId) entityId;
        toAuthorizables(dataset.getParent(), authorizables);
        authorizables.add(new Dataset(dataset.getDataset()));
        break;
      case DATASET_MODULE:
        DatasetModuleId datasetModuleId = (DatasetModuleId) entityId;
        toAuthorizables(datasetModuleId.getParent(), authorizables);
        authorizables.add(new DatasetModule(datasetModuleId.getModule()));
        break;
      case DATASET_TYPE:
        DatasetTypeId datasetTypeId = (DatasetTypeId) entityId;
        toAuthorizables(datasetTypeId.getParent(), authorizables);
        authorizables.add(new DatasetType(datasetTypeId.getType()));
        break;
      case STREAM:
        StreamId streamId = (StreamId) entityId;
        toAuthorizables(streamId.getParent(), authorizables);
        authorizables.add(new Stream((streamId).getStream()));
        break;
      case PROGRAM:
        ProgramId programId = (ProgramId) entityId;
        toAuthorizables(programId.getParent(), authorizables);
        authorizables.add(new Program(programId.getType(), programId.getProgram()));
        break;
      case SECUREKEY:
        SecureKeyId secureKeyId = (SecureKeyId) entityId;
        toAuthorizables(secureKeyId.getParent(), authorizables);
        authorizables.add(new SecureKey(secureKeyId.getName()));
        break;
      default:
        throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s", entityId, entityType));
    }
  }

  Set<ActionFactory.Action> toSentryActions(Set<Action> actions) {
    Set<ActionFactory.Action> sentryActions = new HashSet<>(actions.size());
    for (Action action : actions) {
      sentryActions.add(new ActionFactory.Action(action.name()));
    }
    return Collections.unmodifiableSet(sentryActions);
  }

  private static List<Authorizable> toAuthorizables(List<TAuthorizable> tAuthorizables) {
    List<Authorizable> authorizables = new ArrayList<>(tAuthorizables.size());
    for (TAuthorizable tAuthorizable : tAuthorizables) {
      authorizables.add(ModelAuthorizables.from(tAuthorizable.getType(), tAuthorizable.getName()));
    }
    return authorizables;
  }

  private Set<String> fetchGroups(Principal principal) {
    return authProvider.getGroupMapping().getGroups(principal.getName());
  }

  private Set<Role> fetchRoles(final String group) throws Exception {
    Set<TSentryRole> tSentryRoles = execute(new Command<Set<TSentryRole>>() {
      @Override
      public Set<TSentryRole> run(SentryGenericServiceClient client) throws Exception {
        return client.listRolesByGroupName(sentryAdminGroup, group, COMPONENT_NAME);
      }
    });
    Set<Role> roles = new HashSet<>();
    for (TSentryRole tSentryRole : tSentryRoles) {
      roles.add(new Role(tSentryRole.getRoleName()));
    }
    return roles;
  }

  private Set<WildcardPolicy> fetchPolicies(final Role role) throws Exception {
    Set<TSentryPrivilege> sentryPrivileges = execute(new Command<Set<TSentryPrivilege>>() {
      @Override
      public Set<TSentryPrivilege> run(SentryGenericServiceClient client) throws Exception {
        return client.listPrivilegesByRoleName(sentryAdminGroup, role.getName(), COMPONENT_NAME, instanceName);
      }
    });

    if (sentryPrivileges == null) {
      LOG.debug("Got empty set of policies for role {}", role);
      return Collections.emptySet();
    }

    Set<WildcardPolicy> policies = new HashSet<>(sentryPrivileges.size());
    for (TSentryPrivilege sentryPrivilege : sentryPrivileges) {
      policies.add(new WildcardPolicy(toAuthorizables(sentryPrivilege.getAuthorizables()),
                                      new ActionFactory.Action(sentryPrivilege.getAction())));
    }

    LOG.debug("Got policies {} for role {}", policies, role);
    return Collections.unmodifiableSet(policies);
  }
}
