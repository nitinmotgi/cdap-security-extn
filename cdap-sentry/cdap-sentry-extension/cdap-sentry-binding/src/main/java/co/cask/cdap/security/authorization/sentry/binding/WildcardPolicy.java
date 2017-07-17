package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import co.cask.cdap.security.authorization.sentry.model.Authorizable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Used to match wildcard privileges. Supports both access and visibility checking.
 */
class WildcardPolicy {
  private final List<WildcardAuthorizable> wildcardAuthorizables;
  private final ActionFactory.Action allowedAction;

  WildcardPolicy(List<Authorizable> authorizables, ActionFactory.Action action) {
    allowedAction = action;

    if (authorizables.isEmpty()) {
      this.wildcardAuthorizables = Collections.emptyList();
      return;
    }

    this.wildcardAuthorizables = new ArrayList<>(authorizables.size());
    for (Authorizable authorizable : authorizables) {
      this.wildcardAuthorizables.add(new WildcardAuthorizable(authorizable));
    }
  }

  /**
   * Checks whether the {@param action} is allowed on the entity represented by {@param entityAuthorizables}
   * based on this policy.
   *
   * @param entityAuthorizables the entity, no wildcards allowed here
   * @param action the action to check
   * @return true if action is allowed, false otherwise
   */
  boolean isAllowed(List<? extends Authorizable> entityAuthorizables, ActionFactory.Action action) {
    if (wildcardAuthorizables.isEmpty()) {
      return false;
    }

    // Authorizable parts have to match exactly
    if (wildcardAuthorizables.size() != entityAuthorizables.size()) {
      return false;
    }

    int index = 0;
    while (index < wildcardAuthorizables.size()) {
      if (!wildcardAuthorizables.get(index).matches(entityAuthorizables.get(index))) {
        return false;
      }
      ++index;
    }

    // Check action
    if (!allowedAction.implies(action)) {
      return false;
    }

    // Both authorizables and action matched, hence the action is allowed on this entity
    return true;
  }

  /**
   * Checks whether the entity is visible based on this policy.
   * The entity is visible if this policy allows any action on either the entity or its descendants.
   *
   * @param entityAuthorizables the entity, no wildcards allowed here
   * @return true if entity is visible, false otherwise
   */
  boolean isVisible(List<? extends Authorizable> entityAuthorizables) {
    if (wildcardAuthorizables.isEmpty()) {
      return false;
    }

    // Entity should be a parent or equal to the authorizable in the policy
    if (entityAuthorizables.size() > wildcardAuthorizables.size()) {
      return false;
    }

    int index = 0;
    while (index < entityAuthorizables.size()) {
      if (!wildcardAuthorizables.get(index).matches(entityAuthorizables.get(index))) {
        return false;
      }
      ++index;
    }

    // Entity is a parent or the same as the authorizable in the policy,
    // hence the entity is visible
    return true;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    WildcardPolicy that = (WildcardPolicy) o;
    return Objects.equals(wildcardAuthorizables, that.wildcardAuthorizables) &&
      Objects.equals(allowedAction, that.allowedAction);
  }

  @Override
  public int hashCode() {
    return Objects.hash(wildcardAuthorizables, allowedAction);
  }

  @Override
  public String toString() {
    return "WildcardPolicy{" +
      "wildcardAuthorizables=" + wildcardAuthorizables +
      ", allowedAction=" + allowedAction +
      '}';
  }
}
