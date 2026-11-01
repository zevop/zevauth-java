package com.zevauth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;
import java.util.Map;

/** The backend API's resources. Unknown fields are ignored. */
public final class Models {
  private Models() {}

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record User(
      String id, String email, boolean emailVerified, String username, String phone, boolean phoneVerified,
      String firstName, String lastName, String imageUrl, Map<String, Object> publicMetadata, String status,
      Boolean mfaEnabled, String lastSignInAt, String createdAt) {}

  /** One page of a list. {@code next} is the cursor for the following page. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Page<T>(List<T> data, boolean hasMore, String next, int totalCount) {}

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record SetBlockedResult(User user, int sessionsRevoked) {}

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Organization(
      String id, String name, String slug, String imageUrl, Object publicMetadata, Integer maxMembers,
      Boolean requireMfa, String createdAt) {}

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record OrganizationMember(
      String userId, String email, String firstName, String lastName, String role, String joinedAt) {}

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Membership(Organization organization, String role, List<String> permissions) {}

  @JsonIgnoreProperties(ignoreUnknown = true)
  public record OrganizationWithMembers(Organization organization, List<OrganizationMember> members) {}
}
