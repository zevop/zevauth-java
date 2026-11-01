package com.zevauth;

/**
 * Options for {@code requireAuth} (contract §2.3).
 *
 * @param allowPendingTasks serve a session that still has tasks to finish;
 *     only for routes that help finish them
 * @param requireMfa refuse a session that did not pass a second factor
 */
public record RequireOptions(boolean allowPendingTasks, boolean requireMfa) {
  public static final RequireOptions DEFAULT = new RequireOptions(false, false);

  /** Refuse sessions without a second factor. */
  public static RequireOptions mfaRequired() {
    return new RequireOptions(false, true);
  }

  /** Serve sessions with pending tasks. */
  public static RequireOptions pendingTasksAllowed() {
    return new RequireOptions(true, false);
  }
}
