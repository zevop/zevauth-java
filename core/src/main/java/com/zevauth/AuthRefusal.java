package com.zevauth;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Why {@code requireAuth} refused a request. {@link #toJson()} is the
 * shared error envelope to answer with, using {@link #getStatus()}.
 */
public final class AuthRefusal extends Exception {
  public static final String UNAUTHORIZED = "unauthorized";
  public static final String SESSION_TASK_PENDING = "session_task_pending";
  public static final String MFA_REQUIRED = "mfa_required";

  private static final long serialVersionUID = 1L;

  private final int status;
  private final String code;
  private final transient List<String> pendingTasks;

  AuthRefusal(int status, String code, String message, List<String> pendingTasks) {
    super(message);
    this.status = status;
    this.code = code;
    this.pendingTasks = pendingTasks;
  }

  public int getStatus() { return status; }
  public String getCode() { return code; }
  /** Set for session_task_pending. */
  public List<String> getPendingTasks() { return pendingTasks; }

  /** {@code { "error": { "code", "message", "pendingTasks"? } }} */
  public Map<String, Object> body() {
    Map<String, Object> error = new LinkedHashMap<>();
    error.put("code", code);
    error.put("message", getMessage());
    if (SESSION_TASK_PENDING.equals(code)) error.put("pendingTasks", pendingTasks);
    return Map.of("error", error);
  }

  /** {@link #body()} as JSON. */
  public String toJson() {
    return Json.write(body());
  }
}
