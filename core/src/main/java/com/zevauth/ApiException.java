package com.zevauth;

/**
 * A failed backend API call (contract §3.4). {@link #getStatus()} is 0 for
 * a transport failure ({@code network_error}).
 */
public final class ApiException extends RuntimeException {
  public static final String MISSING_SECRET_KEY = "missing_secret_key";
  public static final String WRONG_KEY_TYPE = "wrong_key_type";
  public static final String REQUEST_FAILED = "request_failed";
  public static final String NETWORK_ERROR = "network_error";

  private static final long serialVersionUID = 1L;

  private final String code;
  private final int status;
  private final String requestId;

  public ApiException(String code, int status, String message, String requestId, Throwable cause) {
    super(code + " (" + status + "): " + message + (requestId == null ? "" : " [request " + requestId + "]"), cause);
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }

  /** {@code not_found}, {@code rate_limited}, a domain code, … */
  public String getCode() { return code; }
  public int getStatus() { return status; }
  /** From the {@code x-request-id} response header. Quote it to ZevAuth support. */
  public String getRequestId() { return requestId; }
}
