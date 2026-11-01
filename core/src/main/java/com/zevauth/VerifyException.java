package com.zevauth;

/**
 * Why a session token was refused (contract §1.4). Every code means "this
 * request is not signed in"; {@link ZevAuthVerifier#getAuth} turns them
 * into a signed-out {@link Auth} and never throws.
 */
public final class VerifyException extends Exception {
  public static final String MALFORMED_TOKEN = "malformed_token";
  public static final String UNSUPPORTED_ALGORITHM = "unsupported_algorithm";
  public static final String UNKNOWN_KEY = "unknown_key";
  public static final String INVALID_SIGNATURE = "invalid_signature";
  public static final String INVALID_ISSUER = "invalid_issuer";
  public static final String INVALID_AUDIENCE = "invalid_audience";
  public static final String TOKEN_EXPIRED = "token_expired";
  public static final String TOKEN_NOT_YET_VALID = "token_not_yet_valid";
  public static final String JWKS_UNAVAILABLE = "jwks_unavailable";

  private static final long serialVersionUID = 1L;

  private final String code;

  public VerifyException(String code, String message) {
    this(code, message, null);
  }

  public VerifyException(String code, String message, Throwable cause) {
    super(message == null || message.isEmpty() ? code : code + ": " + message, cause);
    this.code = code;
  }

  /** One of the constants on this class. */
  public String getCode() {
    return code;
  }
}
