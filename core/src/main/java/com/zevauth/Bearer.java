package com.zevauth;

/** Session tokens from an {@code Authorization} header (contract §1.5). */
public final class Bearer {
  private Bearer() {}

  /**
   * The token from {@code Bearer <token>}, or {@code null} for no header,
   * another scheme, an empty token, or an API key sent in the wrong place.
   */
  public static String from(String header) {
    if (header == null || !header.startsWith("Bearer ")) return null;
    String token = header.substring("Bearer ".length()).trim();
    if (token.isEmpty() || token.startsWith("pk_") || token.startsWith("sk_")) return null;
    return token;
  }
}
