package com.zevauth;

/** Why a webhook delivery was refused (contract §4). */
public final class WebhookException extends Exception {
  public static final String MALFORMED_SIGNATURE = "webhook_malformed_signature";
  public static final String TIMESTAMP_OUT_OF_RANGE = "webhook_timestamp_out_of_range";
  public static final String SIGNATURE_MISMATCH = "webhook_signature_mismatch";

  private static final long serialVersionUID = 1L;

  private final String code;

  WebhookException(String code, String message) {
    super(code + ": " + message);
    this.code = code;
  }

  /** One of the constants on this class. */
  public String getCode() {
    return code;
  }
}
