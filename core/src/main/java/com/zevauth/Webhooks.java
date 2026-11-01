package com.zevauth;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Verifies webhook deliveries. Pass the raw request body: a body that was
 * parsed and re-serialised fails, correctly.
 *
 * <pre>{@code
 * WebhookEvent event = Webhooks.constructEvent(rawBody, request.getHeader("zevauth-signature"), secret);
 * }</pre>
 */
public final class Webhooks {
  public static final String SIGNATURE_HEADER = "zevauth-signature";
  public static final String EVENT_TYPE_HEADER = "zevauth-event-type";
  public static final String DELIVERY_ID_HEADER = "zevauth-delivery-id";
  public static final String ATTEMPT_HEADER = "zevauth-attempt";
  public static final Duration DEFAULT_TOLERANCE = Duration.ofSeconds(300);

  private Webhooks() {}

  public static void verify(byte[] payload, String signature, String secret) throws WebhookException {
    verify(payload, signature, secret, DEFAULT_TOLERANCE, Clock.systemUTC());
  }

  public static void verify(byte[] payload, String signature, String secret, Duration tolerance, Clock clock)
      throws WebhookException {
    String timestamp = null;
    String v1 = null;
    for (String part : (signature == null ? "" : signature).split(",")) {
      int eq = part.indexOf('=');
      if (eq < 0) continue;
      String key = part.substring(0, eq).trim();
      String value = part.substring(eq + 1).trim();
      if (key.equals("t")) timestamp = value;
      else if (key.equals("v1")) v1 = value;
    }
    long t;
    try {
      if (timestamp == null || v1 == null || v1.isEmpty()) throw new NumberFormatException();
      t = Long.parseLong(timestamp);
    } catch (NumberFormatException e) {
      throw new WebhookException(WebhookException.MALFORMED_SIGNATURE, "expected t=<seconds>,v1=<hex>");
    }

    long age = Math.abs(clock.instant().getEpochSecond() - t);
    if (age > tolerance.getSeconds()) {
      throw new WebhookException(WebhookException.TIMESTAMP_OUT_OF_RANGE, "the signature timestamp is outside the tolerance");
    }

    // The key is the whole secret, whsec_ prefix included.
    String expected;
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      mac.update((timestamp + ".").getBytes(StandardCharsets.UTF_8));
      expected = HexFormat.of().formatHex(mac.doFinal(payload));
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new IllegalStateException(e);
    }

    // Exact and constant-time: no case folding.
    if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), v1.getBytes(StandardCharsets.UTF_8))) {
      throw new WebhookException(WebhookException.SIGNATURE_MISMATCH, "the signature does not match the body");
    }
  }

  public static WebhookEvent constructEvent(byte[] payload, String signature, String secret) throws WebhookException {
    return constructEvent(payload, signature, secret, DEFAULT_TOLERANCE, Clock.systemUTC());
  }

  public static WebhookEvent constructEvent(byte[] payload, String signature, String secret, Duration tolerance, Clock clock)
      throws WebhookException {
    verify(payload, signature, secret, tolerance, clock);
    try {
      JsonNode node = Json.MAPPER.readTree(payload);
      return new WebhookEvent(node.path("id").asText(null), node.path("type").asText(null),
          node.path("createdAt").asText(null), node.get("data"));
    } catch (java.io.IOException e) {
      throw new WebhookException(WebhookException.MALFORMED_SIGNATURE, "the signed body is not a JSON event");
    }
  }
}
