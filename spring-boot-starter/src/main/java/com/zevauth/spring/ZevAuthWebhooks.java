package com.zevauth.spring;

import com.zevauth.WebhookEvent;
import com.zevauth.WebhookException;
import com.zevauth.Webhooks;

/**
 * Verifies webhook deliveries with {@code zevauth.webhook-secret}. Take
 * the body as {@code @RequestBody byte[]} so the bytes are exactly what
 * was signed:
 *
 * <pre>{@code
 * @PostMapping("/webhooks/zevauth")
 * ResponseEntity<Void> hook(@RequestBody byte[] body, @RequestHeader("zevauth-signature") String signature)
 *     throws WebhookException {
 *   WebhookEvent event = webhooks.constructEvent(body, signature);
 *   …
 * }
 * }</pre>
 */
public class ZevAuthWebhooks {
  private final String secret;

  public ZevAuthWebhooks(String secret) {
    this.secret = secret;
  }

  public void verify(byte[] body, String signature) throws WebhookException {
    Webhooks.verify(body, signature, secret);
  }

  public WebhookEvent constructEvent(byte[] body, String signature) throws WebhookException {
    return Webhooks.constructEvent(body, signature, secret);
  }
}
