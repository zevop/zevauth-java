package com.zevauth;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A verified webhook delivery. Deliveries are at-least-once: use
 * {@link #id()} (or the {@code zevauth-delivery-id} header) to stay idempotent.
 */
public record WebhookEvent(String id, String type, String createdAt, JsonNode data) {}
