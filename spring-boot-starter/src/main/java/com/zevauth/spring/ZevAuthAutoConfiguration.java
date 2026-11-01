package com.zevauth.spring;

import com.zevauth.Auth;
import com.zevauth.ZevAuthClient;
import com.zevauth.ZevAuthVerifier;
import java.util.function.Consumer;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Wires ZevAuth from {@code zevauth.*}: a verifier when
 * {@code zevauth.environment-id} is set, the API client when
 * {@code zevauth.secret-key} is set, webhook verification when
 * {@code zevauth.webhook-secret} is set. The servlet side lives in
 * {@link ZevAuthWebAutoConfiguration}. Define any of these beans yourself
 * to replace it.
 */
@AutoConfiguration
@EnableConfigurationProperties(ZevAuthProperties.class)
public class ZevAuthAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "zevauth", name = "environment-id")
  public ZevAuthVerifier zevAuthVerifier(ZevAuthProperties properties) {
    ZevAuthVerifier.Builder builder = ZevAuthVerifier.builder(properties.getEnvironmentId()).apiUrl(properties.getApiUrl());
    if (properties.getJwks() != null && properties.getIssuer() != null) {
      builder.localKeys(properties.getIssuer(), properties.getJwks());
    }
    return builder.build();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "zevauth", name = "secret-key")
  public ZevAuthClient zevAuthClient(ZevAuthProperties properties) {
    return ZevAuthClient.builder(properties.getSecretKey()).apiUrl(properties.getApiUrl()).build();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "zevauth", name = "webhook-secret")
  public ZevAuthWebhooks zevAuthWebhooks(ZevAuthProperties properties) {
    return new ZevAuthWebhooks(properties.getWebhookSecret());
  }

  /** Installs an {@link Auth} into Spring Security's context. */
  @FunctionalInterface
  public interface SecurityContextInstaller extends Consumer<Auth> {}
}
