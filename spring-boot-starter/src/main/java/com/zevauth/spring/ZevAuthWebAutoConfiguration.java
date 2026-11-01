package com.zevauth.spring;

import com.zevauth.SessionBridge;
import com.zevauth.ZevAuthVerifier;
import com.zevauth.spring.ZevAuthAutoConfiguration.SecurityContextInstaller;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * The servlet side: the session bridge (when {@code zevauth.bridge.enabled=true}),
 * the request filter, {@code @RequireAuth} and the {@code Auth} controller
 * argument. Separate from {@link ZevAuthAutoConfiguration} and ordered after
 * it, so its {@code @ConditionalOnBean} checks see the verifier whether it
 * came from properties or from your own bean.
 */
@AutoConfiguration(after = ZevAuthAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(ZevAuthVerifier.class)
public class ZevAuthWebAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "zevauth.bridge", name = "enabled", havingValue = "true")
  public SessionBridge zevAuthSessionBridge(ZevAuthVerifier verifier, ZevAuthProperties properties) {
    ZevAuthProperties.Bridge b = properties.getBridge();
    return SessionBridge.builder(verifier)
        .allowedOrigins(b.getAllowedOrigins() == null ? List.of() : b.getAllowedOrigins())
        .cookieDomain(b.getCookieDomain())
        .secure(b.isSecure())
        .handshakePath(b.getHandshakePath())
        .build();
  }

  @Bean
  @ConditionalOnMissingBean
  public ZevAuthRequestFilter zevAuthRequestFilter(ZevAuthVerifier verifier, ObjectProvider<SessionBridge> bridge,
      ZevAuthProperties properties, ObjectProvider<SecurityContextInstaller> security) {
    SessionBridge sessionBridge = bridge.getIfAvailable();
    SessionBridge.HandshakeOptions handshake = null;
    if (sessionBridge != null && properties.getPublishableKey() != null) {
      handshake = new SessionBridge.HandshakeOptions(properties.getPublishableKey(), properties.getBridge().getPath(),
          properties.getApiUrl(), properties.getBridge().getUiScriptUrl());
    }
    return new ZevAuthRequestFilter(verifier, sessionBridge, properties.getBridge().getPath(), handshake,
        security.getIfAvailable());
  }

  /** {@code @RequireAuth} and the {@code Auth} controller argument, for Spring MVC apps. */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = "org.springframework.web.servlet.config.annotation.WebMvcConfigurer")
  static class MvcConfiguration {
    @Bean
    WebMvcConfigurer zevAuthWebMvcConfigurer() {
      return new WebMvcConfigurer() {
        @Override
        public void addInterceptors(InterceptorRegistry registry) {
          registry.addInterceptor(new RequireAuthInterceptor());
        }

        @Override
        public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
          resolvers.add(new AuthArgumentResolver());
        }
      };
    }
  }

  /** Puts signed-in requests into Spring Security's context, when Spring Security is present. */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = "org.springframework.security.core.context.SecurityContextHolder")
  static class SecurityConfiguration {
    @Bean
    SecurityContextInstaller zevAuthSecurityContextInstaller() {
      return ZevAuthAuthentication::install;
    }
  }
}
