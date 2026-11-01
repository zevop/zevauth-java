package com.zevauth.spring;

import com.zevauth.AuthRefusal;
import com.zevauth.RequireOptions;
import com.zevauth.servlet.ServletSupport;
import com.zevauth.servlet.ZevAuthFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/** Enforces {@link RequireAuth}; a method's annotation wins over its class's. */
public class RequireAuthInterceptor implements HandlerInterceptor {
  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    if (!(handler instanceof HandlerMethod method)) return true;
    RequireAuth rule = AnnotatedElementUtils.findMergedAnnotation(method.getMethod(), RequireAuth.class);
    if (rule == null) rule = AnnotatedElementUtils.findMergedAnnotation(method.getBeanType(), RequireAuth.class);
    if (rule == null) return true;
    try {
      ServletSupport.getAuth(request).require(new RequireOptions(rule.allowPendingTasks(), rule.requireMfa()));
      return true;
    } catch (AuthRefusal refusal) {
      ZevAuthFilter.writeRefusal(response, refusal);
      return false;
    }
  }
}
