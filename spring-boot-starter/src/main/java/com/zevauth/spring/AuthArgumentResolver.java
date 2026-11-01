package com.zevauth.spring;

import com.zevauth.Auth;
import com.zevauth.servlet.ServletSupport;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/** Lets a controller method take the request's {@link Auth} as a parameter. */
public class AuthArgumentResolver implements HandlerMethodArgumentResolver {
  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    return Auth.class.equals(parameter.getParameterType());
  }

  @Override
  public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mav, NativeWebRequest request,
      WebDataBinderFactory binderFactory) {
    HttpServletRequest servlet = request.getNativeRequest(HttpServletRequest.class);
    return servlet == null ? Auth.signedOut() : ServletSupport.getAuth(servlet);
  }
}
