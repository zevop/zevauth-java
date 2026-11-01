package com.zevauth.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Refuses requests that are not signed in, on a controller or one handler
 * method. Answers 401 {@code unauthorized}, or 403
 * {@code session_task_pending} / {@code mfa_required}, with the shared
 * {@code { "error": { "code", "message" } }} body.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface RequireAuth {
  /** Refuse sessions that did not pass a second factor. */
  boolean requireMfa() default false;

  /** Serve sessions with pending tasks; only for routes that help finish them. */
  boolean allowPendingTasks() default false;
}
