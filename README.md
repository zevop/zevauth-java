# ZevAuth for Java

Verify ZevAuth sessions, call the ZevAuth backend API and check webhook
signatures from any JVM server, with a Spring Boot starter. Java 17 or
later.

| Artifact | For |
| --- | --- |
| `com.zevauth:zevauth-java` | Any JVM server: verification, the API client, webhooks, the session bridge, Jakarta Servlet adapters |
| `com.zevauth:zevauth-spring-boot-starter` | Spring Boot: auto-configuration, `@RequireAuth`, an `Auth` controller argument, Spring Security integration |

```xml
<dependency>
  <groupId>com.zevauth</groupId>
  <artifactId>zevauth-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Spring Boot

```properties
zevauth.environment-id=env_live_…
zevauth.secret-key=${ZEVAUTH_SECRET_KEY}
```

```java
@RestController
class AccountController {
  @RequireAuth
  @GetMapping("/api/me")
  Map<String, Object> me(Auth auth) {
    return Map.of("userId", auth.getUserId());
  }

  @RequireAuth(requireMfa = true)
  @PostMapping("/api/payouts")
  void payout(Auth auth) { … }
}
```

`@RequireAuth` answers 401 `unauthorized`, or 403
`session_task_pending` / `mfa_required`, with
`{ "error": { "code", "message" } }`. With Spring Security on the
classpath, signed-in requests also get a `ZevAuthAuthentication` whose
authorities are the organization role and permissions, so
`@PreAuthorize("hasAuthority('org:members:manage')")` works. For URL rules,
add the filter to your chain:
`http.addFilterBefore(zevAuthRequestFilter, AuthorizationFilter.class)`.

## Any JVM server

```java
ZevAuthVerifier verifier = ZevAuthVerifier.builder("env_live_…").build();

Auth auth = verifier.getAuth(request.getHeader("Authorization"));
auth.isSignedIn();
auth.getUserId();
auth.hasPermission("org:members:manage");

verifier.requireAuth(header, RequireOptions.mfaRequired()); // throws AuthRefusal
```

`getAuth` never throws for a missing, expired or forged token: those mean
nobody is signed in. Only RS256 is accepted, the issuer comes from your
environment's discovery document, the audience is enforced, and keys are
cached for up to 10 minutes with a rate-limited refetch on rotation.

Jakarta Servlet apps can use `com.zevauth.servlet.ZevAuthFilter` and read
the result with `ServletSupport.getAuth(request)`.

## Server-rendered pages

With the session bridge, the browser SDK posts its access token to your
server, which keeps it in your own HttpOnly cookie. Your server never
refreshes a session; when the cookie expires, a handshake lets the
browser refresh it and come straight back.

```properties
zevauth.publishable-key=pk_live_…
zevauth.bridge.enabled=true
```

In the browser: `sessionBridge: { url: '/zevauth/bridge' }`. Without
Spring, use `SessionBridgeServlet`, `HandshakeServlet` and
`ZevAuthFilter` with a `SessionBridge`.

## Backend API

```java
ZevAuthClient zevauth = ZevAuthClient.builder(System.getenv("ZEVAUTH_SECRET_KEY")).build();

Models.User user = zevauth.users().get("user_…");
for (Models.User u : zevauth.users().iterate(Map.of("metadata.plan", "pro"))) { … }

try {
  zevauth.users().setBlocked("user_…", true);
} catch (ApiException e) {
  e.getCode();      // "not_found", "rate_limited", …
  e.getRequestId(); // quote this to ZevAuth support
}
```

Retries 429, 502, 503, 504 and network failures (never a 500, which may
have run), honouring `Retry-After`.

## Webhooks

```java
@PostMapping("/webhooks/zevauth")
ResponseEntity<Void> hook(@RequestBody byte[] body, @RequestHeader("zevauth-signature") String signature)
    throws WebhookException {
  WebhookEvent event = webhooks.constructEvent(body, signature); // ZevAuthWebhooks bean
  return ResponseEntity.noContent().build();
}
```

Take the body as `byte[]`: a body parsed and re-serialised fails, correctly.

## Building

```sh
./mvnw verify
```

## Conformance

Every ZevAuth server library implements the same contract,
[`spec/SERVER_SDK.md`](https://github.com/zevop/zevauth-sdk/tree/main/spec),
and passes the same fixtures. They are vendored in
`core/src/test/resources/fixtures`; refresh them with
`./scripts/sync-fixtures.sh ../zevauth-sdk`, then `./mvnw verify`.

## Documentation

<https://docs.zevauth.com/sdk/java>

## Support

Questions and bug reports: open an issue here, or contact ZevAuth support.

## License

MIT
