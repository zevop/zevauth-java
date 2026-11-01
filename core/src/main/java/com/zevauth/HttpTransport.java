package com.zevauth;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Sends one HTTP request. The default uses {@link java.net.http.HttpClient};
 * replace it in tests, or to route through your own client.
 */
@FunctionalInterface
public interface HttpTransport {

  /** A request to send. {@code body} is null for none. */
  record Request(String method, URI uri, Map<String, String> headers, byte[] body, Duration timeout) {}

  /** A response. Header names are lower-cased. */
  record Response(int status, Map<String, List<String>> headers, byte[] body) {
    public String header(String name) {
      List<String> values = headers.get(name.toLowerCase(java.util.Locale.ROOT));
      return values == null || values.isEmpty() ? null : values.get(0);
    }
  }

  /** Sends the request. Throws for a transport failure (DNS, refused, timeout). */
  Response send(Request request) throws IOException, InterruptedException;

  /** The default transport, on {@link java.net.http.HttpClient}. */
  static HttpTransport jdk() {
    return jdk(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
  }

  /** A transport on the given client. */
  static HttpTransport jdk(HttpClient client) {
    return request -> {
      HttpRequest.Builder builder = HttpRequest.newBuilder(request.uri()).timeout(request.timeout());
      request.headers().forEach(builder::header);
      builder.method(request.method(), request.body() == null
          ? HttpRequest.BodyPublishers.noBody()
          : HttpRequest.BodyPublishers.ofByteArray(request.body()));
      HttpResponse<byte[]> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
      Map<String, List<String>> headers = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
      response.headers().map().forEach((name, values) -> headers.put(name.toLowerCase(java.util.Locale.ROOT), values));
      return new Response(response.statusCode(), headers, response.body());
    };
  }
}
