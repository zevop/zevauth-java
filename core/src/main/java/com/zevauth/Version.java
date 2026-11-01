package com.zevauth;

import java.io.InputStream;
import java.util.Properties;

/** This library's version, sent in the User-Agent. */
public final class Version {
  public static final String VERSION = load();
  static final String USER_AGENT = "zevauth-java/" + VERSION;

  private Version() {}

  private static String load() {
    try (InputStream in = Version.class.getResourceAsStream("version.properties")) {
      Properties p = new Properties();
      if (in != null) p.load(in);
      String v = p.getProperty("version", "0.0.0");
      return v.startsWith("${") ? "0.0.0" : v;
    } catch (Exception e) {
      return "0.0.0";
    }
  }
}
