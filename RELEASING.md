# Releasing

Releases run in GitHub Actions: they test, sign and upload to the Maven
Central Portal. The last step, publishing, stays a click in the portal,
because a Maven Central release can never be deleted or replaced.

## Cutting a release

1. Set the new version in all three POMs (the parent, `core`,
   `spring-boot-starter`):

   ```sh
   ./mvnw versions:set -DnewVersion=0.2.0 -DgenerateBackupPoms=false
   ```

   Commit to `main` and let the **CI** workflow pass (Java 17, 21 and 25,
   plus the Spring Boot 3 job).
2. Tag and push the tag:

   ```sh
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

   Or on GitHub: **Releases → Draft a new release → Choose a tag**, type
   `v0.2.0`, target `main`, and publish.
3. When the **Release** workflow finishes, open
   [central.sonatype.com](https://central.sonatype.com) → **Publish →
   Deployments**. Check it lists `zevauth-parent`, `zevauth-java` and
   `zevauth-spring-boot-starter` at the new version and shows as
   validated, then click **Publish**. The release reaches Maven Central
   within about 30 minutes.

The workflow checks the tag matches the project version before anything
is built. If you added a required reviewer to the `maven-central`
environment, approve the run under Actions first.

## One-time setup

### 1. Secrets

GitHub → this repository → **Settings → Environments → New environment**,
named `maven-central`. Optionally add yourself as a required reviewer.
Then add these **environment secrets** to it:

| Secret | Value |
| --- | --- |
| `CENTRAL_USERNAME` | The username of a Central Portal user token (central.sonatype.com → account → Generate User Token) |
| `CENTRAL_PASSWORD` | That token's password |
| `GPG_PRIVATE_KEY` | Your signing key, armored: `gpg --armor --export-secret-keys <KEY_ID>` (the whole block, including the BEGIN and END lines) |
| `GPG_PASSPHRASE` | The key's passphrase |

The public half of the key must be on a keyserver, so Central can check
the signatures:

```sh
gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
```

### 2. The namespace

`com.zevauth` must show as **Verified** under central.sonatype.com →
Publish → Namespaces (a DNS TXT record on `zevauth.com`).

## Releasing from your machine

With the same token in `~/.m2/settings.xml` (server id `central`) and the
key in your local GnuPG:

```sh
./mvnw -P release deploy
```

GnuPG asks for the passphrase; then publish the deployment in the portal
as above.
