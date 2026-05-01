#!/usr/bin/env bash
# Bundle the Java jar and the Android AAR for the Maven Central Portal: a POM, sources and
# javadoc jars and checksums per artifact, and their signatures when MAVEN_GPG_KEY_ID names a
# key of the GnuPG keyring (MAVEN_GPG_PASSPHRASE unlocks it).
# Usage: scripts/maven-bundle.sh <group> <version> <sdk dir> <kotlin sources dir> <out.zip>
# <sdk dir> holds passbolt-sdk-<version>.jar, its -sources.jar and passbolt-sdk-android-<version>.aar.
set -euo pipefail
cd "$(dirname "$0")/.."

if (( $# != 5 )); then
  echo "usage: $0 <group> <version> <sdk dir> <kotlin sources dir> <out.zip>" >&2
  exit 1
fi
group="$1"
version="$2"
sdk="$3"
kotlin="$4"
out="$(realpath -m "$5")"
repository="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-scadra/passbolt-rust}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Central requires a javadoc jar (a zip, like any jar); the bindings document themselves in
# their sources.
mkdir "$work/javadoc"
echo "The API is documented in the sources jar." > "$work/javadoc/README.txt"

pom() {
  local artifact="$1" packaging="$2" description="$3" jna_type="$4"
  cat <<POM
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>$group</groupId>
  <artifactId>$artifact</artifactId>
  <version>$version</version>
  <packaging>$packaging</packaging>
  <name>$artifact</name>
  <description>$description</description>
  <url>$repository</url>
  <licenses>
    <license>
      <name>AGPL-3.0-or-later</name>
      <url>https://www.gnu.org/licenses/agpl-3.0.txt</url>
    </license>
  </licenses>
  <developers>
    <developer>
      <name>Passbolt SA</name>
      <url>https://www.passbolt.com</url>
    </developer>
  </developers>
  <scm>
    <url>$repository</url>
    <connection>scm:git:$repository.git</connection>
  </scm>
  <dependencies>
    <dependency>
      <groupId>net.java.dev.jna</groupId>
      <artifactId>jna</artifactId>
      <version>${JNA:-5.14.0}</version>
      <type>$jna_type</type>
    </dependency>
  </dependencies>
</project>
POM
}

# <artifact> <packaging> <file> <sources jar> <description> <jna type>
add() {
  local artifact="$1" packaging="$2" file="$3" sources="$4" description="$5" jna_type="$6"
  local dir="$work/bundle/${group//.//}/$artifact/$version"
  local base="$dir/$artifact-$version"
  mkdir -p "$dir"
  cp "$file" "$base.$packaging"
  cp "$sources" "$base-sources.jar"
  (cd "$work/javadoc" && zip -qr "$base-javadoc.jar" .)
  pom "$artifact" "$packaging" "$description" "$jna_type" > "$base.pom"
  for file in "$dir"/*; do
    if [[ -n "${MAVEN_GPG_KEY_ID:-}" ]]; then
      gpg --batch --yes --pinentry-mode loopback --passphrase "${MAVEN_GPG_PASSPHRASE:-}" \
        --local-user "$MAVEN_GPG_KEY_ID" --armor --detach-sign "$file"
    fi
    md5sum "$file" | cut -d' ' -f1 > "$file.md5"
    sha1sum "$file" | cut -d' ' -f1 > "$file.sha1"
  done
}

(cd "$kotlin" && zip -qr "$work/android-sources.jar" .)
add passbolt-sdk jar "$sdk/passbolt-sdk-$version.jar" "$sdk/passbolt-sdk-$version-sources.jar" \
  "Passbolt SDK: Java bindings of the Rust SDK, with its native libraries" jar
add passbolt-sdk-android aar "$sdk/passbolt-sdk-android-$version.aar" "$work/android-sources.jar" \
  "Passbolt SDK: Android library of the Rust SDK" aar

rm -f "$out"
(cd "$work/bundle" && zip -qr "$out" .)
echo "$out"
