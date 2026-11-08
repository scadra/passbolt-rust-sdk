#!/usr/bin/env bash
# Writes each ```java example of a Markdown page to <out>/example-<n>/<Class>.java, named after its
# public class, for javac to check them against the jar.
#
#   bash doc-examples.sh docs/sdk/java.md build/doc-examples
set -euo pipefail

page="$1"
out="$2"

awk -v out="$out" '
  /^```java$/ { n++; inside = 1; body = ""; next }
  /^```$/ && inside {
    inside = 0
    if (!match(body, /public (final )?(class|record|interface) [A-Za-z0-9_]+/)) {
      print "example " n " has no public class" > "/dev/stderr"; exit 1
    }
    split(substr(body, RSTART, RLENGTH), words, " ")
    name = words[length(words)]
    dir = out "/example-" n
    system("mkdir -p \"" dir "\"")
    printf "%s", body > (dir "/" name ".java")
    close(dir "/" name ".java")
    next
  }
  inside { body = body $0 "\n" }
  END {
    if (n == 0) { print "no java example" > "/dev/stderr"; exit 1 }
    print n " examples"
  }
' "$page"
