#!/usr/bin/env bash
# Run once per Codespace (or add to your devcontainer's postCreateCommand)
# to install a Gradle-compatible JDK 17 alongside whatever default JDK
# the Codespace image ships with.
set -e

echo "Installing Temurin JDK 17…"
sudo apt-get update -qq
sudo apt-get install -y -qq temurin-17-jdk || sudo apt-get install -y -qq openjdk-17-jdk

echo ""
echo "Installed JDKs:"
ls /usr/lib/jvm/

echo ""
echo "server.js will auto-detect this JDK for Gradle builds (see findCompatibleJavaHome())."
echo "No manual JAVA_HOME export needed — but you can override by setting GRADLE_JAVA_HOME."
