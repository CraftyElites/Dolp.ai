#!/usr/bin/env bash
# Run once per Codespace (or add to devcontainer postCreateCommand)
# Installs the Android SDK command-line tools + the platform/build-tools
# needed for local Gradle builds (expo prebuild + ./gradlew assembleRelease).
set -e

ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/android-sdk}"
CMDLINE_TOOLS_VERSION="11076708"   # latest stable as of writing; update if Google rotates the URL
PLATFORM="android-35"
BUILD_TOOLS="35.0.0"

echo "Installing Android SDK to $ANDROID_SDK_ROOT ..."
mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"

if [ ! -d "$ANDROID_SDK_ROOT/cmdline-tools/latest" ]; then
  cd /tmp
  curl -sSL -o cmdline-tools.zip \
    "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip"
  unzip -q cmdline-tools.zip -d "$ANDROID_SDK_ROOT/cmdline-tools"
  mv "$ANDROID_SDK_ROOT/cmdline-tools/cmdline-tools" "$ANDROID_SDK_ROOT/cmdline-tools/latest"
  rm cmdline-tools.zip
fi

export ANDROID_SDK_ROOT
export ANDROID_HOME="$ANDROID_SDK_ROOT"
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$PATH"

yes | sdkmanager --licenses > /dev/null || true
sdkmanager "platform-tools" "platforms;${PLATFORM}" "build-tools;${BUILD_TOOLS}"

# Persist env vars for future shells in this codespace
{
  echo ""
  echo "export ANDROID_SDK_ROOT=$ANDROID_SDK_ROOT"
  echo "export ANDROID_HOME=$ANDROID_SDK_ROOT"
  echo "export PATH=\$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:\$ANDROID_SDK_ROOT/platform-tools:\$PATH"
} >> "$HOME/.bashrc"

echo ""
echo "Android SDK installed at $ANDROID_SDK_ROOT"
echo "ANDROID_HOME/ANDROID_SDK_ROOT exported for new shells (source ~/.bashrc or restart terminal)."
echo "server.js will also pick this up automatically once ANDROID_HOME is set in the running process env."
