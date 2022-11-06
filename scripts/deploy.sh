#!/usr/bin/bash

GHIDRA_HOME=/opt/ghidra_10.1.5_PUBLIC
GRADLE_HOME=/opt/gradle-6.9.3

echo ">>> Executing gradle script"
$GRADLE_HOME/bin/gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME

echo ">>> Deleting old extension"
OUT_DIR=~/.ghidra/.ghidra_10.1.5_PUBLIC/Extensions/
rm -r $OUT_DIR/GhidraMetrics

echo ">>> Installing new extension"
# fetch latest zip by modifyStamp
ZIP_FILE=./dist/$(ls -Art ./dist | tail -n 1)
unzip $ZIP_FILE -d $OUT_DIR
