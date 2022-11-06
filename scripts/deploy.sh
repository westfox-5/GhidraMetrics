#!/usr/bin/bash

GHIDRA_HOME=/opt/ghidra_10.1.5_PUBLIC
GRADLE_HOME=/opt/gradle-6.9.3

echo ">>> $GRADLE_HOME/bin/gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME"
$GRADLE_HOME/bin/gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME

OUT_DIR=~/.ghidra/.ghidra_10.1.5_PUBLIC/Extensions/
echo ">>> rm -r $OUT_DIR/GhidraMetrics"
rm -r $OUT_DIR/GhidraMetrics

ZIP_FILE=./dist/$(ls -Art ./dist | tail -n 1) # latest zip
echo ">>> unzip $ZIP_FILE -d $OUT_DIR"
unzip $ZIP_FILE -d $OUT_DIR
