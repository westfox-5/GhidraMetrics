#!/usr/bin/bash

GHIDRA_HOME=/opt/ghidra_10.1.5_PUBLIC
GRADLE_HOME=/opt/gradle-6.9.3

echo ">>> clear.sh"
./clear.sh

echo ">>> cd .. && $GRADLE_HOME/bin/gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME"
cd .. && $GRADLE_HOME/bin/gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME

ZIP_FILE=./dist/$(ls -Art ./dist | tail -n 1) # latest zip
echo ">>> unzip $ZIP_FILE -d $OUT_DIR"
unzip $ZIP_FILE -d $OUT_DIR
