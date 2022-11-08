#!/usr/bin/bash

echo "### RUN ME IN THE PROJECT ROOT DIRECTORY ###"

DIR=$HOME/.ghidra/$(ls -A $HOME/.ghidra)/Extensions
echo ">>> rm -r $DIR/GhidraMetrics"
rm -r $DIR/GhidraMetrics

echo ">>> $GRADLE_HOME/bin/gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME"
$GRADLE_HOME/bin/gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME --stacktrace

ZIP_FILE=./dist/$(ls -Art ./dist | tail -n 1) # latest zip
echo ">>>  && unzip $ZIP_FILE -d $DIR"
unzip $ZIP_FILE -d $DIR
