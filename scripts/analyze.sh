#!/usr/bin/bash

## Inputs
INPUT_DIR="$HOME/all_obfuscations/des1/SplitSplitKindstop"
INPUT_FILE="des_SplitSplitKindstop"

METRIC_NAME="Halstead"
FUNCTION_NAME="main"
EXPORT_TYPE="txt"
EXPORT_PATH=$INPUT_DIR/ghidraMetrics-$METRIC_NAME-$FUNCTION_NAME.$EXPORT_TYPE

## -----------------------------------------------------
## Parameters
SCRIPT_NAME=GhidraMetricsScript
SCRIPT_ARGS="metricName=$METRIC_NAME functionName=$FUNCTION_NAME exportType=$EXPORT_TYPE exportPath=$EXPORT_PATH"

PRJLOC=$HOME
PRJNAME="GhidraMetricsTest"
CUSTFLAGS="-deleteProject -analysisTimeoutPerFile 10"

## -----------------------------------------------------
## Execution
echo ">>> rm -r $PRJLOC/$PRJNAME.*"
rm -r $PRJLOC/$PRJNAME.*

echo ">>> gcc -o $INPUT_DIR/$INPUT_FILE $INPUT_DIR/$INPUT_FILE.c"
gcc -o $INPUT_DIR/$INPUT_FILE $INPUT_DIR/$INPUT_FILE.c

echo ">>> $GHIDRA_HOME/support/analyzeHeadless $PRJLOC $PRJNAME \
-import $INPUT_DIR/$INPUT_FILE \
-postScript $SCRIPT_NAME $SCRIPT_ARGS \
$CUSTFLAGS"

$GHIDRA_HOME/support/analyzeHeadless $PRJLOC $PRJNAME \
-import $INPUT_DIR/$INPUT_FILE \
-postScript $SCRIPT_NAME $SCRIPT_ARGS \
$CUSTFLAGS

