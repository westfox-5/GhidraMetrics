## Inputs
INPUT_DIR="~/all_obfuscations/des1/SplitSplitKindstop"
INPUT_FILE="des_SplitSplitKindstop"

METRIC_NAME="McCabe"
FUNCTION_NAME="main"
EXPORT_TYPE="txt"
EXPORT_PATH=$INPUT_DIR/ghidraMetrics-$METRIC_NAME-$FUNCTION_NAME.$EXPORT_TYPE



## -----------------------------------------------------
## Parameters
SCRIPT_NAME=GhidraMetricsScript
SCRIPT_ARGS="metricName=$METRIC_NAME functionName=$FUNCTION_NAME exportType=$EXPORT_TYPE exportPath=$EXPORT_PATH"

PRJLOC=~
PRJNAME="GhidraMetricsTest"

CUSTFLAGS="-deleteProject -analysisTimeoutPerFile 10"

## -----------------------------------------------------
## Execution
echo ">>> Deleting old project"
rm -r $PRJLOC/$PRJNAME.*

echo ">>> Executing headless analyzer"
/opt/ghidra_10.1.5_PUBLIC/support/analyzeHeadless $PRJLOC $PRJNAME \
-import $INPUT_DIR/$INPUT_FILE \
-postScript $SCRIPT_NAME $SCRIPT_ARGS \
$CUSTFLAGS

