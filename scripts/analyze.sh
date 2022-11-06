INDIR="~/all_obfuscations/des1"
INFILE="SplitSplitKindstop/des_SplitSplitKindstop"

## -----------------------------------------------------

SCRIPT_NAME=GhidraMetricsScript
SCRIPT_ARGS="metricName=McCabe exportType=txt exportPath=/home/davide/exportMcCabe.txt"

## -----------------------------------------------------
PRJLOC=~
PRJNAME="GhidraMetricsTest"

CUSTFLAGS="-deleteProject -analysisTimeoutPerFile 10"

## -----------------------------------------------------

echo ">>> Deleting old project"
rm -r $PRJLOC/$PRJNAME.*

echo ">>> Executing headless analyzer"
/opt/ghidra_10.1.5_PUBLIC/support/analyzeHeadless $PRJLOC $PRJNAME \
-import $INDIR/$INFILE \
-postScript $SCRIPT_NAME $SCRIPT_ARGS \
$CUSTFLAGS

