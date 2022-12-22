#!/usr/bin/sh

java -classpath build/libs/GhidraMetrics.jar:lib/commons-cli-1.5.0.jar \
it.unive.ghidra.metrics.script.GMScriptRunner "$@"
