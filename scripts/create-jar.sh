#!/usr/bin/bash

rm GMScriptRunner.jar
jar -cmf MANIFEST.MF GMScriptRunner.jar build/libs/GhidraMetrics.jar lib/commons-cli-1.5.0.jar