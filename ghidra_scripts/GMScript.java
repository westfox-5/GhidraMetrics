import java.nio.file.Path;

import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.GMetric;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.script.GMBaseScript;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentOption;

public class GMScript extends GMBaseScript {

	@Override
	protected void run() throws Exception {
		parseArgs();
		
		GMetric metric = GMetric.initialize(getArgValue(GMScriptArgumentOption.METRIC_NAME), getCurrentProgram());
		GMExporter.Type exportType = getArgValue(GMScriptArgumentOption.EXPORT_TYPE);
		Path exportPath = getArgValue(GMScriptArgumentOption.EXPORT_PATH);
		
		GMExporter.of(exportType)
			.addMetric(metric)
			.toPath(exportPath)
		.export();
		Msg.info(this, "Exported to: "+ exportPath.toAbsolutePath());
	}

}
