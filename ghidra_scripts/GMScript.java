import java.nio.file.Path;

import ghidra.util.Msg;
import it.unive.ghidra.metrics.GMExporter;
import it.unive.ghidra.metrics.base.GMetric;
import it.unive.ghidra.metrics.script.GMBaseScript;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentName;

public class GMScript extends GMBaseScript {
	
	public GMScript() { 
		super();
	}
	
	@Override
	protected void run() throws Exception {		
		GMetric metric = GMetric.initialize(getArgValue(GMScriptArgumentName.METRIC_NAME), getCurrentProgram());
		GMExporter.Type exportType = getArgValue(GMScriptArgumentName.EXPORT_TYPE);
		Path exportPath = getArgValue(GMScriptArgumentName.EXPORT_PATH);
		
		GMExporter.make().addMetric(metric).exportType(exportType).toPath(exportPath);
		Msg.info(this, "Exported to: "+ exportPath.toAbsolutePath());
	}

}
