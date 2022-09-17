import java.nio.file.Path;

import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.GMBaseMetricProvider;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.script.GMBaseScript;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentOption;

public class GhidraMetricsScript extends GMBaseScript {

	@Override
	protected void run() throws Exception {
		parseArgs();
		
		
		GMBaseMetricProvider<?,?,?> provider = GMBaseMetricProvider.GMMetricProviderFactory.createHeadless(getArgValue(GMScriptArgumentOption.METRIC_NAME), getCurrentProgram());
		GMExporter.Type exportType = getArgValue(GMScriptArgumentOption.EXPORT_TYPE);
		Path exportPath = getArgValue(GMScriptArgumentOption.EXPORT_PATH);
		
		GMExporter exporter = provider.makeExporter(exportType)
				.toPath(exportPath)
				.build();
		
		exportPath = exporter.export();
		
		Msg.info(this, "GhidraMetricsScript: "+provider.getMetric().getName()+" exported to: "+ exportPath.toAbsolutePath());
	}

}
