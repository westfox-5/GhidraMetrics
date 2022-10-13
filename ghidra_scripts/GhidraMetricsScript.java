import java.io.IOException;
import java.nio.file.Path;

import ghidra.util.Msg;
import it.unive.ghidra.metrics.GhidraMetricsFactory;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricProvider;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.script.GMBaseScript;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentOption;

public class GhidraMetricsScript extends GMBaseScript {

	@Override
	protected void run() throws Exception {
		parseArgs();

		GMiMetricProvider provider = GhidraMetricsFactory
				.createHeadless(getArgValue(GMScriptArgumentOption.METRIC_NAME), getCurrentProgram());

		if (hasArg(GMScriptArgumentOption.EXPORT_TYPE)) {
			doExport(provider);
		}

		Msg.info(this, "Completed!");
	}

	private final void doExport(GMiMetricProvider provider) throws IOException {
		GMExporter.Type exportType = getArgValue(GMScriptArgumentOption.EXPORT_TYPE);
		Path exportPath = getArgValue(GMScriptArgumentOption.EXPORT_PATH);

		GMExporter exporter = provider.makeExporter(exportType).toPath(exportPath).build();

		exportPath = exporter.export();

		Msg.info(this, "'" + provider.getMetric().getName() + "' exported to: " + exportPath.toAbsolutePath());
	}

}
