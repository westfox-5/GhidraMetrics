import java.io.IOException;
import java.nio.file.Path;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.GhidraMetricsFactory;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricProvider;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.script.GMBaseScript;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentOption;
import it.unive.ghidra.metrics.script.exceptions.ScriptException;

public class GhidraMetricsScript extends GMBaseScript {

	@Override
	protected void run() {
		try {
			parseArgs();

			final String metricName = getArgValue(GMScriptArgumentOption.METRIC_NAME);
			GMiMetricProvider provider = GhidraMetricsFactory.createHeadless(metricName, getCurrentProgram());

			if (hasArg(GMScriptArgumentOption.FUNCTION_NAME)) {
				final String functionName = getArgValue(GMScriptArgumentOption.FUNCTION_NAME);

				Function function = findFunctionByName(provider.getProgram(), functionName);
				if (function == null) {
					throw new ScriptException("Could not find function with name '" + functionName + "'");
				}

				goTo(function);
			}

			if (hasArg(GMScriptArgumentOption.EXPORT_TYPE)) {
				final GMExporter.Type exportType = getArgValue(GMScriptArgumentOption.EXPORT_TYPE);
				final Path exportPath = getArgValue(GMScriptArgumentOption.EXPORT_PATH);

				doExport(provider, exportType, exportPath);
			}

			Msg.error(this, "Script terminated successfully.");

		} catch (Exception e) {
			e.printStackTrace();
			Msg.error(this, e.getMessage());
		}
	}

	private final void doExport(GMiMetricProvider provider, GMExporter.Type exportType, Path exportPath)
			throws IOException {
		GMExporter exporter = provider.makeExporter(exportType).toPath(exportPath).build();

		exportPath = exporter.export();

		Msg.info(this, "'" + provider.getMetric().getName() + "' exported to: " + exportPath.toAbsolutePath());
	}

	private final Function findFunctionByName(Program program, String functionName) {
		FunctionIterator functionIterator = program.getFunctionManager().getFunctions(true);
		while (functionIterator.hasNext()) {
			Function fn = functionIterator.next();
			if (fn.getName().equals(functionName)) {
				return fn;
			}
		}
		return null;
	}
}
