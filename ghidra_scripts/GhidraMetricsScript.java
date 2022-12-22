import java.nio.file.Path;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.GMBaseScript;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerHeadless;
import it.unive.ghidra.metrics.impl.GhidraMetricFactory;
import it.unive.ghidra.metrics.script.GMScriptArgumentContainer.GMScriptArgumentKey;
import it.unive.ghidra.metrics.script.GMScriptException;

public class GhidraMetricsScript extends GMBaseScript {

	@Override
	protected void run() {
		try {
			parseArgs();

			final String metricName = getArgValue(GMScriptArgumentKey.METRIC);
			GMMetricManagerHeadless manager = GhidraMetricFactory.createHeadless(metricName, getCurrentProgram());

			if (hasArg(GMScriptArgumentKey.FUNCTION)) {
				final String fnName = getArgValue(GMScriptArgumentKey.FUNCTION);

				Function function = findFunctionByName(manager.getProgram(), fnName);
				if (function == null) {
					throw new GMScriptException("Could not find function with name '" + fnName + "'");
				}

				goTo(function);
				manager.functionChanged(function);
				Msg.info(this, "Program location changed to address: function.getEntryPoint()");
			}

			if (hasArg(GMScriptArgumentKey.EXPORT)) {
				final GMMetricExporter.FileFormat fileFormat = getArgValue(GMScriptArgumentKey.EXPORT);
				Path exportDir = null;

				if (hasArg(GMScriptArgumentKey.EXPORT_DIR)) {
					// specific directory from arguments
					exportDir = getArgValue(GMScriptArgumentKey.EXPORT_DIR);
				} else {
					// same directory of input file
					exportDir = Path.of(getProgramFile().getParentFile().getAbsolutePath());
				}

				Path exportPath = Path.of(exportDir.toAbsolutePath().toString(), 
						manager.getMetric().getName() + "_"
						+ getProgramFile().getName() + "." + fileFormat.getExtension());

				GMMetricExporter exporter = manager.makeExporter(fileFormat).toFile(exportPath).build();
				if (exporter == null) {
					throw new GMScriptException("Could not export metric.");
				}

				Path export = exporter.export();
				Msg.info(this, manager.getMetric().getName() + " metric exported to: " + export.toAbsolutePath());
			}

			Msg.info(this, "Script terminated successfully.");

		} catch (Exception e) {
			Msg.error(this, e.getMessage());
			e.printStackTrace();
		}
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
