import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerHeadless;
import it.unive.ghidra.metrics.impl.GhidraMetricFactory;
import it.unive.ghidra.metrics.impl.similarity.GMSimilarityManager;
import it.unive.ghidra.metrics.script.GMScriptArgument;
import it.unive.ghidra.metrics.script.GMScriptArgumentParser;
import it.unive.ghidra.metrics.script.GMScriptException;

public class GhidraMetricsScript extends GhidraScript {

	private final Map<GMScriptArgument<?>, String> args = new HashMap<>();

	private final void parseArgs() throws GMScriptException {
		args.clear();
		Map<GMScriptArgument<?>, String> tmp = GMScriptArgumentParser.parse(getScriptArgs());
		args.putAll(tmp);
	}
	
	private final <T> T getArgValue(GMScriptArgument<T> arg) throws GMScriptException {
		T value = arg.getTypedValue(args.get(arg));
		return value;
	}
	
	private final boolean hasArg(GMScriptArgument<?> arg) {
		return args.containsKey(arg);
	}
	
	@Override
	protected void run() {
		try {
			parseArgs();

			String metricName = getArgValue(GMScriptArgument.ARG_METRIC);
			GMMetricManagerHeadless manager = GhidraMetricFactory.createHeadless(metricName, getCurrentProgram());

			if (hasArg(GMScriptArgument.ARG_FUNCTION)) {
				final String fnName = getArgValue(GMScriptArgument.ARG_FUNCTION);

				Function function = findFunctionByName(manager.getProgram(), fnName);
				if (function == null) {
					throw new GMScriptException("Could not find function with name '" + fnName + "'");
				}

				goTo(function);
				manager.functionChanged(function);
				Msg.info(this, "Program location changed to address: function.getEntryPoint()");
			}
			
			if (manager instanceof GMSimilarityManager) {
				final GMSimilarityManager similarityManager = (GMSimilarityManager)manager;
				final Path ncdInput = getArgValue(GMScriptArgument.ARG_SIMILARITY_INPUT); // argument parser validation assures it exists!
				similarityManager.setSelectedFiles(Arrays.asList(ncdInput));
				similarityManager.compute();
			}
			
			if (hasArg(GMScriptArgument.ARG_EXPORT)) {
				final GMMetricExporter.FileFormat fileFormat = getArgValue(GMScriptArgument.ARG_EXPORT);
				Path exportDir = null;

				if (hasArg(GMScriptArgument.ARG_EXPORT_DIR)) {
					// specific directory from arguments
					exportDir = getArgValue(GMScriptArgument.ARG_EXPORT_DIR);
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
