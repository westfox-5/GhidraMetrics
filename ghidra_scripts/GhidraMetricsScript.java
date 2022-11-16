import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.GhidraMetricsFactory;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricProvider;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.script.GMBaseScript;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentOption;
import it.unive.ghidra.metrics.script.exceptions.ScriptException;

public class GhidraMetricsScript extends GMBaseScript {

	private final static List<GMScriptArgumentOption> SCRIPT_ARGS;
	private final static String SCRIPT_HELP;

	static {
		List<GMScriptArgumentOption> scriptArgs = Arrays.asList(
				GMScriptArgumentOption.METRIC_NAME, GMScriptArgumentOption.FUNCTION_NAME, 
				GMScriptArgumentOption.EXPORT_TYPE, GMScriptArgumentOption.EXPORT_PATH);
		SCRIPT_ARGS = Collections.unmodifiableList(scriptArgs);
		
		
		List<String> metricNames = GhidraMetricsFactory.allMetrics().stream()
				.map( clz -> GhidraMetricsFactory.metricNameByClass(clz) )
				.collect(Collectors.toList());
		
		List<String> exportTypes = Stream.of(GMExporter.Type.values())
			.map( type -> type.name() )
			.collect(Collectors.toList());
		
		SCRIPT_HELP = "GhidraMetricsScript Usage:\n"
				+ GMScriptArgumentOption.METRIC_NAME.getOption() +": " + metricNames + "\n"
				+ GMScriptArgumentOption.FUNCTION_NAME.getOption()  + ": Name of the function to analyze\n"
				+ GMScriptArgumentOption.EXPORT_TYPE.getOption() + ": " + exportTypes + "\n"
				+ GMScriptArgumentOption.EXPORT_TYPE.getOption() + ": path of directory in which save the export";
	}

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
				provider.locationChanged(new ProgramLocation(getCurrentProgram(), function.getEntryPoint()));
			}

			if (hasArg(GMScriptArgumentOption.EXPORT_TYPE)) {
				final GMExporter.Type exportType = getArgValue(GMScriptArgumentOption.EXPORT_TYPE);
				final Path exportPath = getArgValue(GMScriptArgumentOption.EXPORT_PATH);

				Path result = doExport(provider, exportType, exportPath);
				Msg.info(this, "'" + provider.getMetric().getName() + "' exported to: " + result.toAbsolutePath());
			}

			Msg.info(this, "Script terminated successfully.");

		} catch (Exception e) {
			printHelp();
			Msg.error(this, e.getMessage());

			e.printStackTrace();
		}
	}

	private final Path doExport(GMiMetricProvider provider, GMExporter.Type exportType, Path exportPath)
			throws IOException {
		GMExporter exporter = provider.makeExporter(exportType).toPath(exportPath).build();

		return exporter.export();
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

	@Override
	protected String getScriptHelp() {
		return SCRIPT_HELP;
	}

	@Override
	protected List<GMScriptArgumentOption> getScriptOptions() {
		return SCRIPT_ARGS;
	}
	
	
}
