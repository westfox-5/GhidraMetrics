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
import it.unive.ghidra.metrics.script.GMScriptArgumentContainer.GMScriptArgumentKey;
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
			
			final String metric = getArgValue(GMScriptArgumentKey.METRIC);
			GMiMetricProvider provider = GhidraMetricsFactory.createHeadless(metric, getCurrentProgram());	 

			if (hasArg(GMScriptArgumentKey.FUNCTION)) {
				final String fnName = getArgValue(GMScriptArgumentKey.FUNCTION);

				Function function = findFunctionByName(provider.getProgram(), fnName);
				if (function == null) {
					throw new ScriptException("Could not find function with name '" + fnName + "'");
				}

				goTo(function);
				provider.locationChanged(new ProgramLocation(getCurrentProgram(), function.getEntryPoint()));
				Msg.info(this, "Program location changed to address: function.getEntryPoint()");
			}

			if (hasArg(GMScriptArgumentKey.EXPORT)) {
				final GMExporter.Type exportType = getArgValue(GMScriptArgumentKey.EXPORT);
				final Path exportPath = Path.of(
						getProgramFile().getParentFile().getAbsolutePath(), 
						provider.getMetric().getName() +"_"+ getProgramFile().getName() +"."+ exportType.getExtension());

				GMExporter exporter = provider.makeExporter(exportType).toPath(exportPath).build();
				Path export = exporter.export();
				Msg.info(this, provider.getMetric().getName() + " metric exported to: " + export.toAbsolutePath());
			}

			Msg.info(this, "Script terminated successfully.");

		} catch (Exception e) {
			printHelp();
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

	@Override
	protected String getScriptHelp() {
		return SCRIPT_HELP;
	}

	@Override
	protected List<GMScriptArgumentOption> getScriptOptions() {
		return SCRIPT_ARGS;
	}
	
	
}
