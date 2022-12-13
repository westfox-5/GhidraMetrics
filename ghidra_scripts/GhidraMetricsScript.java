import java.nio.file.Path;

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
			 e.printStackTrace();
			Msg.error(this, e.getMessage());
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
