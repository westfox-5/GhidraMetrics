package it.unive.ghidra.metrics.base.interfaces;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.export.GMExporter;

public interface GMiMetricProvider {

	boolean isInitialized();

	GhidraMetricsPlugin getPlugin();

	GMiMetric getMetric();

	GMiWindowManager getWinManager();

	Program getProgram();

	boolean isHeadlessMode();

	void locationChanged(ProgramLocation loc);

	GMExporter.Builder makeExporter(GMExporter.Type exportType);
}
