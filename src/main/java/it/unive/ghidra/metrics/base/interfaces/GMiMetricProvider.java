package it.unive.ghidra.metrics.base.interfaces;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.export.GMExporter;

public interface GMiMetricProvider<
	M extends GMiMetric<M, P, W>,
	P extends GMiMetricProvider<M, P, W>,
	W extends GMiMetricWinManager<M, P ,W>
> {
	
	GhidraMetricsPlugin getPlugin();

	M getMetric();
	W getWinManager();
	Program getProgram();
	
	boolean isHeadlessMode();
	
	void locationChanged(ProgramLocation loc);
	
	GMExporter.Builder makeExporter(GMExporter.Type exportType);
}
