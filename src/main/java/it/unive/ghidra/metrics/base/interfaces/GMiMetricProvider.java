package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;
import java.util.Collections;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public interface GMiMetricProvider<
	M extends GMiMetric<M, P, W>,
	P extends GMiMetricProvider<M, P, W>,
	W extends GMiMetricWinManager<M, P ,W>
> {
	
	GhidraMetricsPlugin getPlugin();

	M getMetric();
	W getWinManager();
	Program getProgram();
	
	void locationChanged(ProgramLocation loc);
	
	default Collection<? extends M> getMetricsToExport() {
		return Collections.singletonList(getMetric());
	}
}
