package it.unive.ghidra.metrics.base.interfaces;

import ghidra.program.util.ProgramLocation;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public interface GMMetricControllerGUI extends GMMetricController {
	
	GhidraMetricsPlugin getPlugin();

	GMWindow getWindow();
	
	void locationChanged(ProgramLocation loc);
}
