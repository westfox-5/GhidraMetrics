package it.unive.ghidra.metrics.base.interfaces;

import ghidra.program.util.ProgramLocation;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public interface GMMetricManagerGUI extends GMMetricManager {
	
	GhidraMetricsPlugin getPlugin();

	GMWindowManager getWindowManager();
	
	void locationChanged(ProgramLocation loc);
}
