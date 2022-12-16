package it.unive.ghidra.metrics.base.interfaces;

import ghidra.program.util.ProgramLocation;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public interface GMiMetricGUIManager extends GMiMetricManager {
	
	GhidraMetricsPlugin getPlugin();

	GMiWindowManager getWinManager();
	
	void locationChanged(ProgramLocation loc);
}
