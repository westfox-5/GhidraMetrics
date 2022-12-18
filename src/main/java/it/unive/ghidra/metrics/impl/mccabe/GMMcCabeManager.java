package it.unive.ghidra.metrics.impl.mccabe;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricManager;

public class GMMcCabeManager extends GMBaseMetricManager<GMMcCabe, GMMcCabeManager, GMMcCabeWinManager> {

	public GMMcCabeManager(Program program) {
		super(program, GMMcCabe.class);
	}

	public GMMcCabeManager(GhidraMetricsPlugin plugin) {
		super(plugin, GMMcCabe.class, GMMcCabeWinManager.class);
	}

}
