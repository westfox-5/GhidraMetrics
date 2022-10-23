package it.unive.ghidra.metrics.impl.mccabe;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMAbstractMetricProvider;

public class GMMcCabeProvider extends GMAbstractMetricProvider<GMMcCabe, GMMcCabeProvider, GMMcCabeWinManager> {

	public GMMcCabeProvider(Program program) {
		super(program, GMMcCabe.class);
	}

	public GMMcCabeProvider(GhidraMetricsPlugin plugin) {
		super(plugin, GMMcCabe.class, GMMcCabeWinManager.class);
	}

}
