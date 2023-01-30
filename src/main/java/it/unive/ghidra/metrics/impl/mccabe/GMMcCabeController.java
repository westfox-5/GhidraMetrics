package it.unive.ghidra.metrics.impl.mccabe;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricController;

public class GMMcCabeController extends GMBaseMetricController<GMMcCabe, GMMcCabeController, GMMcCabeWindow> {
	
	public GMMcCabeController(Program program) {
		super(program, GMMcCabe.class);
	}

	public GMMcCabeController(GhidraMetricsPlugin plugin) {
		super(plugin, GMMcCabe.class, GMMcCabeWindow.class);
	}

	@Override
	protected void init() {
		// do nothing
	}
}
