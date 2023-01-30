package it.unive.ghidra.metrics.impl.halstead;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricController;

public class GMHalsteadController extends GMBaseMetricController<GMHalstead, GMHalsteadController, GMHalsteadWindow> {

	public GMHalsteadController(Program program) {
		super(program, GMHalstead.class);
	}

	public GMHalsteadController(GhidraMetricsPlugin plugin) {
		super(plugin, GMHalstead.class, GMHalsteadWindow.class);
	}

	@Override
	protected void init() { 
		// do nothing
	}
}
