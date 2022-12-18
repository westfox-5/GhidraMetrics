package it.unive.ghidra.metrics.impl.halstead;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricManager;

public class GMHalsteadManager extends GMBaseMetricManager<GMHalstead, GMHalsteadManager, GMHalsteadWinManager> {

	public GMHalsteadManager(Program program) {
		super(program, GMHalstead.class);
	}

	public GMHalsteadManager(GhidraMetricsPlugin plugin) {
		super(plugin, GMHalstead.class, GMHalsteadWinManager.class);
	}

	@Override
	protected void init() { 
		// do nothing
	}
}
