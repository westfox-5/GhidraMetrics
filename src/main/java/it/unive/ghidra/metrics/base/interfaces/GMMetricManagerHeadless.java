package it.unive.ghidra.metrics.base.interfaces;

import ghidra.program.model.listing.Program;

public interface GMMetricManagerHeadless extends GMMetricManager {

	Program getProgram();
}
