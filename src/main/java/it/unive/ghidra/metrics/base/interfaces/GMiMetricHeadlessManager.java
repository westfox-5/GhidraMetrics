package it.unive.ghidra.metrics.base.interfaces;

import ghidra.program.model.listing.Program;

public interface GMiMetricHeadlessManager extends GMiMetricManager {

	Program getProgram();
}
