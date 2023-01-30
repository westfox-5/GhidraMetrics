package it.unive.ghidra.metrics.base.interfaces;

import ghidra.program.model.listing.Program;

public interface GMMetricControllerHeadless extends GMMetricController {

	Program getProgram();
}
