package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

import it.unive.ghidra.metrics.export.GMExporter;

public interface GMiExportable {
	
	GMExporter.Builder makeExporter(GMExporter.Type exportType);

	Collection<? extends GMiMetric<?,?,?>> getMetricsToExport();
}
