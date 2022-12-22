package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

import ghidra.program.model.listing.Function;
import it.unive.ghidra.metrics.base.GMBaseMetricExporter;

public interface GMMetricManager {

	boolean isInitialized();
		
	GMMetric getMetric();
	
	Collection<GMMetric> getExportableMetrics();
	
	void functionChanged(Function fn);
		
	void printException(Exception e);
	
	default GMBaseMetricExporter.Builder makeExporter(GMMetricExporter.FileFormat exportType) {
		return GMBaseMetricExporter.make(exportType, this);
	}

}
