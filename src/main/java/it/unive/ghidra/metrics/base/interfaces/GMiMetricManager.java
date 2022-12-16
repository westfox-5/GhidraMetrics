package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

import ghidra.program.model.listing.Function;
import it.unive.ghidra.metrics.base.GMAbstractMetricExporter;

public interface GMiMetricManager {

	boolean isInitialized();
		
	GMiMetric getMetric();
	
	Collection<GMiMetric> getExportableMetrics();
	
	void functionChanged(Function fn);
		
	void printException(Exception e);
	
	default GMAbstractMetricExporter.Builder makeExporter(GMAbstractMetricExporter.Type exportType) {
		return GMAbstractMetricExporter.make(exportType, this);
	}

}
