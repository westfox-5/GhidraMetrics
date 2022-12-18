package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

public interface GMMetric {
	
	GMMetricManager getManager();
	
	String getName();

	Collection<GMMetricValue<?>> getMetrics();

	GMMetricValue<?> getValue(GMMetricKey key);
}
