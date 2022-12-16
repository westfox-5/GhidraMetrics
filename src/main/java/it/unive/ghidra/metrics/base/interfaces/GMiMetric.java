package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

public interface GMiMetric {
	
	GMiMetricManager getManager();
	
	String getName();

	Collection<GMiMetricValue<?>> getMetrics();

	GMiMetricValue<?> getValue(GMiMetricKey key);
}
