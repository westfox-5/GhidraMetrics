package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

public interface GMiMetric {
	void init();

	String getName();

	Collection<GMiMetricValue<?>> getMetrics();

	GMiMetricValue<?> getMetricValue(GMiMetricKey key);
}
