package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

public interface GMiMetric {
	boolean init();

	String getName();

	Collection<GMiMetricValue<?>> getMetrics();

	GMiMetricValue<?> getMetricValue(GMiMetricKey key);
}
