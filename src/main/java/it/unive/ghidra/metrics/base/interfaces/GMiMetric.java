package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

public interface GMiMetric<
/* The metric itself */	 M extends GMiMetric<M, P, W>,
/* The provider */       P extends GMiMetricProvider<M, P, W>,
/* The window manager */ W extends GMiMetricWinManager<M, P, W>
> {
	void init();
	
	String getName();
	
	P getProvider();
	
	Collection<GMiMetricValue<?>> getMetrics();
	
	GMiMetricValue<?> getMetricValue(GMiMetricKey key);
}
