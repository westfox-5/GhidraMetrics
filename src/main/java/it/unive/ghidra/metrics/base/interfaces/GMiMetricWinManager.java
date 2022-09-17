package it.unive.ghidra.metrics.base.interfaces;

public interface GMiMetricWinManager<
	M extends GMiMetric<M, P, W>,			// The metric itself
	P extends GMiMetricProvider<M, P, W>,	// The provider
	W extends GMiMetricWinManager<M, P, W>		// The window manager
	
> extends GMiWinManager {
	
	P getProvider();
	
	M getMetric();
}
