package it.unive.ghidra.metrics.base.interfaces;

public interface GMiMetricWinManager<
	M extends GMiMetric<M, P, W>,
	P extends GMiMetricProvider<M, P, W>,
	W extends GMiMetricWinManager<M, P ,W>
> extends GMiWinManager {

	P getProvider();

	M getMetric();
}
