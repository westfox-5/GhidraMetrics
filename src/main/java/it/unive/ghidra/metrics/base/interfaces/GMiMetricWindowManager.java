package it.unive.ghidra.metrics.base.interfaces;

public interface GMiMetricWindowManager extends GMiWindowManager {

	GMiMetric getMetric();

	GMiMetricProvider getProvider();

	void onMetricInitialized();
}
