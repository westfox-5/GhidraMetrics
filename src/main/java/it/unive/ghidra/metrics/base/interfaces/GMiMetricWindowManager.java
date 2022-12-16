package it.unive.ghidra.metrics.base.interfaces;

public interface GMiMetricWindowManager extends GMiWindowManager {

	GMiMetricManager getManager();

	GMiMetric getMetric();

	void onMetricInitialized();
}
