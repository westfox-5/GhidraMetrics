package it.unive.ghidra.metrics.base.interfaces;

public interface GMMetricWindowManager extends GMWindowManager {

	GMMetricManager getManager();

	GMMetric getMetric();

	void onMetricInitialized();
}
