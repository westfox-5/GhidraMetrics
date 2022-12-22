package it.unive.ghidra.metrics.base.interfaces;

public interface GMMetricWindowManager extends GMWindowManager {

	GMMetricManager getManager();

	default GMMetric getMetric() { return getManager().getMetric(); }
}
