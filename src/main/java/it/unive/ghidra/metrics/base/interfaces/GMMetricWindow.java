package it.unive.ghidra.metrics.base.interfaces;

public interface GMMetricWindow extends GMWindow {

	GMMetricController getController();

	default GMMetric getMetric() { return getController().getMetric(); }
}
