package it.unive.ghidra.metrics.base.interfaces;

public interface GMMetricValue<T> {

	T getValue();

	GMMetricKey getKey();
}
