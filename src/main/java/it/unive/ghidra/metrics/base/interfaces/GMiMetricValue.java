package it.unive.ghidra.metrics.base.interfaces;

public interface GMiMetricValue<T> {

	T getValue();

	GMiMetricKey getKey();
}
