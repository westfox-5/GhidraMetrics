package it.unive.ghidra.metrics.base.interfaces;

public interface GMiMetricValue<T> {
	
	GMiMetricKey getKey();
	
	T getValue();
}
