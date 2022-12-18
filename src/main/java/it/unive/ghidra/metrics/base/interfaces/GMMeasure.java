package it.unive.ghidra.metrics.base.interfaces;

public interface GMMeasure<T> {

	T getValue();

	GMMeasureKey getKey();
}
