package it.unive.ghidra.metrics.base;

import java.util.Objects;

import it.unive.ghidra.metrics.base.interfaces.GMMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMMetricValue;

public class GMBaseMetricValue<T> implements GMMetricValue<T> {
	private final GMMetricKey key;
	private final T value;

	protected GMBaseMetricValue(GMMetricKey key, T value) {
		this.key = key;
		this.value = value;
	}

	@Override
	public GMMetricKey getKey() {
		return key;
	}

	@Override
	public T getValue() {
		return value;
	}

	@Override
	public int hashCode() {
		return Objects.hash(key);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		GMBaseMetricValue<?> other = (GMBaseMetricValue<?>) obj;
		return Objects.equals(key, other.key);
	}

}
