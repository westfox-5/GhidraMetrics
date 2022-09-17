package it.unive.ghidra.metrics.base;

import java.math.BigDecimal;
import java.util.Objects;

import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;

public class GMMetricValue<T> implements GMiMetricValue<T>{	
	private final GMiMetricKey key;
	private final T value;
	
	public static GMMetricValue<BigDecimal> ofNumeric(GMiMetricKey key, BigDecimal value) {
		return new GMMetricValue<BigDecimal>(key, value);
	}
	
	public static GMMetricValue<String> ofString(GMiMetricKey key, String value) {
		return new GMMetricValue<String>(key, value);
	}
	
	protected GMMetricValue(GMiMetricKey key, T value) {
		this.key = key;
		this.value = value;
	}

	@Override
	public GMiMetricKey getKey() {
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
		GMMetricValue<?> other = (GMMetricValue<?>) obj;
		return Objects.equals(key, other.key);
	}
	

}
