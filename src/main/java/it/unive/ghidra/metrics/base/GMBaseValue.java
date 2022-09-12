package it.unive.ghidra.metrics.base;

import java.math.BigDecimal;
import java.util.Objects;

public abstract class GMBaseValue<V> {
	
	public static enum MetricType {
		NUMERIC, STRING
	}
	
	public static class NumericMetric extends GMBaseValue<BigDecimal> {

		public NumericMetric(GMBaseKey mKey, Double value) {
			this(mKey, BigDecimal.valueOf(value));
		}

		public NumericMetric(GMBaseKey mKey, BigDecimal value) {
			super(mKey, value);
		}
	}
	
	public static class StringMetric extends GMBaseValue<String> {

		public StringMetric(GMBaseKey mKey, String value) {
			super(mKey, value);
		}
	}
	
	
	private final GMBaseKey key;
	private final V value;
	
	public GMBaseValue(GMBaseKey key, V value) {
		super();
		this.key = key;
		this.value = value;
	}
	
	public GMBaseKey getKey() {
		return key;
	}
	public V getValue() {
		return value;
	}
	
	public String getName() {
		return key.getName();
	}

	public MetricType getType() {
		return key.getType();
	}
	
	public String getDescription() {
		return key.getOtherInfo().get(GMBaseKey.KEY_DESCRIPTION);
	}

	public String getFormula() {
		return key.getOtherInfo().get(GMBaseKey.KEY_FORMULA);
	}

	@Override
	public int hashCode() {
		return Objects.hash(key, value);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		GMBaseValue<?> other = (GMBaseValue<?>) obj;
		return Objects.equals(key, other.key) && Objects.equals(value, other.value);
	}
}
