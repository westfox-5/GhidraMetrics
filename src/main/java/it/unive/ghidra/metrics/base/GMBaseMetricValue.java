package it.unive.ghidra.metrics.base;

import java.math.BigDecimal;
import java.util.Objects;

public abstract class GMBaseMetricValue<V> {
	
	public static enum MetricType {
		NUMERIC, STRING
	}
	
	public static class NumericMetric extends GMBaseMetricValue<BigDecimal> {

		public NumericMetric(GMBaseMetricKey mKey, Double value) {
			this(mKey, BigDecimal.valueOf(value));
		}

		public NumericMetric(GMBaseMetricKey mKey, BigDecimal value) {
			super(mKey, value);
		}
	}
	
	public static class StringMetric extends GMBaseMetricValue<String> {

		public StringMetric(GMBaseMetricKey mKey, String value) {
			super(mKey, value);
		}
	}
	
	
	private final GMBaseMetricKey key;
	private final V value;
	
	public GMBaseMetricValue(GMBaseMetricKey key, V value) {
		super();
		this.key = key;
		this.value = value;
	}
	
	public GMBaseMetricKey getKey() {
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
		return key.getOtherInfo().get(GMBaseMetricKey.KEY_DESCRIPTION);
	}

	public String getFormula() {
		return key.getOtherInfo().get(GMBaseMetricKey.KEY_FORMULA);
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
		GMBaseMetricValue<?> other = (GMBaseMetricValue<?>) obj;
		return Objects.equals(key, other.key) && Objects.equals(value, other.value);
	}
}
