package ghidrametrics.base;

import java.util.Objects;

public class BaseMetricValue<V> {
	
	public static enum MetricType {
		NUMERIC, STRING
	}
	
	private final BaseMetricKey key;
	private final V value;
	
	public BaseMetricValue(BaseMetricKey key, V value) {
		super();
		this.key = key;
		this.value = value;
	}
	
	public BaseMetricKey getKey() {
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
		return key.getOtherInfo().get(BaseMetricKey.KEY_DESCRIPTION);
	}

	public String getFormula() {
		return key.getOtherInfo().get(BaseMetricKey.KEY_FORMULA);
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
		BaseMetricValue<?> other = (BaseMetricValue<?>) obj;
		return Objects.equals(key, other.key) && Objects.equals(value, other.value);
	}
}
