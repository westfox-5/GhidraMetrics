package ghidrametrics.base;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import ghidrametrics.base.BaseMetric.MetricType;

public class BaseMetricKey {
	private static final String KEY_DESCRIPTION = "description";
	private static final String KEY_FORMULA = "formula";

	public static final BaseMetricKey of(MetricType type, String name) {
		return of(type, name, null, null);
	}

	public static final BaseMetricKey of(MetricType type, String name, String description) {
		return of(type, name, description, null);
	}

	public static final BaseMetricKey of(MetricType type, String name, String description, String formula) {
		BaseMetricKey key = new BaseMetricKey(type, name);
		if (description != null)
			key.data.put(KEY_DESCRIPTION, description);
		if (formula != null)
			key.data.put(KEY_FORMULA, formula);
		return key;
	}

	private final MetricType type;
	private final String name;
	private final Map<String, String> data;

	private BaseMetricKey(MetricType type, String name) {
		this.type = type;
		this.name = name;
		this.data = new HashMap<String, String>();
	}

	public String getName() {
		return name;
	}
	
	public MetricType getType() {
		return type;
	}

	protected String getDescription() {
		return data.get(KEY_DESCRIPTION);
	}

	protected String getFormula() {
		return data.get(KEY_FORMULA);
	}

	@Override
	public int hashCode() {
		return Objects.hash(name);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		BaseMetricKey other = (BaseMetricKey) obj;
		return Objects.equals(name, other.name);
	}
	
	
}
