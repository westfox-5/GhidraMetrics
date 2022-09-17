package it.unive.ghidra.metrics.base;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import it.unive.ghidra.metrics.base.GMBaseMetricValue.MetricType;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMBaseMetricKey {
	public static final String KEY_DESCRIPTION = "description";
	public static final String KEY_FORMULA = "formula";

	private final MetricType type;
	private final String name;
	private final Map<String, String> data;

	public GMBaseMetricKey(MetricType type, String name) {
		this.type = type;
		this.name = name;
		this.data = new HashMap<String, String>();
	}
	
	public GMBaseMetricKey(MetricType type, String name, String description, String formula) {
		this(type, name);
		if (description != null)
			data.put(KEY_DESCRIPTION, description);
		if (formula != null)
			data.put(KEY_FORMULA, formula);
	}
	
	protected <T> T getTypedValue(Class<T> typeClz, GMBaseMetric metric) 
			throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		String getterMethodName = StringUtils.getterMethodName(getName());
		Method getterMethod = metric.getClass().getMethod(getterMethodName);
		Object value = getterMethod.invoke(metric);
		
		if (! typeClz.isAssignableFrom(value.getClass())) {
			throw new RuntimeException("ERROR: key '" +getName()+"' does not return a '"+ typeClz.getName() +"' object for metric "+ metric.getName());
		}
		
		return typeClz.cast(value);
	}
	
	public String getName() {
		return name;
	}
	
	public MetricType getType() {
		return type;
	}

	public Map<String, String> getOtherInfo() {
		return data;
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
		GMBaseMetricKey other = (GMBaseMetricKey) obj;
		return Objects.equals(name, other.name);
	}
	
	
}
