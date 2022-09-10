package ghidrametrics.base;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import ghidrametrics.base.BaseMetricValue.MetricType;
import ghidrametrics.util.StringUtils;

public class BaseMetricKey {
	private static final String KEY_DESCRIPTION = "description";
	private static final String KEY_FORMULA = "formula";

	private final MetricType type;
	private final String name;
	private final Map<String, String> data;

	public BaseMetricKey(MetricType type, String name) {
		this.type = type;
		this.name = name;
		this.data = new HashMap<String, String>();
	}
	
	public BaseMetricKey(MetricType type, String name, String description, String formula) {
		this(type, name);
		if (description != null)
			data.put(KEY_DESCRIPTION, description);
		if (formula != null)
			data.put(KEY_FORMULA, formula);
	}
	
	protected <T> T getTypedValue(Class<T> typeClz, BaseMetricWrapper wrapper) 
			throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		String getterMethodName = StringUtils.getterMethodName(getName());
		Method getterMethod = wrapper.getClass().getDeclaredMethod(getterMethodName);
		Object value = getterMethod.invoke(wrapper);
		
		if (! typeClz.isAssignableFrom(value.getClass())) {
			throw new RuntimeException("ERROR: key '" +getName()+"' does not return a '"+ typeClz.getName() +"' object for wrapper "+ wrapper.getName());
		}
		
		return typeClz.cast(value);
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
