package it.unive.ghidra.metrics.base.interfaces;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collection;

import it.unive.ghidra.metrics.util.StringUtils;

public interface GMiMetricKey{
	
	public static final String KEY_DESCRIPTION = "description";
	public static final String KEY_FORMULA = "formula";

	public static enum Type { STRING, NUMERIC };
	
	String getName();

	Type getType();
	
	void addInfo(String key, String value);
	String getInfo(String key);
	Collection<String> getAllInfo();
	
	default <T> T getTypedValue(Class<T> typeClz, GMiMetric<?,?,?> metric) 
			throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		String getterMethodName = StringUtils.getterMethodName(getName());
		Method getterMethod = metric.getClass().getMethod(getterMethodName);
		Object value = getterMethod.invoke(metric);
		
		if (! typeClz.isAssignableFrom(value.getClass())) {
			throw new RuntimeException("ERROR: key '" +getName()+"' does not return a '"+ typeClz.getName() +"' object for metric "+ metric.getName());
		}
		
		return typeClz.cast(value);
	}
}
