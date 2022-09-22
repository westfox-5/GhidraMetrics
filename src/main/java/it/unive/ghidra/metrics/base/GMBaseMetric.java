package it.unive.ghidra.metrics.base;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;
import it.unive.ghidra.metrics.impl.ncd.GMNCD;
import it.unive.ghidra.metrics.util.StringUtils;

public abstract class GMBaseMetric<
/* The metric itself */	 M extends GMBaseMetric<M, P, W>,
/* The provider */       P extends GMBaseMetricProvider<M, P, W>,
/* The window manager */ W extends GMBaseMetricWinManager<M, P, W>
> implements GMiMetric<M, P , W> {
	
	
	
	private static final Map<String, Class<? extends GMBaseMetric<?,?,?>>> metricLookup;
	static {
		metricLookup = new HashMap<>();
		metricLookup.put(GMHalstead.NAME, GMHalstead.class);
		metricLookup.put(GMNCD.NAME, GMNCD.class);

	}
	
	public static Class<? extends GMBaseMetric<?,?,?>> metricByName(String name) {
		return metricLookup.get(name);
	}
	public static Collection<Class<? extends GMBaseMetric<?,?,?>>> allMetrics() {
		return metricLookup.values();
	}

	
	private final Map<GMiMetricKey, GMiMetricValue<?>> metricsByKey = new TreeMap<>();
	protected final String name;

	protected final P provider;
	protected final Program program;
	
	public GMBaseMetric(String name, P provider) {
		this.name = name;

		this.provider = provider;
		this.program = provider.getProgram();
	}
	
	
	protected abstract void functionChanged(Function fn);

	@Override
	public String getName() {
		return name;
	}
	
	@Override
	public P getProvider() {
		return provider;
	}

	@Override
	public GMiMetricValue<?> getMetricValue(GMiMetricKey key) {
		if (key == null) return null;
		return metricsByKey.get(key);
	}
	
	public Collection<GMiMetricValue<?>> getMetrics() {
		return metricsByKey.values();
	}
	public Collection<GMiMetricKey> getMetricKeys() {
		return metricsByKey.keySet();
	}
	
	public boolean isHeadlessMode() {
		return getProvider().isHeadlessMode();
	}
	
	protected <T> void createMetricValue(GMiMetricKey key) {
		try {			
			var value = getValue(key, this);
			createMetricValue(key, value);
			
		// TODO handle these exceptions more gracefully
		} catch (IllegalAccessException x) {
		    x.printStackTrace();
		} catch (InvocationTargetException x) {
		    x.printStackTrace();
		} catch (NoSuchMethodException x) {
		    x.printStackTrace();
		}
	}
	
	protected <T> void createMetricValue(GMiMetricKey key, T value) {
		GMMetricValue<?> gmMetricValue = new GMMetricValue<T>(key, value);
		addMetricValue(gmMetricValue);
	}
	
	private void addMetricValue(GMiMetricValue<?> value) {
		if (value != null)
			metricsByKey.put(value.getKey(), value);
	}
	
	@SuppressWarnings("unchecked")
	private static final <T> T getValue(GMiMetricKey key, GMiMetric<?, ?, ?> metric)
			throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		String getterMethodName = StringUtils.getterMethodName(key.getName());
		Method getterMethod = metric.getClass().getMethod(getterMethodName);
		Object value = getterMethod.invoke(metric);

		Class<T> typeClass = (Class<T>)key.getTypeClass();
		if (!typeClass.isAssignableFrom(value.getClass())) {
			throw new RuntimeException("ERROR: key '" + key.getName() + "' does not return a '" + typeClass.getName()
					+ "' object for metric " + metric.getName());
		}

		return typeClass.cast(value);
	}
}
