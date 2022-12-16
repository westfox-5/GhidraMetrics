package it.unive.ghidra.metrics.base;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;
import it.unive.ghidra.metrics.util.StringUtils;

//@formatter:off
public abstract class GMAbstractMetric<
	M extends GMAbstractMetric<M, P, W>, 
	P extends GMAbstractMetricManager<M, P, W>, 
	W extends GMAbstractMetricWindowManager<M, P, W>>
implements GMiMetric {
//@formatter:on

	private boolean initialized = false;
	private final Map<GMiMetricKey, GMiMetricValue<?>> metricsByKey = new TreeMap<>();
	protected final String name;

	protected final P manager;
	protected final Program program;

	public GMAbstractMetric(String name, P manager) {
		this.name = name;

		this.manager = manager;
		this.program = manager.getProgram();
	}

	protected abstract boolean init();
	protected abstract void functionChanged(Function function);

	protected boolean _init() {
		if (!initialized) {
			boolean ok = init();
			initialized = ok;
			return ok;
		}
		return true;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public P getManager() {
		return manager;
	}

	@Override
	public GMiMetricValue<?> getValue(GMiMetricKey key) {
		if (key == null)
			return null;
		return metricsByKey.get(key);
	}

	@Override
	public Collection<GMiMetricValue<?>> getMetrics() {
		return metricsByKey.values();
	}

	protected void clearMetrics() {
		this.metricsByKey.clear();
	}

	protected <T> void createMetricValue(GMiMetricKey key) {
		try {
			var value = getMetricValueByKeyName(key, this);
			createMetricValue(key, value);

		} catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			manager.printException(e);
		}
	}

	protected <T> void createMetricValue(GMiMetricKey key, T value) {
		GMMetricValue<T> gmMetricValue = new GMMetricValue<>(key, value);
		addMetricValue(gmMetricValue);
	}

	private void addMetricValue(GMiMetricValue<?> value) {
		if (value != null)
			metricsByKey.put(value.getKey(), value);
	}

	/**
	 * Executes the getter method in the GMiMetric object for the GMiMetricKey.name
	 * object,
	 */
	private static final Object getMetricValueByKeyName(GMiMetricKey key, GMiMetric metric)
			throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		String getterMethodName = StringUtils.getterMethodName(key.getName());
		Method getterMethod = metric.getClass().getMethod(getterMethodName);
		return getterMethod != null ? getterMethod.invoke(metric) : null;
	}
}
