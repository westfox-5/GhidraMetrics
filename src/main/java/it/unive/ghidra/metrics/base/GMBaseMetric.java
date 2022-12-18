package it.unive.ghidra.metrics.base;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMMetricValue;
import it.unive.ghidra.metrics.util.StringUtils;

//@formatter:off
public abstract class GMBaseMetric<
	M extends GMBaseMetric<M, P, W>, 
	P extends GMBaseMetricManager<M, P, W>, 
	W extends GMBaseMetricWindowManager<M, P, W>>
implements GMMetric {
//@formatter:on

	private boolean initialized = false;
	private final Map<GMMetricKey, GMMetricValue<?>> metricsByKey = new TreeMap<>();
	protected final String name;

	protected final P manager;
	protected final Program program;

	public GMBaseMetric(String name, P manager) {
		this.name = name;

		this.manager = manager;
		this.program = manager.getProgram();
	}

	protected abstract boolean init();
	protected abstract void functionChanged(Function function);

	protected boolean _init() {
		if (!initialized) {
			initialized = false;
			if (getManager().getProgram() != null) {
				initialized = init();
			}
		}
		return initialized;
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
	public GMMetricValue<?> getValue(GMMetricKey key) {
		if (key == null)
			return null;
		return metricsByKey.get(key);
	}

	@Override
	public Collection<GMMetricValue<?>> getMetrics() {
		return metricsByKey.values();
	}

	protected void clearMetrics() {
		this.metricsByKey.clear();
	}

	protected <T> void createMetricValue(GMMetricKey key) {
		try {
			var value = getMetricValueByKeyName(key, this);
			createMetricValue(key, value);

		} catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			manager.printException(e);
		}
	}

	protected <T> void createMetricValue(GMMetricKey key, T value) {
		GMBaseMetricValue<T> gmMetricValue = new GMBaseMetricValue<>(key, value);
		addMetricValue(gmMetricValue);
	}

	private void addMetricValue(GMMetricValue<?> value) {
		if (value != null)
			metricsByKey.put(value.getKey(), value);
	}

	/**
	 * Executes the getter method in the GMiMetric object for the GMiMetricKey.name
	 * object,
	 */
	private static final Object getMetricValueByKeyName(GMMetricKey key, GMMetric metric)
			throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		String getterMethodName = StringUtils.getterMethodName(key.getName());
		Method getterMethod = metric.getClass().getMethod(getterMethodName);
		return getterMethod != null ? getterMethod.invoke(metric) : null;
	}
}
