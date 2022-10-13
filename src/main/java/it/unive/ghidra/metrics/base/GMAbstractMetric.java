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
	P extends GMAbstractMetricProvider<M, P, W>, 
	W extends GMAbstractMetricWindowManager<M, P, W>>
implements GMiMetric {
//@formatter:on

	private boolean initialized = false;
	private final Map<GMiMetricKey, GMiMetricValue<?>> metricsByKey = new TreeMap<>();
	protected final String name;

	protected final P provider;
	protected final Program program;

	public GMAbstractMetric(String name, P provider) {
		this.name = name;

		this.provider = provider;
		this.program = provider.getProgram();
	}

	protected abstract void functionChanged(Function fn);

	protected void _init() {
		if (!initialized) {
			init();
			initialized = true;
		}
	}

	@Override
	public String getName() {
		return name;
	}

	public P getProvider() {
		return provider;
	}

	@Override
	public GMiMetricValue<?> getMetricValue(GMiMetricKey key) {
		if (key == null)
			return null;
		return metricsByKey.get(key);
	}

	@Override
	public Collection<GMiMetricValue<?>> getMetrics() {
		return metricsByKey.values();
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
		GMMetricValue<T> gmMetricValue = new GMMetricValue<>(key, value);
		addMetricValue(gmMetricValue);
	}

	private void addMetricValue(GMiMetricValue<?> value) {
		if (value != null)
			metricsByKey.put(value.getKey(), value);
	}

	private static final Object getValue(GMiMetricKey key, GMiMetric metric)
			throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		String getterMethodName = StringUtils.getterMethodName(key.getName());
		Method getterMethod = metric.getClass().getMethod(getterMethodName);
		return getterMethod.invoke(metric);
	}
}
