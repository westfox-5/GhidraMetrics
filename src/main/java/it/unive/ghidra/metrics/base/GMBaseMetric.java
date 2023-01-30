package it.unive.ghidra.metrics.base;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMeasureKey;
import it.unive.ghidra.metrics.base.interfaces.GMMeasure;
import it.unive.ghidra.metrics.util.StringUtils;

//@formatter:off
public abstract class GMBaseMetric<
	M extends GMBaseMetric<M, C, W>, 
	C extends GMBaseMetricController<M, C, W>, 
	W extends GMBaseMetricWindow<M, C, W>>
implements GMMetric {
//@formatter:on

	private boolean initialized = false;
	private final Map<GMMeasureKey, GMMeasure<?>> measuresByKey = new TreeMap<>();
	protected final String name;

	protected final C controller;
	protected final Program program;

	public GMBaseMetric(String name, C controller) {
		this.name = name;

		this.controller = controller;
		this.program = controller.getProgram();
	}

	protected abstract boolean init();
	protected abstract void functionChanged(Function function);

	protected boolean _init() {
		if (!initialized) {
			initialized = false;
			if (getController().getProgram() != null) {
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
	public C getController() {
		return controller;
	}

	@Override
	public GMMeasure<?> getMeasureValue(GMMeasureKey key) {
		if (key == null)
			return null;
		return measuresByKey.get(key);
	}

	@Override
	public Collection<GMMeasure<?>> getMeasures() {
		return measuresByKey.values();
	}

	public void clearMeasures() {
		this.measuresByKey.clear();
	}

	protected <T> void createMeasure(GMMeasureKey key) {
		try {
			var value = getMeasureByReflection(key, this);
			createMeasure(key, value);

		} catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
			controller.printException(e);
		}
	}

	protected <T> void createMeasure(GMMeasureKey key, T value) {
		GMBaseMeasure<T> gmMetricValue = new GMBaseMeasure<>(key, value);
		addMetricValue(gmMetricValue);
	}

	private void addMetricValue(GMMeasure<?> value) {
		if (value != null)
			measuresByKey.put(value.getKey(), value);
	}

	/**
	 * Executes the getter method in the GMMetric object for the GMMeasureKey.name
	 */
	private static final Object getMeasureByReflection(GMMeasureKey key, GMMetric metric)
			throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		String getterMethodName = StringUtils.getterMethodName(key.getName());
		Method getterMethod = metric.getClass().getMethod(getterMethodName);
		return getterMethod != null ? getterMethod.invoke(metric) : null;
	}
}
