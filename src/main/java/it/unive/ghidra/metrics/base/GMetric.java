package it.unive.ghidra.metrics.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.swing.JComponent;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.GMBaseValue.NumericMetric;
import it.unive.ghidra.metrics.base.GMBaseValue.StringMetric;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;

public abstract class GMetric {
	
	private static final Map<String, Class<? extends GMetric>> metricLookup;
	static {
		metricLookup = new HashMap<>();
		metricLookup.put(GMHalstead.NAME, GMHalstead.class);
		
	}
	
	public static Class<? extends GMetric> metricByName(String name) {
		return metricLookup.get(name);
	}
	public static Collection<Class<? extends GMetric>> allMetrics() {
		return metricLookup.values();
	}

	private final Map<String, GMBaseValue<?>> metricsByKey;
	
	protected final String name;
	protected final Program program;
	protected JComponent component;
	
	private BigDecimal getNumericMetric(GMBaseKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		return key.getTypedValue(BigDecimal.class, this);
	}
	private String getStringMetric(GMBaseKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		return key.getTypedValue(String.class, this);
	}
	
	private GMBaseValue<?> createMetricByKey(GMBaseKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		switch(key.getType()) {
		case NUMERIC: return new NumericMetric(key, getNumericMetric(key));
		case STRING:  return new StringMetric(key, getStringMetric(key));
		}

		throw new RuntimeException("Measure Type not managed: " + key.getType());
	}

	protected void createMetric(GMBaseKey key) {
		try {
			GMBaseValue<?> metric = createMetricByKey(key);
			
			metricsByKey.put(metric.getName(), metric);

		// TODO handle these exceptions more gracefully
		} catch (IllegalAccessException x) {
		    x.printStackTrace();
		} catch (InvocationTargetException x) {
		    x.printStackTrace();
		} catch (NoSuchMethodException x) {
		    x.printStackTrace();
		}	
	}
	
	protected abstract void buildComponent();
	
	protected GMetric(String name, Program program) {
		this.name = name;
		this.program = program;
		this.metricsByKey = new HashMap<String, GMBaseValue<?>>();
	}
	
	public String getName() {
		return name;
	}

	public Program getProgram() {
		return program;
	}
	
	public JComponent getComponent() {
		return component;
	}
	
	public Set<GMBaseValue<?>> getMetrics() {
		return Set.copyOf(metricsByKey.values());
	}
	
	public GMBaseValue<?> getMetric(String keyName) {
		return metricsByKey.get(keyName);
	}
	
	public GMBaseValue<?> getMetric(GMBaseKey mKey) {
		return getMetric(mKey.getName());
	}
	

	public static <T extends GMetric> T initialize(Class<T> metricClz, Program progam) {
		try {
			Constructor<T> declaredConstructor = metricClz.getDeclaredConstructor(Program.class);
			T metric = declaredConstructor.newInstance(progam);
			
			return metric;

		// TODO handle these exceptions more gracefully
		} catch (InstantiationException x) {
		    x.printStackTrace();
		} catch (IllegalAccessException x) {
		    x.printStackTrace();
		} catch (InvocationTargetException x) {
		    x.printStackTrace();
		} catch (NoSuchMethodException x) {
		    x.printStackTrace();
		}
		
		return null;
	}
	
}
