package it.unive.ghidra.metrics.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.GMBaseMetricValue.NumericMetric;
import it.unive.ghidra.metrics.base.GMBaseMetricValue.StringMetric;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;

public abstract class GMBaseMetric<M extends GMBaseMetric<M>> {
	
	private static final Map<String, Class<? extends GMBaseMetric<?>>> metricLookup;
	static {
		metricLookup = new HashMap<>();
		metricLookup.put(GMHalstead.NAME, GMHalstead.class);
		
	}
	
	public static Class<? extends GMBaseMetric<?>> metricByName(String name) {
		return metricLookup.get(name);
	}
	public static Collection<Class<? extends GMBaseMetric<?>>> allMetrics() {
		return metricLookup.values();
	}

	
	
	
	private final Map<String, GMBaseMetricValue<?>> metricsByKey = new HashMap<String, GMBaseMetricValue<?>>();
	protected final String name;

	protected final GMBaseMetricProvider<M> provider;
	protected final Class<? extends GMBaseMetricWindowManager<? extends GMBaseMetric<?>>> wmClz;
	
	protected final boolean headlessMode;
	protected final Program program;
	
	protected GMBaseMetric(String name, GMBaseMetricProvider<M> provider, Class<? extends GMBaseMetricWindowManager<M>> wmClz) {
		this.name = name;

		this.headlessMode = false;
		this.wmClz = wmClz;
		this.provider = provider;
		this.program = provider.getCurrentProgram();
	}
	
	protected GMBaseMetric(String name, Program program) {
		this.name = name;
		
		this.headlessMode = true;
		this.wmClz = null;
		this.provider = null;
		this.program = program;
	}
		
	protected abstract void init();
	protected abstract void functionChanged(Function fn);
	

	private BigDecimal getNumericMetric(GMBaseMetricKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		return key.getTypedValue(BigDecimal.class, this);
	}
	private String getStringMetric(GMBaseMetricKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		return key.getTypedValue(String.class, this);
	}
	
	private GMBaseMetricValue<?> createMetricByKey(GMBaseMetricKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		switch(key.getType()) {
		case NUMERIC: return new NumericMetric(key, getNumericMetric(key));
		case STRING:  return new StringMetric(key, getStringMetric(key));
		}

		throw new RuntimeException("Measure Type not managed: " + key.getType());
	}

	protected void createMetric(GMBaseMetricKey key) {
		try {
			GMBaseMetricValue<?> metric = createMetricByKey(key);
			
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
	
	public boolean isHeadlessMode() {
		return headlessMode;
	}
	
	public String getName() {
		return name;
	}

	public GMBaseMetricProvider<M> getProvider() {
		return provider;
	}
	
	public Program getProgram() {
		return program;
	}
	
	public Set<GMBaseMetricValue<?>> getMetrics() {
		return Set.copyOf(metricsByKey.values());
	}
	
	public GMBaseMetricValue<?> getMetric(String keyName) {
		return metricsByKey.get(keyName);
	}
	
	public GMBaseMetricValue<?> getMetric(GMBaseMetricKey mKey) {
		return getMetric(mKey.getName());
	}
	
	protected void clearMetrics() {
		this.metricsByKey.clear();
	}
	
	public Class<? extends GMBaseMetricWindowManager<? extends GMBaseMetric<?>>> getWindowManagerClass() {
		return wmClz;
	}
	
	
	public Collection<GMBaseMetric<?>> getMetricsToExport() {
		return Collections.singletonList(this);
	}
	
	public static <M extends GMBaseMetric<?>> M initialize(Class<M> metricClz, GMBaseMetricProvider<M> provider) {
		try {
			Constructor<M> declaredConstructor = metricClz.getDeclaredConstructor(GMBaseMetricProvider.class);
			M metric = declaredConstructor.newInstance(provider);
			
			metric.init();
			
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
	
	public static <M extends GMBaseMetric<?>> M initializeHeadless(Class<M> metricClz, Program program) {
		try {
			Constructor<M> declaredConstructor = metricClz.getDeclaredConstructor(Program.class);
			M metric = declaredConstructor.newInstance(program);
			
			metric.init();
			
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
