package it.unive.ghidra.metrics.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.GMBaseMetricValue.NumericMetric;
import it.unive.ghidra.metrics.base.GMBaseMetricValue.StringMetric;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;

public abstract class GMBaseMetric {
	
	private static final Map<String, Class<? extends GMBaseMetric>> metricLookup;
	static {
		metricLookup = new HashMap<>();
		metricLookup.put(GMHalstead.NAME, GMHalstead.class);
		
	}
	
	public static Class<? extends GMBaseMetric> metricByName(String name) {
		return metricLookup.get(name);
	}
	public static Collection<Class<? extends GMBaseMetric>> allMetrics() {
		return metricLookup.values();
	}

	
	
	
	private final Map<String, GMBaseMetricValue<?>> metricsByKey;
	protected final String name;
	
	protected final GMBaseMetricProvider<? extends GMBaseMetric> provider;
	protected final Class<? extends GMBaseMetricWindowManager<?>> wmClz;
	
	protected final boolean headlessMode;
	protected final Program program;
	
	protected GMBaseMetric(String name, GMBaseMetricProvider<? extends GMBaseMetric> provider, Class<? extends GMBaseMetricWindowManager<?>> wmClz) {
		this.name = name;
		this.metricsByKey = new HashMap<String, GMBaseMetricValue<?>>();

		this.provider = provider;
		this.wmClz = wmClz;
		
		this.headlessMode = false;
		this.program = provider.getCurrentProgram();
	}
	
	protected GMBaseMetric(String name, Program program) {
		this.name = name;
		this.metricsByKey = new HashMap<String, GMBaseMetricValue<?>>();
		
		this.provider = null;
		this.wmClz = null;
		
		this.headlessMode = true;
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

	public GMBaseMetricProvider<? extends GMBaseMetric> getProvider() {
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

	
	
	public static <T extends GMBaseMetric> T initialize(Class<T> metricClz, GMBaseMetricProvider<T> provider) {
		try {
			Constructor<T> declaredConstructor = metricClz.getDeclaredConstructor(GMBaseMetricProvider.class);
			T metric = declaredConstructor.newInstance(provider);
			
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
	
	public static <T extends GMBaseMetric> T initializeHeadless(Class<T> metricClz, Program program) {
		try {
			Constructor<T> declaredConstructor = metricClz.getDeclaredConstructor(Program.class);
			T metric = declaredConstructor.newInstance(program);
			
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
	
	
	
	
	@SuppressWarnings("unchecked")
	public static <M extends GMBaseMetric, T extends GMBaseMetricWindowManager<M>> T windowManagerFor(M metric) {
		try {
			Constructor<T> declaredConstructor = ((Class<T>)metric.wmClz).getDeclaredConstructor(metric.getClass());
			T wm = declaredConstructor.newInstance(metric);
			
			return wm;
		
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
