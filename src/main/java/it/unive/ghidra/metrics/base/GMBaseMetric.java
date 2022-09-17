package it.unive.ghidra.metrics.base;

import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;
import it.unive.ghidra.metrics.impl.halstead.GMHalstead;

public abstract class GMBaseMetric<
	M extends GMBaseMetric<M, P, W>,		// The metric itself
	P extends GMBaseMetricProvider<M, P, W>,		// The provider
	W extends GMBaseMetricWinManager<M, P, W>	// The window manager>
> implements GMiMetric<M, P , W> {
	
	
	
	private static final Map<String, Class<? extends GMBaseMetric<?,?,?>>> metricLookup;
	static {
		metricLookup = new HashMap<>();
		metricLookup.put(GMHalstead.NAME, GMHalstead.class);
	}
	
	public static Class<? extends GMBaseMetric<?,?,?>> metricByName(String name) {
		return metricLookup.get(name);
	}
	public static Collection<Class<? extends GMBaseMetric<?,?,?>>> allMetrics() {
		return metricLookup.values();
	}

	
	
	
	private final Map<GMiMetricKey, GMiMetricValue<?>> metricsByKey = new HashMap<>();
	protected final String name;

	protected final P provider;
	protected final Class<W> winManagerClz;	
	protected final Program program;
	
	protected GMBaseMetric(String name, P provider, Class<W> wmClz) {
		this.name = name;

		this.winManagerClz = wmClz;
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
	
	public Class<W> getWinManagerClass() {
		return winManagerClz;
	}
	
	protected void createMetricValue(GMiMetricKey key) {
		GMMetricValue<?> gmMetricValue = null;
		
		try {
			switch(key.getType()) {
			case NUMERIC: 
				gmMetricValue = GMMetricValue.ofNumeric(key, getNumericValue(key));
				break;
			case STRING:
				gmMetricValue = GMMetricValue.ofString(key, getStringValue(key));
				break;
			default:
				throw new RuntimeException("Metric type not managed: " + key.getType());
			}
			
		// TODO handle these exceptions more gracefully
		} catch (IllegalAccessException x) {
		    x.printStackTrace();
		} catch (InvocationTargetException x) {
		    x.printStackTrace();
		} catch (NoSuchMethodException x) {
		    x.printStackTrace();
		}	
		
		
		if (gmMetricValue != null) {
			metricsByKey.put(key, gmMetricValue);
		}
	}
	
	private BigDecimal getNumericValue(GMiMetricKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		return key.getTypedValue(BigDecimal.class, this);
	}
	private String getStringValue(GMiMetricKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		return key.getTypedValue(String.class, this);
	}
}
