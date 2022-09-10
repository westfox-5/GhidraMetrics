package ghidrametrics.base;

import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.listing.Program;

public abstract class BaseMetricWrapper {
	
	protected final String name;
	protected final Program program;
	private final Map<String, BaseMetricValue<?>> metricsByKey;
	
	private BigDecimal getNumericMetric(BaseMetricKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		return key.getTypedValue(BigDecimal.class, this);
	}
	private String getStringMetric(BaseMetricKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		return key.getTypedValue(String.class, this);
	}
	
	private BaseMetricValue<?> createMetricByKey(BaseMetricKey key) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		switch(key.getType()) {
		case NUMERIC: return new NumericMetric(key, getNumericMetric(key));
		case STRING:  return new StringMetric(key, getStringMetric(key));
		}

		throw new RuntimeException("Measure Type not managed: " + key.getType());
	}

	protected void createMetric(BaseMetricKey key) {
		try {
			BaseMetricValue<?> metric = createMetricByKey(key);
			
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
	
	protected BaseMetricWrapper(String name, Program program) {
		this.name = name;
		this.program = program;
		this.metricsByKey = new HashMap<String, BaseMetricValue<?>>();
	}
	
	public String getName() {
		return name;
	}

	public Program getProgram() {
		return program;
	}
	
	public Set<BaseMetricValue<?>> getMetrics() {
		return Set.copyOf(metricsByKey.values());
	}
	
	public BaseMetricValue<?> getMetric(String keyName) {
		return metricsByKey.get(keyName);
	}
	
	public BaseMetricValue<?> getMetric(BaseMetricKey mKey) {
		return getMetric(mKey.getName());
	}
}
