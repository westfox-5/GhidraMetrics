package ghidrametrics.base;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.listing.Program;

public abstract class BaseMetricWrapper {
	
	protected final String name;
	protected final Program program;
	private final Map<String, BaseMetric<?>> metricsByKey;
	
	/* INIT UTILITIES */
	protected abstract BigDecimal getNumericMetric(BaseMetricKey key);
	protected abstract String getStringMetric(BaseMetricKey key);
	
	private BaseMetric<?> createMetricByKey(BaseMetricKey key) {
		switch(key.getType()) {
		case NUMERIC: return new NumericMetric(key, getNumericMetric(key));
		case STRING:  return new StringMetric(key, getStringMetric(key));
		}

		throw new RuntimeException("Measure Type not managed: " + key.getType());
	}

	protected void addMetric(BaseMetricKey key) {
		BaseMetric<?> measure = createMetricByKey(key);
		metricsByKey.put(measure.getName(), measure);
	}
	/* ------------------- */
	
	protected BaseMetricWrapper(String name, Program program) {
		this.name = name;
		this.program = program;
		this.metricsByKey = new HashMap<String, BaseMetric<?>>();
	}
	
	public String getName() {
		return name;
	}

	public Program getProgram() {
		return program;
	}
	
	public Set<BaseMetric<?>> getMetrics() {
		return Set.copyOf(metricsByKey.values());
	}
	
	public BaseMetric<?> getMetric(String keyName) {
		return metricsByKey.get(keyName);
	}
	
	public BaseMetric<?> getMetric(BaseMetricKey mKey) {
		return getMetric(mKey.getName());
	}
}
