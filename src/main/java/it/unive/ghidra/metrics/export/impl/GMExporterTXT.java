package it.unive.ghidra.metrics.export.impl;

import java.util.Collection;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMExporterTXT extends GMExporter {
	private static final String TXT_KEY_VALUE_SEP = ":";

	public GMExporterTXT() {
		super(GMExporter.Type.TXT);
	}

	@Override
	protected <V> StringBuilder serialize(Collection<GMiMetric> metrics) {
		StringBuilder sb = new StringBuilder();
		
		metrics.forEach(metric ->  {
			sb.append(serializeMetric(metric));
			sb.append(System.lineSeparator());
		});
		
		return sb;
	}
	
	/**
	 * A metric object is formatted as:
	 * 
	 * 	name: metricName
	 * 	metrics:
	 * 	metricKey: metricValue
	 * }
	 */
	private StringBuilder serializeMetric(GMiMetric metric) {
		StringBuilder sb = new StringBuilder();
		Stream<GMiMetricValue<?>> values = metric.getMetrics().stream();

		sb.append(format("name", metric.getName()));
		sb.append(format("metrics"));
		values.forEach(v -> {
			sb.append(format(v.getKey().getName(), v.getValue()));
		});
		return sb;
	}

	private static final String format(Object key) {
		return key + TXT_KEY_VALUE_SEP + System.lineSeparator();
	}

	private static final String format(Object key, Object value) {
		return key + TXT_KEY_VALUE_SEP + StringUtils.quotate(value) + System.lineSeparator();
	}
}
