package it.unive.ghidra.metrics.export;

import java.util.Collection;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.base.GMAbstractMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricManager;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMExporterTXT extends GMAbstractMetricExporter {
	private static final String METRIC_BEGIN_SEPARATOR = "--- BEGIN METRIC";
	private static final String METRIC_END_SEPARATOR = "--- END METRIC";
	private static final String TXT_KEY_VALUE_SEP = ": ";

	public GMExporterTXT(GMiMetricManager manager) {
		super(manager, GMAbstractMetricExporter.Type.TXT);
	}

	@Override
	protected <V> StringBuilder serialize(Collection<GMiMetric> metrics) {
		StringBuilder sb = new StringBuilder();

		metrics.forEach(metric -> {
			sb.append(serializeMetric(metric));
			sb.append(System.lineSeparator());
		});

		return sb;
	}

	/**
	 * A metric object is formatted as:
	 * 
	 * name: metricName
	 * 
	 * metricKey: metricValue
	 */
	private StringBuilder serializeMetric(GMiMetric metric) {
		StringBuilder sb = new StringBuilder();
		Stream<GMiMetricValue<?>> values = metric.getMetrics().stream();

		sb
		.append(METRIC_BEGIN_SEPARATOR + System.lineSeparator())
		.append(format("name", metric.getName()));
		values.forEach(v -> {
			sb.append(format(v.getKey().getName(), v.getValue()));
		});
		sb.append(METRIC_END_SEPARATOR + System.lineSeparator());
		return sb;
	}

	private static final String format(Object key, Object value) {
		return key + TXT_KEY_VALUE_SEP + StringUtils.quotate(value) + System.lineSeparator();
	}
}
