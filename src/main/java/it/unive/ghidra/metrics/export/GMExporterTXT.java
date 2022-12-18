package it.unive.ghidra.metrics.export;

import java.util.Collection;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.base.GMBaseMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManager;
import it.unive.ghidra.metrics.base.interfaces.GMMetricValue;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMExporterTXT extends GMBaseMetricExporter {
	private static final String METRIC_BEGIN_SEPARATOR = "--- BEGIN METRIC";
	private static final String METRIC_END_SEPARATOR = "--- END METRIC";
	private static final String TXT_KEY_VALUE_SEP = ": ";

	public GMExporterTXT(GMMetricManager manager) {
		super(manager, GMMetricExporter.Type.TXT);
	}

	@Override
	protected <V> StringBuilder serialize(Collection<GMMetric> metrics) {
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
	private StringBuilder serializeMetric(GMMetric metric) {
		StringBuilder sb = new StringBuilder();
		Stream<GMMetricValue<?>> values = metric.getMetrics().stream();

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
