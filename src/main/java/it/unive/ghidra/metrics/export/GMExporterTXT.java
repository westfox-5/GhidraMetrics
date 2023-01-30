package it.unive.ghidra.metrics.export;

import java.util.Collection;
import java.util.stream.Collectors;

import it.unive.ghidra.metrics.base.GMBaseMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMeasure;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricController;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMExporterTXT extends GMBaseMetricExporter {
	private static final String METRIC_BEGIN_SEPARATOR = "--- BEGIN METRIC";
	private static final String METRIC_END_SEPARATOR = "--- END METRIC";
	private static final String TXT_KEY_VALUE_SEP = ": ";

	public GMExporterTXT(GMMetricController controller) {
		super(controller, GMMetricExporter.FileFormat.TXT);
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
	 * A metric is formatted as:
	 * 
	 * METRIC_BEGIN_SEPARATOR
	 * name: metricName
	 * measureKey: measureValue
	 * METRIC_END_SEPARATOR
	 * 
	 */
	private String serializeMetric(GMMetric metric) {
		
		Collection<GMMeasure<?>> measures = metric.getMeasures();
		String dumpMeasures = "";
		if (measures != null) {
			dumpMeasures = measures.stream().map(m -> formatKeyValue(m.getKey().getName(), m.getValue())).collect(Collectors.joining(System.lineSeparator()));
		}
		
		return METRIC_BEGIN_SEPARATOR + System.lineSeparator() 
			+ formatKeyValue("name", metric.getName())
			+ dumpMeasures
			+ METRIC_END_SEPARATOR + System.lineSeparator();
	}

	private static final String formatKeyValue(Object key, Object value) {
		return key + TXT_KEY_VALUE_SEP + StringUtils.quotate(value) + System.lineSeparator();
	}
}
