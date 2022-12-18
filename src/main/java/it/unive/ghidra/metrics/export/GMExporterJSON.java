package it.unive.ghidra.metrics.export;

import java.util.Collection;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.base.GMBaseMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManager;
import it.unive.ghidra.metrics.base.interfaces.GMMetricValue;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMExporterJSON extends GMBaseMetricExporter {

	private static final String JSON_SEP = ",";
	private static final String JSON_KEY_VALUE_SEP = ":";

	public GMExporterJSON(GMMetricManager manager) {
		super(manager, GMMetricExporter.Type.JSON);
	}

	@Override
	protected <V> StringBuilder serialize(Collection<GMMetric> metrics) {
		StringBuilder sb = new StringBuilder();

		sb.append("{");
		sb.append(format("metrics")).append("[");

		metrics.forEach(m -> {
			sb.append(serializeMetric(m)).append(JSON_SEP);
		});
		sb.deleteCharAt(sb.length() - 1);

		sb.append("]").append("}");

		return sb;
	}

	/**
	 * A metric object is formatted as: { name, metrics: { keys: [ metricKey ],
	 * values: [ metricValue ] } }
	 */
	private StringBuilder serializeMetric(GMMetric metric) {
		StringBuilder sb = new StringBuilder();

		Stream<GMMetricValue<?>> values = metric.getMeasures().stream();
		Stream<GMMetricKey> keys = metric.getMeasures().stream().map(val -> val.getKey());

		sb.append("{")
		.append(format("name", metric.getName())).append(JSON_SEP)
		.append(format("metrics")).append("{")

		.append(format("keys")).append("[");
		keys.forEach(k -> {
			sb.append(dumpMetricKey(k)).append(JSON_SEP);
		});
		sb.deleteCharAt(sb.length() - 1);
		sb.append("]").append(JSON_SEP)
		
		.append(format("values")).append("[");
		values.forEach(v -> {
			sb.append(dumpMetricValue(v)).append(JSON_SEP);
		});
		sb.deleteCharAt(sb.length() - 1)
		.append("]")
		.append("}")
		.append("}");

		return sb;
	}

	/**
	 * A metric key is formatted as: { name, type, info: [{name, value}] }
	 */
	private StringBuilder dumpMetricKey(GMMetricKey key) {

		StringBuilder sb = new StringBuilder();

		sb.append("{")
		.append(format("name", key.getName())).append(JSON_SEP)
		.append(format("type", key.getType().name())).append(JSON_SEP)
		.append(format("info"))
		.append("{")
			.append(format(GMMetricKey.KEY_INFO_DESCRIPTION, key.getInfo(GMMetricKey.KEY_INFO_DESCRIPTION))).append(JSON_SEP)
			.append(format(GMMetricKey.KEY_INFO_FORMULA, key.getInfo(GMMetricKey.KEY_INFO_FORMULA)))
		.append("}")
		.append("}");

		return sb;
	}

	/**
	 * A metric value is formatted as: { keyName, value }
	 */
	private StringBuilder dumpMetricValue(GMMetricValue<?> value) {

		StringBuilder sb = new StringBuilder();

		sb.append("{")
		.append(format("keyName", value.getKey().getName())).append(JSON_SEP)
		.append(format("value", value.getValue()))
		.append("}");

		return sb;
	}

	private static final String format(Object key) {
		return StringUtils.quotate(key) + JSON_KEY_VALUE_SEP;
	}

	private static final String format(Object key, Object value) {
		return StringUtils.quotate(key) + JSON_KEY_VALUE_SEP + StringUtils.quotate(value);
	}
}
