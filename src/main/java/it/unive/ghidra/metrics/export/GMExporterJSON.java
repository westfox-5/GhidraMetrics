package it.unive.ghidra.metrics.export;

import java.util.Collection;
import java.util.stream.Collectors;

import it.unive.ghidra.metrics.base.GMBaseMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMeasure;
import it.unive.ghidra.metrics.base.interfaces.GMMeasureKey;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricController;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMExporterJSON extends GMBaseMetricExporter {

	private static final String JSON_SEP = ",";
	private static final String JSON_KEY_VALUE_SEP = ":";

	public GMExporterJSON(GMMetricController controller) {
		super(controller, GMMetricExporter.FileFormat.JSON);
	}

	@Override
	protected <V> StringBuilder serialize(Collection<GMMetric> metrics) {

		String dumpMetrics = "";
		if (metrics != null) {
			dumpMetrics = metrics.stream().map(m -> serializeMetric(m)).collect(Collectors.joining(JSON_SEP));
		}
				
		StringBuilder sb = new StringBuilder();

		sb.append("{")
		.append(format("metrics")).append("[")
			.append(dumpMetrics)
		.append("]")
		.append("}");

		return sb;
	}

	/**
	 * A metric is formatted as: { name, measures: { keys: [ measureKey ], values: [ measureValue ] } }
	 */
	private String serializeMetric(GMMetric metric) {
		
		Collection<GMMeasure<?>> measures = metric.getMeasures();
		String dumpMeasureValues = "";
		String dumpMeasureKeys = "";
		if (measures != null) {
			dumpMeasureValues = measures.stream().map(m -> dumpMeasure(m)).collect(Collectors.joining(JSON_SEP));
			dumpMeasureKeys = measures.stream().map(m -> dumpMeasureKey(m.getKey())).collect(Collectors.joining(JSON_SEP));
		}
		
		return "{"
			+ format("name", metric.getName()) + ","
			+ format("measures") + "{"
				+ format("keys") + "[" + dumpMeasureKeys + "],"
				+ format("values") + "[" + dumpMeasureValues + "]"
			+"}"
			+"}";
	}

	/**
	 * A measure key is formatted as: { name, type, info: [{infoKey, infoValue}] }
	 */
	private String dumpMeasureKey(GMMeasureKey key) {

		Collection<String> infoKeys = key.getInfoKeys();
		String dumpKeyInfos = "";
		if (infoKeys != null) {
			dumpKeyInfos = infoKeys.stream().map(i -> formatKeyValueAsObject(i, key.getInfo(i))).collect(Collectors.joining(JSON_SEP));
		}
		
		return "{" 
			+ format("name", key.getName()) + ","
			+ format("type", key.getType().name()) + ","
			+ format("info") + "[" + dumpKeyInfos + "]"
			+ "}";	
	}

	/**
	 * A measure is formatted as: { key, value }
	 */
	private String dumpMeasure(GMMeasure<?> value) {
		return "{"+format("key", value.getKey().getName())+JSON_SEP+format("value", value.getValue())+"}";
	}
	
	private static final String formatKeyValueAsObject(String key, Object value) {
		return "{"+format(key, value)+"}";
	}

	private static final String format(Object key) {
		return StringUtils.quotate(key) + JSON_KEY_VALUE_SEP;
	}

	private static final String format(Object key, Object value) {
		return StringUtils.quotate(key) + JSON_KEY_VALUE_SEP + StringUtils.quotate(value);
	}
}