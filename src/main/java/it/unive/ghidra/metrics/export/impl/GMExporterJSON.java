package it.unive.ghidra.metrics.export.impl;

import java.util.Collection;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMExporterJSON extends GMExporter {
	
	private static final String JSON_SEP = ",";
	private static final String JSON_KEY_VALUE_SEP = ":";

	public GMExporterJSON() {
		super(GMExporter.Type.JSON);
	}

	@Override
	protected <V> StringBuilder serialize(Collection<GMiMetric<?,?,?>> metrics) {
	
		StringBuilder sb = new StringBuilder();
		
		sb.append("{");
			sb.append(format("metrics")).append("[");
			
			metrics.forEach(m ->  {
				sb.append(serializeMetric(m)).append(JSON_SEP);
			});
			
			sb.append("]")
		.append("}");
			
		return sb;
	}
	
	/**
	 * A metric object is formatted as:
	 * {
	 * 	name, 
	 * 	metric: { 
	 * 		keys: [ metricKey ],
	 * 		values: [ metricValue ]
	 *  },
	 *  info: [{name, value}]
	 * }
	 */
	private <M extends GMiMetric<?,?,?>> StringBuilder serializeMetric(M metric) {
		StringBuilder sb = new StringBuilder();
		
		Stream<GMiMetricValue<?>> values = metric.getMetrics().stream();
		Stream<GMiMetricKey> keys = metric.getMetrics().stream().map(val -> val.getKey());
		
		sb.append("{") 
			.append(format("name", metric.getName())).append(JSON_SEP)
			.append(format("metrics")).append("{")
				
			.append(format("keys")).append("[");
				keys.forEach(k -> {
					sb.append(dumpMetricKey(k)).append(JSON_SEP);
				});
				sb.append("]").append(JSON_SEP)
				
			.append(format("values")).append("[");
				values.forEach(v -> {
					sb.append(dumpMetricValue(v)).append(JSON_SEP);
				});
				sb.append("]")
				
			.append("}")
		.append("}");
		
		return sb;
	}

	/**
	 * A metric key is formatted as:
	 * { name, type, info: [{name, value}] }
	 */
	private StringBuilder dumpMetricKey(GMiMetricKey key) {
		
		StringBuilder sb = new StringBuilder();
		
		sb.append("{")
			.append(format("name", key.getName())).append(JSON_SEP)
			.append(format("type", key.getType().name())).append(JSON_SEP)
			.append(format("info"))
			.append("{");
				key.getAllInfo().forEach((info) -> {
					sb.append(format(info, key.getInfo(info))).append(JSON_SEP);
				});
			sb.deleteCharAt(sb.length()-1)
			.append("}")
		.append("}");
		
		return sb;
	}

	/**
	 * A metric value is formatted as:
	 * { keyName, value } 
	 */
	private StringBuilder dumpMetricValue(GMiMetricValue<?> value) {
		
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
