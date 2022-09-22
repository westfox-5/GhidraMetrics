package it.unive.ghidra.metrics.export.impl;

import java.util.Collection;
import java.util.Iterator;
import java.util.function.BiConsumer;

import it.unive.ghidra.metrics.base.GMBaseMetric;
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
	protected <V> StringBuilder serialize(Collection<GMBaseMetric<?,?,?>> metrics) {
		Iterator<GMBaseMetric<?,?,?>> it = metrics.iterator();
		
		StringBuilder dump = dumpAll(it, (sb, metric) -> {
			sb.append(serialize(metric));
		});
		
		StringBuilder sb = new StringBuilder();
		sb.append("[").append(dump).append("]");

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
	private <M extends GMBaseMetric<?,?,?>> StringBuilder serialize(M metric) {
		StringBuilder sb = new StringBuilder();
		
		sb.append("{") 
			.append(format("name", metric.getName())).append(JSON_SEP)
			.append(format("metrics")).append("{")
				.append(format("keys")).append("[").append(dumpMetricKeys(metric)).append("]").append(JSON_SEP)
				.append(format("values")).append("[").append(dumpMetricValues(metric)).append("]")
			.append("}")
		.append("}");
		
		return sb;
	}

	/**
	 * A metric key is formatted as:
	 * { name, type, info: [{name, value}] }
	 */
	private <M extends GMBaseMetric<?,?,?>> StringBuilder dumpMetricKeys(M metric) {
		Iterator<GMiMetricKey> it = metric.getMetricKeys().iterator();
		
		StringBuilder dump = dumpAll(it, (sb, next) -> {
			sb.append("{")
				.append(format("name", next.getName())).append(JSON_SEP)
				.append(format("type", next.getType().name())).append(JSON_SEP)
				.append(format("info")).append("{");			
					next.getAllInfo().forEach((key) -> {
						sb/*.append("{")*/.append(format(key, next.getInfo(key)))/*.append("}")*/.append(JSON_SEP);
					}); sb.deleteCharAt(sb.length()-1) // remove last ','
				.append("}");
			sb.append("}");
		});
		
		return dump;
	}

	/**
	 * A metric value is formatted as:
	 * { keyName, value } 
	 */
	private <M extends GMBaseMetric<?,?,?>> StringBuilder dumpMetricValues(M metric) {
		Iterator<GMiMetricValue<?>> it = metric.getMetrics().iterator();
		
		StringBuilder dump = dumpAll(it, (sb, next) -> {
			sb.append("{")
				.append(format("keyName", next.getKey().getName())).append(JSON_SEP)
				.append(format("value", next.getValue()))
			.append("}");
		});
		
		return dump;
	}
	
	private <T> StringBuilder dumpAll(Iterator<T> it, BiConsumer<StringBuilder, T> f) {
		StringBuilder sb = new StringBuilder();
		
		while(it.hasNext()) {
			T next = it.next();
			f.accept(sb, next);
			
			if (it.hasNext())
				sb.append(JSON_SEP);
		}
		
		return sb;
	}

	
	private static final String format(Object key) {
		return StringUtils.quotate(key) + JSON_KEY_VALUE_SEP;
	}
	
	private static final String format(Object key, Object value) {
		return StringUtils.quotate(key) + JSON_KEY_VALUE_SEP + StringUtils.quotate(value);
	}
}
