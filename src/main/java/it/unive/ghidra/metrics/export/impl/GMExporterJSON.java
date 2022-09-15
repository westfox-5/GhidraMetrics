package it.unive.ghidra.metrics.export.impl;

import java.util.Collection;
import java.util.Iterator;
import java.util.function.BiConsumer;

import it.unive.ghidra.metrics.base.GMBaseKey;
import it.unive.ghidra.metrics.base.GMBaseValue;
import it.unive.ghidra.metrics.base.GMetric;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.util.StringUtils;

public class GMExporterJSON extends GMExporter {

	public GMExporterJSON() {
		super(GMExporter.Type.JSON);
	}

	@Override
	protected <V> StringBuilder serialize(Collection<GMetric> metrics) {
		StringBuilder sb = new StringBuilder();
		
		sb.append("[");
		dumpAll(metrics.iterator(), (sb_, next) -> {
			sb_.append(serialize(next));
		});
		sb.append("]");

		return sb;
	}
	
	/**
	 * A metric object is formatted as:
	 * {
	 * 	name, 
	 * 	metric: { 
	 * 		keys: [ metricKey ],
	 * 		values: [ metricValue ]
	 *  }
	 * }
	 */
	private StringBuilder serialize(GMetric metric) {
		StringBuilder sb = new StringBuilder();
		
		sb.append("{")
			.append("name:").append(StringUtils.quotate(metric.getName())).append(",")
			.append("metrics:").append("{")
				.append("keys:[").append(dumpMetricKeys(metric)).append("],")
				.append("values:[").append(dumpMetricValues(metric)).append("]")
			.append("}")
		.append("}")
		.append(System.lineSeparator());
		
		return sb;
	}

	/**
	 * A metric key is formatted as:
	 * { name, type, info: [{name, value}] }
	 */
	private StringBuilder dumpMetricKeys(GMetric metric) {
		Iterator<GMBaseKey> it = metric.getMetrics().stream().map(m -> m.getKey()).iterator();
		
		StringBuilder dump = dumpAll(it, (sb, next) -> {
			sb.append("{")
				.append("name:").append(StringUtils.quotate(next.getName())).append(",")
				.append("type:").append(StringUtils.quotate(next.getType().name())).append(",")
				.append("info:[");
				next.getOtherInfo().forEach((k,v) -> {
					sb.append("{")
					.append(k).append(":").append(StringUtils.quotate(v))
					.append("},");
				}); sb.deleteCharAt(sb.length()-1) // remove last ','
				.append("]");
			sb.append("}");
		});
		
		return dump;
	}

	/**
	 * A metric value is formatted as:
	 * { keyName, value } 
	 */
	private StringBuilder dumpMetricValues(GMetric metric) {
		Iterator<GMBaseValue<?>> it = metric.getMetrics().iterator();
		
		StringBuilder dump = dumpAll(it, (sb, next) -> {
			sb.append("{")
				.append("keyName:").append(StringUtils.quotate(next.getName())).append(",")
				.append("value:").append(StringUtils.quotate(next.getValue()))
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
				sb.append(",");
		}
		
		return sb;
	}

}
