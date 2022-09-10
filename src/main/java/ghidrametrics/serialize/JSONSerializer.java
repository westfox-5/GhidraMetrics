package ghidrametrics.serialize;

import java.util.Iterator;
import java.util.function.BiConsumer;

import ghidrametrics.GhidraMetricsExporter;
import ghidrametrics.base.BaseMetricKey;
import ghidrametrics.base.BaseMetricValue;
import ghidrametrics.base.BaseMetricWrapper;
import ghidrametrics.util.StringUtils;

/**
 * 
 * {
 * 	name,
 * 	metrics: {
 * 	 keys: [{name, type, info: [{name, value}] }]
 *   values: [{keyName, value}]
 *  }
 * }
 * 
 */
public class JSONSerializer extends Serializer {

	public JSONSerializer() {
		super(GhidraMetricsExporter.Type.JSON);
	}

	@Override
	protected <V> StringBuilder serializeWrapper(BaseMetricWrapper wrapper) {
		StringBuilder sb = new StringBuilder();
		
		sb.append("{")
			.append("name:").append(StringUtils.quotate(wrapper.getName())).append(",")
			.append("metrics:").append("{")
				.append("keys:[").append(dumpMetricKeys(wrapper)).append("],")
				.append("values:[").append(dumpMetricValues(wrapper)).append("]")
			.append("}")
		.append("}")
		.append(System.lineSeparator());
		
		return sb;
	}

	/**
	 * { name, type, info: [{name, value}] }
	 */
	private String dumpMetricKeys(BaseMetricWrapper wrapper) {
		Iterator<BaseMetricKey> it = wrapper.getMetrics().stream().map(m -> m.getKey()).iterator();
		
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
		
		return dump.toString();
	}

	/**
	 * { keyName, value } 
	 */
	private String dumpMetricValues(BaseMetricWrapper wrapper) {
		Iterator<BaseMetricValue<?>> it = wrapper.getMetrics().iterator();
		
		StringBuilder dump = dumpAll(it, (sb, next) -> {
			sb.append("{")
				.append("keyName:").append(StringUtils.quotate(next.getName())).append(",")
				.append("value:").append(StringUtils.quotate(next.getValue()))
			.append("}");
		});
		
		return dump.toString();
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
