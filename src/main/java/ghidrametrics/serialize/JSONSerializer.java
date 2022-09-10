package ghidrametrics.serialize;

import ghidrametrics.GhidraMetricsExporter;
import ghidrametrics.base.BaseMetricWrapper;
import ghidrametrics.util.StringUtils;

/**
 * 
 * {
 * 	name,
 * 	metrics: {
 * 	 keys: [{name, type, description, formula, }]
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
			.append("name: ").append(StringUtils.quotate(wrapper.getName()))
		.append("}");
		
		sb.append(System.lineSeparator());
		
		return sb;
	}
}
