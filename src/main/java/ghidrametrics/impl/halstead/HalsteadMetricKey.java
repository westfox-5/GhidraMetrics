package ghidrametrics.impl.halstead;

import java.util.HashMap;
import java.util.Map;

import static ghidrametrics.base.BaseMetric.MetricType;
import ghidrametrics.base.BaseMetricKey;

public enum HalsteadMetricKey {
	NUM_DISTINCT_OPS	(MetricType.NUMERIC, "n1", "Number of distinct operators.", null),
	NUM_DISTINCT_OPNDS	(MetricType.NUMERIC, "n2", "Number of distinct operands.", null),
	NUM_OPS				(MetricType.NUMERIC, "N1", "Number of operators.", null),
	NUM_OPNDS			(MetricType.NUMERIC, "N2", "Number of operands.", null),
	VOCABULARY			(MetricType.NUMERIC, "n", "Program vocabulary.","n = n1 + n2"),
	PROGRAM_LENGTH		(MetricType.NUMERIC, "N", "Program length.", "N = N1 + N2"),
	ESTIMATED_LENGTH	(MetricType.NUMERIC, "N^", "Program estimated length.", "N^ = n1*log2(n1) + n2*log2(n2)"),
	VOLUME				(MetricType.NUMERIC, "V", "Program volume.", "V = N*log2(n)"),
	DIFFICULTY			(MetricType.NUMERIC, "D", "Program difficulty.", "D(n1/2) * (N2/n2)"),
	EFFORT				(MetricType.NUMERIC, "E", "Program effort of programming.", "E = D * V"),
	CODING_TIME			(MetricType.NUMERIC, "T", "Time taken to code the program.", "T = E / 18"),
	ESTIMATED_ERRORS	(MetricType.NUMERIC, "B", "Number of estimated errors.", "B = V / 3000"),
	;

	private final BaseMetricKey key;
	private final String name;

	private HalsteadMetricKey(MetricType type, String name, String description, String formula) {
		this.key = BaseMetricKey.of(type, name, description, formula);
		this.name = name;
	}

	public BaseMetricKey getBaseKey() {
		return this.key;
	}
	
	private static final Map<String, HalsteadMetricKey> lookupByName;
	static {
		lookupByName = new HashMap<String, HalsteadMetricKey>();
		for (HalsteadMetricKey key: HalsteadMetricKey.values()) {
			lookupByName.put(key.name, key);
		}
	}
	
	public static final HalsteadMetricKey byName(String name) {
		return lookupByName.get(name);
	}

}
