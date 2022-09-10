package ghidrametrics.impl.halstead;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidrametrics.base.BaseMetricKey;
import ghidrametrics.base.BaseMetricValue.MetricType;

public final class HalsteadMetricKey extends BaseMetricKey {

	private static final HalsteadMetricKey NUM_DISTINCT_OPERATORS;
	private static final HalsteadMetricKey NUM_DISTINCT_OPERANDS;
	private static final HalsteadMetricKey NUM_OPERATORS;
	private static final HalsteadMetricKey NUM_OPERANDS;
	private static final HalsteadMetricKey VOCABULARY;
	private static final HalsteadMetricKey PROGRAM_LENGTH;
	private static final HalsteadMetricKey ESTIMATED_LENGTH;
	private static final HalsteadMetricKey VOLUME;
	private static final HalsteadMetricKey DIFFICULTY;
	private static final HalsteadMetricKey EFFORT;
	private static final HalsteadMetricKey CODING_TIME;
	private static final HalsteadMetricKey ESTIMATED_ERRORS;
	
	private static final Map<String, BaseMetricKey> lookupByName;
	
	static {
		lookupByName = new HashMap<>();
		
		NUM_DISTINCT_OPERATORS	= new HalsteadMetricKey(MetricType.NUMERIC, "Num Distinct Operators", "Number of distinct operators.", null);		
		NUM_DISTINCT_OPERANDS	= new HalsteadMetricKey(MetricType.NUMERIC, "Num Distinct Operands", "Number of distinct operands.", null);
		NUM_OPERATORS			= new HalsteadMetricKey(MetricType.NUMERIC, "Num Operators", "Number of operators.", null);
		NUM_OPERANDS			= new HalsteadMetricKey(MetricType.NUMERIC, "Num Operands", "Number of operands.", null);
		VOCABULARY			= new HalsteadMetricKey(MetricType.NUMERIC, "Vocabulary", "Program vocabulary.", "n = n1 + n2");
		PROGRAM_LENGTH		= new HalsteadMetricKey(MetricType.NUMERIC, "Program Length", "Program length.", "N = N1 + N2");
		ESTIMATED_LENGTH	= new HalsteadMetricKey(MetricType.NUMERIC, "Estimated Length", "Program estimated length.", "N^ = n1*log2(n1) + n2*log2(n2)");
		VOLUME				= new HalsteadMetricKey(MetricType.NUMERIC, "Volume", "Program volume.", "V = N*log2(n)");
		DIFFICULTY			= new HalsteadMetricKey(MetricType.NUMERIC, "Difficulty", "Program difficulty.", "D(n1/2) * (N2/n2)");
		EFFORT				= new HalsteadMetricKey(MetricType.NUMERIC, "Effort", "Program effort of programming.", "E = D * V");
		CODING_TIME			= new HalsteadMetricKey(MetricType.NUMERIC, "Coding Time", "Time taken to code the program.", "T = E / 18");
		ESTIMATED_ERRORS	= new HalsteadMetricKey(MetricType.NUMERIC, "Estimated Errors", "Number of estimated errors.", "B = V / 3000");
	}

	public static final List<BaseMetricKey> ALL_KEYS = List.of(NUM_DISTINCT_OPERATORS, NUM_DISTINCT_OPERANDS, NUM_OPERATORS, NUM_OPERANDS,
			VOCABULARY, PROGRAM_LENGTH, ESTIMATED_LENGTH, VOLUME, DIFFICULTY, EFFORT, CODING_TIME, ESTIMATED_ERRORS);

	public static final BaseMetricKey byName(String name) {
		return lookupByName.get(name);
	}
	
	private HalsteadMetricKey(MetricType type, String name, String description, String formula) {
		super(type, name, description, formula);
		
		lookupByName.put(name, this);
	}
}
