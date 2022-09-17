package it.unive.ghidra.metrics.impl.halstead;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.unive.ghidra.metrics.base.GMMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;

public final class GMHalsteadKey extends GMMetricKey {

	private static final GMHalsteadKey NUM_DISTINCT_OPERATORS;
	private static final GMHalsteadKey NUM_DISTINCT_OPERANDS;
	private static final GMHalsteadKey NUM_OPERATORS;
	private static final GMHalsteadKey NUM_OPERANDS;
	private static final GMHalsteadKey VOCABULARY;
	private static final GMHalsteadKey PROGRAM_LENGTH;
	private static final GMHalsteadKey ESTIMATED_LENGTH;
	private static final GMHalsteadKey VOLUME;
	private static final GMHalsteadKey DIFFICULTY;
	private static final GMHalsteadKey EFFORT;
	private static final GMHalsteadKey CODING_TIME;
	private static final GMHalsteadKey ESTIMATED_ERRORS;
	
	private static final Map<String, GMMetricKey> lookupByName;
	
	static {
		lookupByName = new HashMap<>();
		
		NUM_DISTINCT_OPERATORS	= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Num Distinct Operators", "Number of distinct operators.", null);		
		NUM_DISTINCT_OPERANDS	= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Num Distinct Operands", "Number of distinct operands.", null);
		NUM_OPERATORS			= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Num Operators", "Number of operators.", null);
		NUM_OPERANDS			= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Num Operands", "Number of operands.", null);
		VOCABULARY			= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Vocabulary", "Program vocabulary.", "n = n1 + n2");
		PROGRAM_LENGTH		= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Program Length", "Program length.", "N = N1 + N2");
		ESTIMATED_LENGTH	= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Estimated Length", "Program estimated length.", "N^ = n1*log2(n1) + n2*log2(n2)");
		VOLUME				= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Volume", "Program volume.", "V = N*log2(n)");
		DIFFICULTY			= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Difficulty", "Program difficulty.", "D(n1/2) * (N2/n2)");
		EFFORT				= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Effort", "Program effort of programming.", "E = D * V");
		CODING_TIME			= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Coding Time", "Time taken to code the program.", "T = E / 18");
		ESTIMATED_ERRORS	= new GMHalsteadKey(GMiMetricKey.Type.NUMERIC, "Estimated Errors", "Number of estimated errors.", "B = V / 3000");
	}

	public static final List<GMMetricKey> ALL_KEYS = List.of(NUM_DISTINCT_OPERATORS, NUM_DISTINCT_OPERANDS, NUM_OPERATORS, NUM_OPERANDS,
			VOCABULARY, PROGRAM_LENGTH, ESTIMATED_LENGTH, VOLUME, DIFFICULTY, EFFORT, CODING_TIME, ESTIMATED_ERRORS);

	public static final GMMetricKey byName(String name) {
		return lookupByName.get(name);
	}
	
	private GMHalsteadKey(GMiMetricKey.Type type, String name, String description, String formula) {
		super(type, name, description, formula);
		
		lookupByName.put(name, this);
	}
}
