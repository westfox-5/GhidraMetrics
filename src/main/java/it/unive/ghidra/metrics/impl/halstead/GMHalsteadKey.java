package it.unive.ghidra.metrics.impl.halstead;

import java.util.List;

import it.unive.ghidra.metrics.base.GMBaseMeasureKey;
import it.unive.ghidra.metrics.base.interfaces.GMMeasureKey;

public final class GMHalsteadKey extends GMBaseMeasureKey {

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

	private static int sn = 0;

	static {
		//@formatter:off
		NUM_DISTINCT_OPERATORS	= new GMHalsteadKey("Num Distinct Operators", "Number of distinct operators.", null);		
		NUM_DISTINCT_OPERANDS	= new GMHalsteadKey("Num Distinct Operands", "Number of distinct operands.", null);
		NUM_OPERATORS			= new GMHalsteadKey("Num Operators", "Number of operators.", null);
		NUM_OPERANDS			= new GMHalsteadKey("Num Operands", "Number of operands.", null);
		VOCABULARY			= new GMHalsteadKey("Vocabulary", "Program vocabulary.", "n = n1 + n2");
		PROGRAM_LENGTH		= new GMHalsteadKey("Program Length", "Program length.", "N = N1 + N2");
		ESTIMATED_LENGTH	= new GMHalsteadKey("Estimated Length", "Program estimated length.", "N^ = n1*log2(n1) + n2*log2(n2)");
		VOLUME				= new GMHalsteadKey("Volume", "Program volume.", "V = N*log2(n)");
		DIFFICULTY			= new GMHalsteadKey("Difficulty", "Program difficulty.", "D = (n1/2) * (N2/n2)");
		EFFORT				= new GMHalsteadKey("Effort", "Program effort of programming.", "E = D * V");
		CODING_TIME			= new GMHalsteadKey("Coding Time", "Time taken to code the program.", "T = E / 18");
		ESTIMATED_ERRORS	= new GMHalsteadKey("Estimated Errors", "Number of estimated errors.", "B = V / 3000");
		//@formatter:on
	}

	//@formatter:off
	public static final List<GMBaseMeasureKey> ALL_KEYS = List.of(NUM_DISTINCT_OPERATORS, NUM_DISTINCT_OPERANDS, NUM_OPERATORS, NUM_OPERANDS,
			VOCABULARY, PROGRAM_LENGTH, ESTIMATED_LENGTH, VOLUME, DIFFICULTY, EFFORT, CODING_TIME, ESTIMATED_ERRORS);
	//@formatter:on

	private GMHalsteadKey(String name, String description, String formula) {
		super(GMMeasureKey.Type.NUMERIC, name, description, formula, sn++);
	}

}
