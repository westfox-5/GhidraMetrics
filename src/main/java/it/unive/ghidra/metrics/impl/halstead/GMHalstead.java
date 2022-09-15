package it.unive.ghidra.metrics.impl.halstead;

import java.math.BigDecimal;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.base.GMetric;
import it.unive.ghidra.metrics.impl.halstead.GMHalsteadParser.Result;
import it.unive.ghidra.metrics.util.NumberUtils;

public class GMHalstead extends GMetric {
	public static final String NAME = "HALSTEAD";
	
	private final GMHalsteadParser parser;
	
	BigDecimal n1; // no. operators [distinct, total]
	BigDecimal N1;

	BigDecimal n2; // no. operands [distinct, total]
	BigDecimal N2;
	
	private Function function;
	
	private GMHalstead fnHalstead;
	
	public GMHalstead(Program program) {
		super(NAME, program, GMHalsteadWindowManager.class);
		this.parser = GMHalsteadParser.programParser(program);
	}
	
	public GMHalstead(Function function) {
		super(NAME, function.getProgram(), GMHalsteadWindowManager.class);
		this.parser = GMHalsteadParser.functionParser(function);
		this.function = function;
	}
	
	@Override
	protected void init() {
		clearMetrics();
		Result result = getParser().parse();
		
		this.n1 = result.n1;
		this.n2 = result.n2;
		this.N1 = result.N1;
		this.N2 = result.N2;
				
		GMHalsteadKey.ALL_KEYS.forEach(k -> {
			createMetric(k);
		});
	}

	@Override
	protected void functionChanged(Function fn) {
		fnHalstead = new GMHalstead(fn);
		fnHalstead.init();
	}
	
	private GMHalsteadParser getParser() {
		return parser;
	}
	
	public BigDecimal getNumDistinctOperators() {
		return n1;
	}

	public BigDecimal getNumOperators() {
		return N1;
	}

	public BigDecimal getNumDistinctOperands() {
		return n2;
	}

	public BigDecimal getNumOperands() {
		return N2;
	}

	/** 
	 * Program Vocabulary: <strong>n</strong>
	 * 
	 * @return n1 + n2
	 */
	public BigDecimal getVocabulary() {
		return n1.add(n2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Program Length: <strong>N</strong>
	 * 
	 * @return N1 + N2
	 */
	public BigDecimal getProgramLength() {
		return N1.add(N2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Calculated Estimated Program Length: <strong>N^</strong>
	 * 
	 * @return n1*log2(n1) + n2*log2(n2)
	 */
	public BigDecimal getEstimatedLength() {
		BigDecimal n1_log2 = n1.multiply(NumberUtils.log2(n1));
		BigDecimal n2_log2 = n2.multiply(NumberUtils.log2(n2));
		return n1_log2.add(n2_log2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Program Volume: <strong>V</strong>
	 * 
	 * @return N * log2(n)
	 */
	public BigDecimal getVolume() {
		BigDecimal N = getProgramLength();
		BigDecimal n = getVocabulary();
		return N.multiply(NumberUtils.log2(n), NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Difficulty of the program to write/understand: <string>D</strong>
	 * 
	 * @return (n1/2) * (N2/n2)
	 */
	public BigDecimal getDifficulty() {
		BigDecimal a = n1.divide(new BigDecimal(2), NumberUtils.DEFAULT_CONTEXT);
		BigDecimal b = N2.divide(n2, NumberUtils.DEFAULT_CONTEXT);
		return a.multiply(b, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Effort in coding the program: <strong>E</strong>
	 * 
	 * @return D * V
	 */
	public BigDecimal getEffort() {
		BigDecimal D = getDifficulty();
		BigDecimal V = getVolume();
		return D.multiply(V, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Time to code the program: <strong>T</strong>
	 * 
	 * @return E / 18
	 */
	public BigDecimal getCodingTime() {
		BigDecimal E = getEffort();
		return E.divide(new BigDecimal(18), NumberUtils.DEFAULT_CONTEXT);
	}

	/**
	 * Estimated number of Errors in the implementation: <strong>B</strong>
	 * 
	 * @return V / 3000
	 */
	public BigDecimal getEstimatedErrors() {
		BigDecimal V = getVolume();
		return V.divide(new BigDecimal(3000), NumberUtils.DEFAULT_CONTEXT);
	}

	public GMHalstead getFnHalstead() {
		return fnHalstead;
	}

	public Function getFunction() {
		return function;
	} 
	
}
