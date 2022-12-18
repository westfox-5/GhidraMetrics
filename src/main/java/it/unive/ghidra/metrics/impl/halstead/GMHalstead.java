package it.unive.ghidra.metrics.impl.halstead;

import java.math.BigDecimal;

import ghidra.program.model.listing.Function;
import it.unive.ghidra.metrics.base.GMBaseMetric;
import it.unive.ghidra.metrics.impl.halstead.GMHalsteadParser.Result;
import it.unive.ghidra.metrics.util.NumberUtils;

public class GMHalstead extends GMBaseMetric<GMHalstead, GMHalsteadManager, GMHalsteadWinManager> {
	public static final String NAME = "Halstead";
	public static final String LOOKUP_NAME = "halstead";

	public static final class GMHalsteadFunction extends GMHalstead {

		private final Function function;

		protected GMHalsteadFunction(GMHalsteadManager manager, Function function) {
			super(NAME, manager);
			this.function = function;
		}

		@Override
		public String getName() {
			return super.getName() + "." + function.getName();
		}

		@Override
		protected GMHalsteadParser getParser() {
			return GMHalsteadParser.functionParser(function);
		}

		public Function getFunction() {
			return function;
		}
	}

	private BigDecimal n1; // no. operators [distinct, total]
	private BigDecimal N1;

	private BigDecimal n2; // no. operands [distinct, total]
	private BigDecimal N2;

	protected GMHalstead(String name, GMHalsteadManager manager) {
		super(name, manager);
	}

	public GMHalstead(GMHalsteadManager manager) {
		this(NAME, manager);
	}

	@Override
	public boolean init() {
		Result result = getParser().parse();

		if (result.ok()) { 
			this.n1 = result.n1;
			this.n2 = result.n2;
			this.N1 = result.N1;
			this.N2 = result.N2;
	
			GMHalsteadKey.ALL_KEYS.forEach(key -> {
				createMetricValue(key);
			});

			return true;
		} 
		
		return false;
	}

	@Override
	protected void functionChanged(Function function) {
		manager.setMetricFn(new GMHalsteadFunction(manager, function));
		manager.getMetricFn().init();
	}

	protected GMHalsteadParser getParser() {
		return GMHalsteadParser.programParser(getManager().getProgram());
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
		return NumberUtils.add(n1, n2);
	}

	/**
	 * Program Length: <strong>N</strong>
	 * 
	 * @return N1 + N2
	 */
	public BigDecimal getProgramLength() {
		return NumberUtils.add(N1, N2);
	}

	/**
	 * Calculated Estimated Program Length: <strong>N^</strong>
	 * 
	 * @return n1*log2(n1) + n2*log2(n2)
	 */
	public BigDecimal getEstimatedLength() {
		BigDecimal n1_log2 = NumberUtils.mul(n1, NumberUtils.log2(n1));
		BigDecimal n2_log2 = NumberUtils.mul(n2, NumberUtils.log2(n2));
		return NumberUtils.add(n1_log2, n2_log2);
	}

	/**
	 * Program Volume: <strong>V</strong>
	 * 
	 * @return N * log2(n)
	 */
	public BigDecimal getVolume() {
		BigDecimal N = getProgramLength();
		BigDecimal n = getVocabulary();
		return NumberUtils.mul(N, NumberUtils.log2(n));
	}

	/**
	 * Difficulty of the program to write/understand: <string>D</strong>
	 * 
	 * @return (n1/2) * (N2/n2)
	 */
	public BigDecimal getDifficulty() {
		BigDecimal a = NumberUtils.div(n1, new BigDecimal(2));
		BigDecimal b = NumberUtils.div(N2, n2);
		return NumberUtils.mul(a, b);
	}

	/**
	 * Effort in coding the program: <strong>E</strong>
	 * 
	 * @return D * V
	 */
	public BigDecimal getEffort() {
		BigDecimal D = getDifficulty();
		BigDecimal V = getVolume();
		return NumberUtils.mul(D, V);
	}

	/**
	 * Time to code the program: <strong>T</strong>
	 * 
	 * @return E / 18
	 */
	public BigDecimal getCodingTime() {
		BigDecimal E = getEffort();
		return NumberUtils.div(E, new BigDecimal(18));
	}

	/**
	 * Estimated number of Errors in the implementation: <strong>B</strong>
	 * 
	 * @return V / 3000
	 */
	public BigDecimal getEstimatedErrors() {
		BigDecimal V = getVolume();
		return NumberUtils.div(V, new BigDecimal(3000));
	}

}
