package ghidrametrics.impl.halstead;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidrametrics.base.BaseMetric;
import ghidrametrics.base.BaseMetricKey;
import ghidrametrics.base.BaseMetricWrapper;
import ghidrametrics.util.NumberUtils;
import ghidrametrics.util.StringUtils;

public class HalsteadWrapper extends BaseMetricWrapper {
	public static final String NAME = "HALSTEAD";
	
	private BigDecimal n1, N1; // no. operators [distinct, total]
	private BigDecimal n2, N2; // no. operands [distinct, total]
	
	public HalsteadWrapper(Program program) {
		super(NAME, program);
	}
	
	@Override
	protected BigDecimal getNumericMetric(BaseMetricKey key) {
		HalsteadMetricKey hKey = HalsteadMetricKey.byName(key.getName());
		switch(hKey) {
		case NUM_DISTINCT_OPNDS:return getNumDistinctOperands();
		case NUM_DISTINCT_OPS: 	return getNumDistinctOperators();
		case NUM_OPNDS: 		return getNumOperands();
		case NUM_OPS: 			return getNumOperators();
		case CODING_TIME: 		return getCodingTime();
		case DIFFICULTY: 		return getDifficulty();
		case EFFORT: 			return getEffort();
		case PROGRAM_LENGTH: 	return getProgramLength();
		case ESTIMATED_ERRORS:	return getEstimatedErrors();
		case ESTIMATED_LENGTH: 	return getEstimatedLength();
		case VOCABULARY: 		return getVocabulary();
		case VOLUME: 			return getVolume();
		}
		return null;
	}

	@Override
	protected String getStringMetric(BaseMetricKey key) {
		// no metrics of type 'String'
		return null;
	}
	
	public BaseMetric<?> getMetric(HalsteadMetricKey hKey) {
		return super.getMetric(hKey.getBaseKey());
	}
	
	public static class Builder {
		private final List<String> ops;
		private final List<String> opnds;
		
		private final Program program;
	
		public Builder(Program program) {
			this.program = program;
			this.ops = new ArrayList<>();
			this.opnds = new ArrayList<>();
		}
		
		public HalsteadWrapper build() {
			parseProgram();
			
			HalsteadWrapper hWrapper = new HalsteadWrapper(program);
			// distinct operators/operands number: number of distinct keys
			Integer _distinctOps = new HashSet<>(ops).size();
			hWrapper.n1 = BigDecimal.valueOf(_distinctOps);
			Integer _distinctOpnds = new HashSet<>(opnds).size();
			hWrapper.n2 = BigDecimal.valueOf(_distinctOpnds);

			// total operators/operands number: union of all keys
			//hWrapper.operators = new ArrayList<>(ops);
			hWrapper.N1 = BigDecimal.valueOf(ops.size());

			//hWrapper.operands =  new ArrayList<>(opnds);
			hWrapper.N2 = BigDecimal.valueOf(opnds.size());
			
			for (HalsteadMetricKey hKey: HalsteadMetricKey.values()) {
				hWrapper.addMetric(hKey.getBaseKey());
			}
			
			return hWrapper;
		}
		
		private void parseProgram() {
			FunctionIterator functions = program.getFunctionManager().getFunctions(true);
			for (Function function: functions) {
				if (function.isExternal()) {
					continue;
				}
				
				parseFunction(function);
			}
		}
		
		private void parseFunction(Function function) {
			AddressSetView body = function.getBody();
			InstructionIterator instructions = program.getListing().getInstructions(body, true);
			
			for (Instruction instr: instructions) {
				parseInstruction(instr);
			}
		}
		
		private void parseInstruction(Instruction instruction) {
			{ /* OPERATOR */
				String op = instruction.getMnemonicString();
				if (StringUtils.isEmpty(op)) {
					throw new RuntimeException("Empty operator found at '"+instruction.getAddressString(false, true)+"'");
				}

				addOperator(op, instruction);
			}
			
			
			{ /* OPERANDS */
				int numOperands = instruction.getNumOperands();
				String opnd;
				for (int i=0;i<numOperands;i++) {
					opnd = instruction.getDefaultOperandRepresentation(i);
					if (StringUtils.isEmpty(opnd)) { 
						throw new RuntimeException("Empty operand found at '"+instruction.getAddressString(false, true)+"'");
					}
					
					addOperand(opnd, instruction);
				}
			}
		}
		
		private void addOperator(String opDescriptor, Instruction instruction) {
			ops.add(opDescriptor);
		}
		
		private void addOperand(String opndDescriptor, Instruction instruction) {
			opnds.add(opndDescriptor);
		}
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
	private BigDecimal getVocabulary() {
		return n1.add(n2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Program Length: <strong>N</strong>
	 * 
	 * @return N1 + N2
	 */
	private BigDecimal getProgramLength() {
		return N1.add(N2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/** 
	 * Calculated Estimated Program Length: <strong>N^</strong>
	 * 
	 * @return n1*log2(n1) + n2*log2(n2)
	 */
	private BigDecimal getEstimatedLength() {
		BigDecimal n1_log2 = n1.multiply(NumberUtils.log2(n1));
		BigDecimal n2_log2 = n2.multiply(NumberUtils.log2(n2));
		return n1_log2.add(n2_log2, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Program Volume: <strong>V</strong>
	 * 
	 * @return N * log2(n)
	 */
	private BigDecimal getVolume() {
		BigDecimal N = getProgramLength();
		BigDecimal n = getVocabulary();
		return N.multiply(NumberUtils.log2(n), NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Difficulty of the program to write/understand: <string>D</strong>
	 * 
	 * @return (n1/2) * (N2/n2)
	 */
	private BigDecimal getDifficulty() {
		BigDecimal a = n1.divide(new BigDecimal(2), NumberUtils.DEFAULT_CONTEXT);
		BigDecimal b = N2.divide(n2, NumberUtils.DEFAULT_CONTEXT);
		return a.multiply(b, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Effort in coding the program: <strong>E</strong>
	 * 
	 * @return D * V
	 */
	private BigDecimal getEffort() {
		BigDecimal D = getDifficulty();
		BigDecimal V = getVolume();
		return D.multiply(V, NumberUtils.DEFAULT_CONTEXT);
	}
	
	/**
	 * Time to code the program: <strong>T</strong>
	 * 
	 * @return E / 18
	 */
	private BigDecimal getCodingTime() {
		BigDecimal E = getEffort();
		return E.divide(new BigDecimal(18), NumberUtils.DEFAULT_CONTEXT);
	}

	/**
	 * Estimated number of Errors in the implementation: <strong>B</strong>
	 * 
	 * @return V / 3000
	 */
	private BigDecimal getEstimatedErrors() {
		BigDecimal V = getVolume();
		return V.divide(new BigDecimal(3000), NumberUtils.DEFAULT_CONTEXT);
	}
	

}
