package it.unive.ghidra.metrics.impl.halstead;

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
import it.unive.ghidra.metrics.util.NumberUtils;
import it.unive.ghidra.metrics.util.StringUtils;

public abstract class GMHalsteadParser {

	public enum Type {
		PROGRAM, // analysis of entire program
		FUNCTION; // analysis of specific function
	}

	public static final GMHalsteadProgramParser programParser(Program program) {
		return new GMHalsteadProgramParser(program);
	}

	public static final GMHalsteadFunctionParser functionParser(Function function) {
		return new GMHalsteadFunctionParser(function);
	}

	public static final class GMHalsteadProgramParser extends GMHalsteadParser {
		private final Program program;

		protected GMHalsteadProgramParser(Program program) {
			super(GMHalsteadParser.Type.PROGRAM);
			this.program = program;
		}

		@Override
		protected void parseImpl() {
			parseProgram(program);
		}
	}

	public static final class GMHalsteadFunctionParser extends GMHalsteadParser {
		private final Function function;

		protected GMHalsteadFunctionParser(Function function) {
			super(GMHalsteadParser.Type.FUNCTION);
			this.function = function;
		}

		@Override
		protected void parseImpl() {
			parseFunction(function);
		}
	}

	private final GMHalsteadParser.Type parseType;

	private final List<String> ops;
	private final List<String> opnds;

	protected GMHalsteadParser(GMHalsteadParser.Type parseType) {
		this.parseType = parseType;

		this.ops = new ArrayList<>();
		this.opnds = new ArrayList<>();
	}

	protected abstract void parseImpl();

	public Result parse() {
		parseImpl();
		return createResult();
	}

	protected void parseProgram(Program program) {
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		functions.forEach(fn -> parseFunction(fn));
	}

	protected void parseFunction(Function function) {
		if (function.isExternal())
			return;

		AddressSetView body = function.getBody();
		InstructionIterator instructions = function.getProgram().getListing().getInstructions(body, true);
		instructions.forEach(instr -> parseInstruction(instr));
	}

	private void parseInstruction(Instruction instruction) {
		{ /* OPERATOR */
			String op = instruction.getMnemonicString();
			if (StringUtils.isEmpty(op)) {
				throw new RuntimeException("Empty operator found at '" + instruction.getAddressString(false, true) + "'");
			}

			addOperator(op, instruction);
		}

		{ /* OPERANDS */
			int numOperands = instruction.getNumOperands();
			String opnd;
			for (int i = 0; i < numOperands; i++) {
				opnd = instruction.getDefaultOperandRepresentation(i);
				if (StringUtils.isEmpty(opnd)) {
					throw new RuntimeException("Empty operand found at '" + instruction.getAddressString(false, true) + "'");
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

	public GMHalsteadParser.Type getParseType() {
		return parseType;
	}

	private Result createResult() {
		// distinct operators/operands number: number of distinct keys
		Integer _distinctOps = new HashSet<>(ops).size();
		BigDecimal n1 = BigDecimal.valueOf(_distinctOps);
		Integer _distinctOpnds = new HashSet<>(opnds).size();
		BigDecimal n2 = BigDecimal.valueOf(_distinctOpnds);

		// total operators/operands number: union of all keys
		BigDecimal N1 = BigDecimal.valueOf(ops.size());
		BigDecimal N2 = BigDecimal.valueOf(opnds.size());

		return new Result(n1, n2, N1, N2);
	}

	public static class Result {
		protected final BigDecimal n1, n2, N1, N2;

		public Result(BigDecimal n1, BigDecimal n2, BigDecimal N1, BigDecimal N2) {
			super();
			this.n1 = n1;
			this.n2 = n2;
			this.N1 = N1;
			this.N2 = N2;
		}
		
		public boolean ok() {
			return NumberUtils.gt0(n1) && NumberUtils.gt0(n2) && NumberUtils.gt0(N1) && NumberUtils.gt0(N2);
		}
	}
}