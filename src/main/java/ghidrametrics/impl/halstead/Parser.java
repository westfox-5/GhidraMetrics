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
import ghidrametrics.util.StringUtils;

class Parser {
	private final List<String> ops;
	private final List<String> opnds;

	public Parser() {
		this.ops = new ArrayList<>();
		this.opnds = new ArrayList<>();
	}
	
	private Program program;
	
	public Result parse(Program program) {
		this.program = program;
		
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		for (Function function: functions) {
			if (function.isExternal()) {
				continue;
			}
			
			parseFunction(function);
		}
		
		// distinct operators/operands number: number of distinct keys
		Integer _distinctOps = new HashSet<>(ops).size();
		BigDecimal n1 = BigDecimal.valueOf(_distinctOps);
		Integer _distinctOpnds = new HashSet<>(opnds).size();
		BigDecimal n2 = BigDecimal.valueOf(_distinctOpnds);

		// total operators/operands number: union of all keys
		//hWrapper.operators = new ArrayList<>(ops);
		BigDecimal N1 = BigDecimal.valueOf(ops.size());

		//hWrapper.operands =  new ArrayList<>(opnds);
		BigDecimal N2 = BigDecimal.valueOf(opnds.size());
		
		return new Result(n1, n2, N1, N2);
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
	
	public static class Result {
		protected final BigDecimal n1, n2, N1, N2;

		public Result(BigDecimal n1, BigDecimal n2, BigDecimal N1, BigDecimal N2) {
			super();
			this.n1 = n1;
			this.n2 = n2;
			this.N1 = N1;
			this.N2 = N2;
		}
	}
}