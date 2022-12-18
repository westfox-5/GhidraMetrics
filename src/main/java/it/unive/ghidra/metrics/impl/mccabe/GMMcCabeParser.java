package it.unive.ghidra.metrics.impl.mccabe;

import java.math.BigDecimal;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import it.unive.ghidra.metrics.util.GMTaskMonitor;
import it.unive.ghidra.metrics.util.NumberUtils;

public abstract class GMMcCabeParser {
	
	public enum Type {
		PROGRAM, // analysis of entire program
		FUNCTION; // analysis of specific function
	}
	

	public static final GMMcCabeParser programParser(Program program) {
		return new GMMcCabeProgramParser(program);
	}

	public static final GMMcCabeParser functionParser(Program program, Function function) {
		return new GMMcCabeFunctionParser(program, function);
	}
	
	public static final class GMMcCabeProgramParser extends GMMcCabeParser {

		protected GMMcCabeProgramParser(Program program) {
			super(program, GMMcCabeParser.Type.PROGRAM);
		}

		@Override
		public Result parse() throws CancelledException {
			return parseImpl(null);
		}
	}
	

	public static final class GMMcCabeFunctionParser extends GMMcCabeParser {
		private final Function function;

		protected GMMcCabeFunctionParser(Program program, Function function) {
			super(program, GMMcCabeParser.Type.FUNCTION);
			this.function = function;
		}

		@Override
		public Result parse() throws CancelledException {
			return parseImpl(function);
		}
	}
	
	private final Program program;
	private final GMMcCabeParser.Type parseType;

	protected GMMcCabeParser(Program program, GMMcCabeParser.Type parseType) {
		this.program = program;
		this.parseType = parseType;
	}
	
	public abstract Result parse() throws CancelledException;
	
	protected Result parseImpl(Function function) throws CancelledException {
		BigDecimal nodes = BigDecimal.ZERO;
		BigDecimal edges = BigDecimal.ZERO;
		BigDecimal exits = BigDecimal.ZERO;

		GMTaskMonitor monitor = new GMTaskMonitor();
		
		BasicBlockModel basicBlockModel = new BasicBlockModel(program);
		CodeBlockIterator codeBlockIterator;
		Address entryPoint;
		
		if (function == null) {
			codeBlockIterator = basicBlockModel.getCodeBlocks(monitor);
			entryPoint = program.getMinAddress();
		} else {
			codeBlockIterator = basicBlockModel.getCodeBlocksContaining(function.getBody(), monitor);
			entryPoint = function.getEntryPoint();
		}
		
		while (codeBlockIterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			CodeBlock codeBlock = codeBlockIterator.next();
			nodes = nodes.add(BigDecimal.ONE);
			if (codeBlock.getFlowType().isTerminal()) {
				exits = exits.add(BigDecimal.ONE);
				edges = edges.add(BigDecimal.ONE);
			}
			CodeBlockReferenceIterator destinations = codeBlock.getDestinations(monitor);
			while (destinations.hasNext()) {
				if (monitor.isCancelled()) {
					break;
				}
				CodeBlockReference reference = destinations.next();
				FlowType flowType = reference.getFlowType();
				if (flowType.isIndirect() || flowType.isCall()) {
					continue;
				}
				edges = edges.add(BigDecimal.ONE);
				if (codeBlock.getFlowType().isTerminal() && reference.getDestinationAddress().equals(entryPoint)) {
					edges = edges.subtract(BigDecimal.ONE);
				}
			}
		}

		Result result = new Result(edges, nodes, exits);
		return result;
	}

	public Program getProgram() {
		return program;
	}

	public GMMcCabeParser.Type getParseType() {
		return parseType;
	}

	public static class Result {
		protected final BigDecimal edges, nodes, exits;
		
		public Result(BigDecimal edges, BigDecimal nodes, BigDecimal exits) {
			super();
			this.edges = edges;
			this.nodes = nodes;
			this.exits = exits;
		}
		
		public boolean ok() {
			return NumberUtils.gt0(edges) && NumberUtils.gt0(nodes) && NumberUtils.gt0(exits);
		}
	}
}
