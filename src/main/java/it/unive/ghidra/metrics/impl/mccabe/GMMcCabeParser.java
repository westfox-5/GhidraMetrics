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
import ghidra.util.task.TaskMonitor;

public class GMMcCabeParser {

	private final Program program;

	public GMMcCabeParser(Program program) {
		this.program = program;
	}

	public Result parse(Function function, TaskMonitor monitor) throws CancelledException {
		Address entryPoint = function.getEntryPoint();
		BigDecimal nodes = BigDecimal.ZERO;
		BigDecimal edges = BigDecimal.ZERO;
		BigDecimal exits = BigDecimal.ZERO;

		BasicBlockModel basicBlockModel = new BasicBlockModel(program);
		CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocksContaining(function.getBody(), monitor);
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

	public static class Result {
		protected final BigDecimal e, n, p;

		public Result(BigDecimal e, BigDecimal n, BigDecimal p) {
			this.e = e;
			this.n = n;
			this.p = p;
		}
	}
}
