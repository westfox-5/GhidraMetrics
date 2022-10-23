package it.unive.ghidra.metrics.impl.mccabe;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import it.unive.ghidra.metrics.base.GMAbstractMetric;
import it.unive.ghidra.metrics.util.GMTaskMonitor;

public class GMMcCabe extends GMAbstractMetric<GMMcCabe, GMMcCabeProvider, GMMcCabeWinManager> {
	public static final String NAME = "McCabe";
	public static final String METRIC_KEY = "Ciclomatic Complexity";

	public GMMcCabe(GMMcCabeProvider provider) {
		super(NAME, provider);
	}

	@Override
	public void init() {
		// only on functions
	}

	@Override
	protected void functionChanged(Function fn) {
		clearMetrics();
		
		BasicBlockModel basicBlockModel = new BasicBlockModel(program);
		
		TaskMonitor monitor = new GMTaskMonitor();
		try {
			CodeBlockIterator codeBlockIt = basicBlockModel.getCodeBlocksContaining(fn.getBody(), monitor);

			int complexity = calculateComplexity(fn, codeBlockIt, monitor);
			createMetricValue(new GMMcCabeKey(METRIC_KEY), complexity);

		} catch (CancelledException ce) {
			ce.printStackTrace();
		}
	}

	private int calculateComplexity(Function function, CodeBlockIterator codeBlockIterator, TaskMonitor monitor)
			throws CancelledException {
		Address entryPoint = function.getEntryPoint();
		int nodes = 0;
		int edges = 0;
		int exits = 0;
		while (codeBlockIterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			CodeBlock codeBlock = codeBlockIterator.next();
			++nodes;
			if (codeBlock.getFlowType().isTerminal()) {
				++exits;
				++edges;
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
				++edges;
				if (codeBlock.getFlowType().isTerminal() && reference.getDestinationAddress().equals(entryPoint)) {
					// remove the edge I created since it already exists and was counted above at
					// (*)
					--edges;
				}
			}
		}

		int complexity = edges - nodes + exits;
		return Math.max(0, complexity);
	}

}
