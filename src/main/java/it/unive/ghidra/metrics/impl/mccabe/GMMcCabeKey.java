package it.unive.ghidra.metrics.impl.mccabe;

import java.util.List;

import it.unive.ghidra.metrics.base.GMAbstractMetricKey;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;

public final class GMMcCabeKey extends GMAbstractMetricKey {
	
	private static final GMMcCabeKey NUM_EDGES;
	private static final GMMcCabeKey NUM_NODES;
	private static final GMMcCabeKey NUM_CONNECTED_COMPONENTS;
	private static final GMMcCabeKey COMPLEXITY;
	
	private static int sn = 0;
	
	static {
		//@formatter:off
		NUM_EDGES	= new GMMcCabeKey("Num Edges", "Number of edges.", null);		
		NUM_NODES	= new GMMcCabeKey("Num Nodes", "Number of nodes.", null);
		NUM_CONNECTED_COMPONENTS	= new GMMcCabeKey("Num Connected Components", "Number of connected components.", null);
		COMPLEXITY 	= new GMMcCabeKey("Complexity", "Cyclomatic complexity.", "M = E - N + 2P");
		//@formatter:on
	}
	
	public static final List<GMAbstractMetricKey> ALL_KEYS = List.of(NUM_EDGES, NUM_NODES, NUM_CONNECTED_COMPONENTS, COMPLEXITY);
	
	public GMMcCabeKey(String name, String description, String formula) {
		super(GMiMetricKey.Type.NUMERIC, name, description, formula, sn++);
	}

}
