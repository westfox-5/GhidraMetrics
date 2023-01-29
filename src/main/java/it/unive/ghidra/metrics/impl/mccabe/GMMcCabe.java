package it.unive.ghidra.metrics.impl.mccabe;

import java.math.BigDecimal;

import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import it.unive.ghidra.metrics.base.GMBaseMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMeasure;
import it.unive.ghidra.metrics.base.interfaces.GMMeasureKey;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabeParser.Result;
import it.unive.ghidra.metrics.util.NumberUtils;

public class GMMcCabe extends GMBaseMetric<GMMcCabe, GMMcCabeManager, GMMcCabeWinManager> {
	public static final String NAME = "McCabe";
	public static final String LOOKUP_NAME = "mccabe";
	
	private static final String[] 
			TABLE_COLUMNS = { "Name", "Value", "Formula" };
	private static final java.util.function.Function<GMMeasure<?>, Object[]> 
			TABLE_ROWS_FUNCTION = measure -> new Object[] {
				measure.getKey().getName(), 
				measure.getValue(), 
				measure.getKey().getInfo(GMMeasureKey.KEY_INFO_DESCRIPTION),
				measure.getKey().getInfo(GMMeasureKey.KEY_INFO_FORMULA)
			};


	public static final class GMMcCabeFunction extends GMMcCabe {

		private final Function function;

		protected GMMcCabeFunction(GMMcCabeManager manager, Function function) {
			super(NAME, manager);
			this.function = function;
		}

		@Override
		public String getName() {
			return super.getName() + "." + function.getName();
		}

		@Override
		protected GMMcCabeParser getParser() {
			return GMMcCabeParser.functionParser(program, function);
		}

		public Function getFunction() {
			return function;
		}
	}

	private BigDecimal edges;
	private BigDecimal nodes;
	private BigDecimal exits;
	
	protected GMMcCabe(String name, GMMcCabeManager manager) {
		super(name, manager);
	}

	public GMMcCabe(GMMcCabeManager manager) {
		this(NAME, manager);
	}

	@Override
	public boolean init() {
		try {
			Result result = getParser().parse();

			if (result.ok()) { 
				this.edges = result.edges;
				this.nodes = result.nodes;
				this.exits = result.exits;
	
				GMMcCabeKey.ALL_KEYS.forEach(key -> {
					createMeasure(key);
				});
	
				return true;
			}
			
		} catch(CancelledException e) {
			manager.printException(e);
		}	

		return false;
	}
	
	protected GMMcCabeParser getParser() {
		return GMMcCabeParser.programParser(getManager().getProgram());
	}


	@Override
	protected void functionChanged(Function function) {
		manager.setMetricFn(new GMMcCabeFunction(manager, function));
		manager.getMetricFn().init();
	}

	public BigDecimal getNumEdges() {
		return edges;
	}

	public BigDecimal getNumNodes() {
		return nodes;
	}

	public BigDecimal getNumConnectedComponents() {
		return exits;
	}

	/**
	 * McCabe Cyclomatic Complexity: <strong>m</strong>
	 * 
	 * @return e - n + 2p
	 */
	public BigDecimal getComplexity() {
		BigDecimal a = NumberUtils.sub(edges, nodes);
		BigDecimal b = NumberUtils.mul(exits, new BigDecimal(1));
		BigDecimal c = NumberUtils.add(a, b);

		return NumberUtils.gte0(c) ? c : BigDecimal.ZERO;
	}

	@Override
	public String[] getTableColumns() {
		return TABLE_COLUMNS;
	}

	@Override
	public java.util.function.Function<GMMeasure<?>, Object[]> getTableRowFn() {
		return TABLE_ROWS_FUNCTION;
	}

}
