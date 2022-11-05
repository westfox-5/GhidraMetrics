package it.unive.ghidra.metrics.impl.mccabe;

import java.math.BigDecimal;

import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import it.unive.ghidra.metrics.base.GMAbstractMetric;
import it.unive.ghidra.metrics.impl.mccabe.GMMcCabeParser.Result;
import it.unive.ghidra.metrics.util.GMTaskMonitor;
import it.unive.ghidra.metrics.util.NumberUtils;

public class GMMcCabe extends GMAbstractMetric<GMMcCabe, GMMcCabeProvider, GMMcCabeWinManager> {
	public static final String NAME = "McCabe";
	public static final String METRIC_KEY = "Ciclomatic Complexity";
	
	private BigDecimal e;
	private BigDecimal n;
	private BigDecimal p;

	public GMMcCabe(GMMcCabeProvider provider) {
		super(NAME, provider);
	}

	@Override
	public boolean init() {
		// only on functions
		return true;
	}

	@Override
	protected void functionChanged(Function function) {
		clearMetrics();
		
		
		TaskMonitor monitor = new GMTaskMonitor();
		try {
			GMMcCabeParser parser = new GMMcCabeParser(program);
			Result result = parser.parse(function, monitor);
			
			this.e = result.e;
			this.n = result.n;
			this.p = result.p;
			
			GMMcCabeKey.ALL_KEYS.forEach(key -> {
				createMetricValue(key);
			});

		} catch (CancelledException ce) {
			ce.printStackTrace();
		}
	}

	
	public BigDecimal getNumEdges() {
		return e;
	}
	
	public BigDecimal getNumNodes() {
		return n;
	}
	
	public BigDecimal getNumConnectedComponents() {
		return p;
	}

	/**
	 * McCabe Cyclomatic Complexity: <strong>m</strong>
	 * 
	 * @return e - n + 2p
	 */
	public BigDecimal getComplexity() {
		BigDecimal a = NumberUtils.sub(e, n);
		BigDecimal b = NumberUtils.mul(p, new BigDecimal(2));
		BigDecimal c = NumberUtils.add(a, b);
		
		return NumberUtils.gte0(c) ? c : BigDecimal.ZERO;
	}

}
