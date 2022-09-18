package it.unive.ghidra.metrics.base;

import it.unive.ghidra.metrics.base.interfaces.GMiMetricWinManager;

public abstract class GMBaseMetricWinManager <
	M extends GMBaseMetric<M, P, W>,
	P extends GMBaseMetricProvider<M, P, W>,
	W extends GMBaseMetricWinManager<M, P, W>>
extends GMBaseWinManager implements GMiMetricWinManager<M, P, W> {
	
	private final P provider;
	
	public GMBaseMetricWinManager(P provider) {
		super();
		this.provider = provider;
	}

	@Override
	public M getMetric() {
		return getProvider().getMetric();
	}

	@Override
	public P getProvider() {
		return provider;
	}

}
