package it.unive.ghidra.metrics.base;

public abstract class GMBaseMetricWindowManager<M extends GMBaseMetric<?>> extends GMBaseWindowManager {

	private final GMBaseMetricProvider<M> provider;

	protected GMBaseMetricWindowManager(GMBaseMetricProvider<M> provider) {
		super();
		this.provider = provider;
	}
	
	public abstract void init();

	
	public GMBaseMetricProvider<M> getProvider() {
		return provider;
	}

	public M getMetric() {
		return provider.getMetric();
	}

}
