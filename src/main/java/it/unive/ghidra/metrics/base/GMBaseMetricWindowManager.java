package it.unive.ghidra.metrics.base;

public abstract class GMBaseMetricWindowManager<T extends GMBaseMetric>  extends GMBaseWindowManager {

	private final T metric;

	protected GMBaseMetricWindowManager(T metric) {
		super();
		this.metric = metric;
	}
	
	public abstract void init();

	public T getMetric() {
		return metric;
	}

}
