package ghidrametrics.base.ui;

import javax.swing.JComponent;
import javax.swing.JPanel;

import ghidra.program.model.listing.Program;
import ghidrametrics.GhidraMetricsPlugin;
import ghidrametrics.GhidraMetricsProvider;
import ghidrametrics.base.BaseMetricWrapper;

public abstract class BaseMetricProvider<T extends BaseMetricWrapper> {

	private final Class<T> wrapperClz;
	protected final GhidraMetricsPlugin plugin;
	protected T wrapper;
	protected JPanel panel;

	public BaseMetricProvider(GhidraMetricsPlugin plugin, Class<T> wrapperClz) {
		this.plugin = plugin;
		this.wrapperClz = wrapperClz;
	}

	public final T getWrapper() {
		return wrapper;
	}

	public final String getName() {
		return wrapperClz.getSimpleName().replace("Wrapper", "");
	}

	protected abstract T initWrapper();
	protected abstract void buildComponent();
	
	public final void init() {
		initWrapper();
		buildComponent();
	}

	public final Program getCurrentProgram() {
		return plugin.getCurrentProgram();
	}

	public final JComponent getComponent() {
		return panel;
	}
	
	public BaseMetricButton getMetricButton(GhidraMetricsProvider originalProvider) {
		return new BaseMetricButton(this, originalProvider);
	}
}