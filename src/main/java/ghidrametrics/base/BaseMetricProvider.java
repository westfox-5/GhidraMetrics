package ghidrametrics.base;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ComponentProvider;
import ghidra.program.model.listing.Program;
import ghidrametrics.GhidraMetricsPlugin;

public abstract class BaseMetricProvider<T extends BaseMetricWrapper> extends ComponentProvider {

	private final String metricName;
	protected final GhidraMetricsPlugin plugin;
	protected T wrapper;
	protected JPanel panel;

	public BaseMetricProvider(GhidraMetricsPlugin plugin, String metricName) {
		super(plugin.getTool(), metricName, plugin.getName());
		this.plugin = plugin;
		this.metricName = metricName;
	}

	public final T getWrapper() {
		return wrapper;
	}

	public final String getMetricName() {
		return metricName;
	}

	protected abstract T initWrapper();
	protected abstract void buildComponent();
	
	public final void init() {
		initWrapper();
		buildComponent();
	}

	public final void setVisible(boolean visible) {
		super.setVisible(visible);
		plugin.getProvider().setVisible(!visible);
	}

	public final Program getCurrentProgram() {
		return plugin.getCurrentProgram();
	}

	@Override
	public final JComponent getComponent() {
		return panel;
	}
	
	
}
