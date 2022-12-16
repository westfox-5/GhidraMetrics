package it.unive.ghidra.metrics;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.GMAbstractMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricGUIManager;
import it.unive.ghidra.metrics.gui.GMActionBack;
import it.unive.ghidra.metrics.gui.GMActionExport;
import it.unive.ghidra.metrics.gui.GMWindowManager;

public class GhidraMetricsProvider extends ComponentProvider {

	private final GhidraMetricsPlugin plugin;
	private final GMWindowManager windowManager;

	private GMiMetricGUIManager metricManager;

	private List<DockingAction> actions;

	public GhidraMetricsProvider(GhidraMetricsPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;

		this.windowManager = new GMWindowManager(plugin);

		createActions();
		buildPanel();
	}

	private void buildPanel() {
		windowManager.init();

		showMainWindow();

		setVisible(true);
	}

	private void createActions() {
		this.actions = new ArrayList<>();

		actions.add(new GMActionBack(plugin));

		for (GMAbstractMetricExporter.Type type : GMAbstractMetricExporter.Type.values()) {
			actions.add(new GMActionExport(plugin, type));
		}
	}

	@Override
	public JComponent getComponent() {
		return windowManager.getComponent();
	}

	public GhidraMetricsPlugin getPlugin() {
		return plugin;
	}

	public void showMainWindow() {
		metricManager = null;
		refresh();
	}

	public void showMetricWindow(String metricName) {
		metricManager = GhidraMetricsFactory.create(metricName, getPlugin());

		refresh();
	}

	public void doExport(GMAbstractMetricExporter.Type exportType) {
		if (metricManager == null)
			throw new RuntimeException("ERROR: no metric is selected!");

		try {
			GMAbstractMetricExporter exporter = metricManager.makeExporter(exportType).withFileChooser().build();
			if ( exporter == null ) {
				return; // no error
			}
			
			Path exportPath = exporter.export();
			if (exportPath == null) {
				throw new RuntimeException("Could not export selected metric.");
			}

			Msg.info(this, "Export to file: " + exportPath.toAbsolutePath());
			Msg.showInfo(this, getComponent(), "Export", "File exported: " + exportPath.toAbsolutePath());

		} catch (IOException e) {
			metricManager.printException(e);
		}
	}

	public final void refresh() {
		if (metricManager != null) {
			// metric view
			setSubTitle(metricManager.getMetric().getName());
			addLocalActions();

		} else {
			// main view
			setSubTitle(null);
			removeLocalActions();
		}

		windowManager.showWindow(metricManager);
		windowManager.refresh();
	}

	private final void addLocalActions() {
		for (DockingAction action : actions) {
			dockingTool.addLocalAction(this, action);
		}
	}

	private final void removeLocalActions() {
		for (DockingAction action : actions) {
			dockingTool.removeLocalAction(this, action);
		}
	}

	public void locationChanged(ProgramLocation loc) {
		if ( metricManager == null || loc == null || !isVisible() ) {
			return;
		}
		
		Function fn = plugin.getCurrentProgram().getFunctionManager().getFunctionContaining(loc.getAddress());
		if ( fn != null ) {
			metricManager.functionChanged(fn);
		}
	}
}