package it.unive.ghidra.metrics;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricProvider;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.ui.GMActionBack;
import it.unive.ghidra.metrics.ui.GMActionExport;
import it.unive.ghidra.metrics.ui.GMWindowManager;

public class GhidraMetricsProvider extends ComponentProvider {

	private final GhidraMetricsPlugin plugin;
	private final GMWindowManager windowManager;

	private GMiMetricProvider activeProvider;

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

		showWindowMain();

		setVisible(true);
	}

	private void createActions() {
		this.actions = new ArrayList<>();

		actions.add(new GMActionBack(plugin));

		for (GMExporter.Type type : GMExporter.Type.values()) {
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

	public void showWindowMain() {
		activeProvider = null;
		refresh();
	}

	public void showWindowMetric(Class<? extends GMiMetric> metricClz) {
		activeProvider = GhidraMetricsFactory.create(getPlugin(), metricClz);

		refresh();
	}

	public void doExport(GMExporter.Type exportType) {
		if (activeProvider == null)
			throw new RuntimeException("ERROR: No active provider is selected!");

		GMExporter exporter = activeProvider.makeExporter(exportType).build();
		if (exporter == null) {
			return;
		}

		try {
			Path exportPath = exporter.export();

			if (exportPath == null) {
				throw new RuntimeException("Could not export selected metric.");
			}

			Msg.info(this, "Export to file: " + exportPath.toAbsolutePath());
			Msg.showInfo(this, getComponent(), "Export", "File exported: " + exportPath.toAbsolutePath());

			// TODO handle these exceptions more gracefully
		} catch (IOException x) {
			x.printStackTrace();
			Msg.showError(this, windowManager.getComponent(), "Could not export", x.getMessage());
		}
	}

	public final void refresh() {
		if (activeProvider != null) {
			// metric view
			setSubTitle(activeProvider.getMetric().getName());
			addLocalActions();

		} else {
			// main view
			setSubTitle(null);
			removeLocalActions();
		}

		windowManager.showWindow(activeProvider);
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
		if (activeProvider == null)
			return;

		if (loc == null)
			return;

		if (!isVisible())
			return;

		activeProvider.locationChanged(loc);
	}
}