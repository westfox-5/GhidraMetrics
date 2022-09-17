package it.unive.ghidra.metrics.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;

import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetric;
import it.unive.ghidra.metrics.base.GMBaseMetricProvider;
import it.unive.ghidra.metrics.base.GMBaseMetricWinManager;
import it.unive.ghidra.metrics.base.GMBaseWinManager;

public class GMWindowManager extends GMBaseWinManager {
	
	private final GhidraMetricsPlugin plugin;
	
	private JPanel pnlMetricList;
	private JPanel pnlMetricContainer;
	
	public GMWindowManager(GhidraMetricsPlugin plugin) {
		this.plugin = plugin;
	}

	@Override
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void init() {
		for (Class<? extends GMBaseMetric<?,?,?>> metricClz: GMBaseMetric.allMetrics()) {
			pnlMetricList.add(new GMMetricButton(plugin, metricClz));
		}
	}
	
	@Override
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setBorder(new EmptyBorder(5, 5, 5, 5));

		component.setLayout(new BorderLayout(0, 0));
		
		pnlMetricContainer = new JPanel();
		pnlMetricContainer.setVisible(false);
		pnlMetricContainer.setMaximumSize(new Dimension(32767, 30));
		component.add(pnlMetricContainer, BorderLayout.NORTH);
		pnlMetricContainer.setLayout(new BorderLayout(0, 0));
		
		JPanel pnlMetricHeader = new JPanel();
		pnlMetricContainer.add(pnlMetricHeader, BorderLayout.NORTH);
		pnlMetricHeader.setMaximumSize(new Dimension(32767, 30));
		pnlMetricHeader.setLayout(new BoxLayout(pnlMetricHeader, BoxLayout.X_AXIS));
		
		JPanel pnlMetricFooter= new JPanel();
		pnlMetricContainer.add(pnlMetricFooter, BorderLayout.SOUTH);
		
		pnlMetricList = new JPanel();
		component.add(pnlMetricList, BorderLayout.CENTER);
		pnlMetricList.setLayout(new GridLayout(0, 1, 0, 0));
		pnlMetricList.setVisible(true);
		
		return component;
	}
	
	public final 
		<M extends GMBaseMetric<M, P, W>, 
		P extends GMBaseMetricProvider<M, P, W>,
		W extends GMBaseMetricWinManager<M, P, W>>
	void showView(P provider) {
		if (provider == null) {
			pnlMetricContainer.setVisible(false);
			pnlMetricList.setVisible(true);

		} else {
			JComponent component = provider.getWinManager().getComponent();
			pnlMetricContainer.add(component, BorderLayout.CENTER); 

			pnlMetricList.setVisible(false);
			pnlMetricContainer.setVisible(true);			
		}
		
		revalidate();
	}

}
