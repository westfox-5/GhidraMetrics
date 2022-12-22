package it.unive.ghidra.metrics.impl.similarity;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import it.unive.ghidra.metrics.base.GMBaseMetricWindowManager;

public class GMSimilarityWinManager extends GMBaseMetricWindowManager<GMSimilarity, GMSimilarityManager, GMSimilarityWinManager> {

	private List<Path> selectedFiles;

	private JPanel pnlContainer;
	private JTable tblMeasure;
	private JButton btnClearMeasures;

	public GMSimilarityWinManager(GMSimilarityManager manager) {
		super(manager);
	}

	@Override
	protected boolean init() {
		return true;
	}

	/**
	 * @wbp.parser.entryPoint
	 */
	@Override
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setLayout(new BorderLayout(0, 0));

		pnlContainer = new JPanel();
		pnlContainer.setVisible(true);
		pnlContainer.setBorder(new EmptyBorder(10, 10, 10, 10));
		pnlContainer.setLayout(new BorderLayout(0, 0));
		component.add(pnlContainer, BorderLayout.CENTER);
		

		JPanel pnlTop = new JPanel();
		pnlTop.setLayout(new BorderLayout(0, 0));
		pnlContainer.add(pnlTop, BorderLayout.NORTH);
		
		JLabel lblNewLabel = new JLabel("Select binary files");
		pnlTop.add(lblNewLabel, BorderLayout.WEST);

		JPanel pnlTopBtn = new JPanel();
		pnlTopBtn.setLayout(new FlowLayout());
		pnlTop.add(pnlTopBtn, BorderLayout.EAST);
		
		btnClearMeasures = new JButton("Clear");
		btnClearMeasures.setVisible(false);
		pnlTopBtn.add(btnClearMeasures);
		{
			btnClearMeasures.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent arg0) {
					getManager().clearSelectedFiles();
				}
			});
		}
		
		JButton btnSelectFiles = new JButton("Select");
		pnlTopBtn.add(btnSelectFiles);

		{
			final GhidraFileChooser fileChooser = new GhidraFileChooser(component);
			fileChooser.setMultiSelectionEnabled(true);
			fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			fileChooser.setSelectedFileFilter(new GhidraFileFilter() {
				@Override
				public String getDescription() {
					return "Only binary files";
				}

				@Override
				public boolean accept(File arg0, GhidraFileChooserModel arg1) {
					String type = null;
					try {
						type = Files.probeContentType(arg0.toPath());

					} catch (IOException e) {
						getManager().printException(e);
					}

					if (type == null)
						return true; // assume binary

					if (type.startsWith("text"))
						return false;

					return true; // assume binary
				}
			});

			btnSelectFiles.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent arg0) {
					List<File> _selectedFiles = fileChooser.getSelectedFiles();
					if (_selectedFiles != null) {
						selectedFiles = _selectedFiles.stream().map(f -> f.toPath()).collect(Collectors.toList());
					}
					getManager().fileSelected();
				}
			});
		}

		JPanel pnlMeasureTable = new JPanel();
		pnlMeasureTable.setLayout(new BorderLayout());
		tblMeasure = new JTable();
		pnlMeasureTable.add(tblMeasure.getTableHeader(), BorderLayout.NORTH);
		pnlMeasureTable.add(tblMeasure, BorderLayout.CENTER);
		pnlContainer.add(pnlMeasureTable, BorderLayout.CENTER);
		pnlContainer.setVisible(true);

		return component;
	}

	@Override
	public void revalidate() {
		super.revalidate();
		
		if ( hasSelectedFiles() ) {
			populateMeasureTable(tblMeasure);

			btnClearMeasures.setVisible(true);	
			tblMeasure.setVisible(true);
		} else {
			btnClearMeasures.setVisible(false);	
			tblMeasure.setVisible(false);
		}
	}

	public List<Path> getSelectedFiles() {
		return selectedFiles;
	}

	public boolean hasSelectedFiles() {
		return selectedFiles != null && !selectedFiles.isEmpty();
	}
}
