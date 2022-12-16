package it.unive.ghidra.metrics.impl.ncd;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.function.Function;

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
import it.unive.ghidra.metrics.base.GMAbstractMetricWindowManager;
import it.unive.ghidra.metrics.base.interfaces.GMiMetricValue;

public class GMNCDWinManager extends GMAbstractMetricWindowManager<GMNCD, GMNCDManager, GMNCDWinManager> {
	private static final String[] TABLE_COLUMNS_DEFINITION = { "File", "NCD Similarity" };
	private static final Function<GMiMetricValue<?>, Object[]> TABLE_ROWS_FUNCTION = metric -> new Object[] {
			metric.getKey().getName(), metric.getValue() };

	private List<File> selectedFiles;

	private JPanel pnlSelection;
	private JPanel pnlNcdContainer;
	private JTable tblNcd;

	public GMNCDWinManager(GMNCDManager manager) {
		super(manager);
	}

	/**
	 * @wbp.parser.entryPoint
	 */
	@Override
	protected JComponent createComponent() {
		JComponent component = new JPanel();
		component.setLayout(new BorderLayout(0, 0));

		pnlSelection = new JPanel();
		pnlSelection.setVisible(true);
		pnlSelection.setBorder(new EmptyBorder(10, 10, 10, 10));
		component.add(pnlSelection, BorderLayout.NORTH);
		pnlSelection.setLayout(new BorderLayout(0, 0));

		JLabel lblNewLabel = new JLabel("Select binary files");
		pnlSelection.add(lblNewLabel, BorderLayout.WEST);

		JButton btnSelectFiles = new JButton("Select");
		pnlSelection.add(btnSelectFiles, BorderLayout.EAST);

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
					selectedFiles = fileChooser.getSelectedFiles();
					getManager().fileSelected();
				}
			});
		}

		pnlNcdContainer = new JPanel();
		pnlNcdContainer.setLayout(new BorderLayout(0, 0));
		component.add(pnlNcdContainer, BorderLayout.CENTER);

		tblNcd = new JTable();
		pnlNcdContainer.add(tblNcd.getTableHeader(), BorderLayout.NORTH);
		pnlNcdContainer.add(tblNcd, BorderLayout.CENTER);
		pnlNcdContainer.setVisible(false);

		return component;
	}

	public void setNcdVisible(boolean visible) {
		this.pnlSelection.setVisible(!visible);
		this.pnlNcdContainer.setVisible(visible);

		if (visible) {
			populateMetricTable(tblNcd, TABLE_COLUMNS_DEFINITION, TABLE_ROWS_FUNCTION);
		}
		refresh();
	}

	public List<File> getSelectedFiles() {
		return selectedFiles;
	}

	public boolean hasSelectedFiles() {
		return selectedFiles != null && !selectedFiles.isEmpty();
	}

}
