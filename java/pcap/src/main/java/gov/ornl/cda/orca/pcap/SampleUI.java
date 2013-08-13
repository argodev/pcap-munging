package gov.ornl.cda.orca.pcap;

import java.io.File;
import java.util.List;

import gov.ornl.cda.orca.pcap.utils.TextBoxAppender;

import org.apache.commons.lang3.SystemUtils;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.EnhancedPatternLayout;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.custom.CTabItem;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.wb.swt.SWTResourceManager;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.ModifyEvent;

public class SampleUI {

	// set up logging
	static Logger logger = LogManager.getLogger(AttackProjector.class.getName());

	protected Shell shell;
	private static AttackProjector projector = null;;
	
	private static Text sourceFilePath;
	private static Text targetFilePath;
	private static Text sourceVictimIp;
	private static Text targetVictimIp;
	private static Text loggingTextBox;
	private static Text outputFilePath;
	private static Text winEditCapPath;
	private static Text winBitTwistePath;
	private static Text winMergeCapPath;
	private static Text winCapInfosPath;
	private static Text winWinDumpPath;
	private static Text winTsharkPath;
	private static Text linuxEditCapPath;
	private static Text linuxBitTwistePath;
	private static Text linuxMergeCapPath;
	private static Text linuxCapInfosPath;
	private static Text linuxTcpDumpPath;
	private static Text linuxTsharkPath;
	
	private static Button sourceIpTopTalkersButton;
	private static Button targetIpTopTalkersButton;
	
	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		
		try {
			SampleUI window = new SampleUI();
			window.open();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Open the window.
	 */
	public void open() {
		Display display = Display.getDefault();
		createContents();
		shell.open();
		shell.layout();
		
		initLogger();
		logger.info("hello from the UI!");
		
		// setup the projector engine
        projector = new AttackProjector();
        
        if (SystemUtils.IS_OS_WINDOWS) {
        	projector.setEditcapPath(winEditCapPath.getText());
            projector.setBittwistePath(winBitTwistePath.getText());
            projector.setMergecapPath(winMergeCapPath.getText());
            projector.setCapinfosPath(winCapInfosPath.getText());
            projector.setWindumpPath(winWinDumpPath.getText());
            projector.setTsharkPath(winTsharkPath.getText());
        } else {
        	projector.setEditcapPath(linuxEditCapPath.getText());
        	projector.setBittwistePath(linuxBitTwistePath.getText());
        	projector.setMergecapPath(linuxMergeCapPath.getText());
        	projector.setCapinfosPath(linuxCapInfosPath.getText());
        	projector.setTcpdumpPath(linuxTcpDumpPath.getText());
        	projector.setTsharkPath(linuxTsharkPath.getText());
        }
		
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
		
		projector.cleanUp();
        projector = null;
	}
	
	/**
	 * Create contents of the window.
	 */
	protected void createContents() {
		shell = new Shell();
		shell.setSize(831, 581);
		shell.setText("ORCA PCAP Combination Tool");
		shell.setLayout(new GridLayout(1, false));
		
		Menu menu = new Menu(shell, SWT.BAR);
		shell.setMenuBar(menu);
		
		MenuItem mntmNewSubmenu = new MenuItem(menu, SWT.CASCADE);
		mntmNewSubmenu.setText("&File");
		
		Menu menu_1 = new Menu(mntmNewSubmenu);
		mntmNewSubmenu.setMenu(menu_1);
		
		MenuItem mntmNewItem_2 = new MenuItem(menu_1, SWT.NONE);
		mntmNewItem_2.setText("New Item");
		
		new MenuItem(menu_1, SWT.SEPARATOR);
		
		MenuItem mntmNewItem_3 = new MenuItem(menu_1, SWT.NONE);
		mntmNewItem_3.setText("E&xit");
		
		CTabFolder tabFolder_1 = new CTabFolder(shell, SWT.FLAT);
		tabFolder_1.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 1, 1));
		tabFolder_1.setSelectionBackground(Display.getCurrent().getSystemColor(SWT.COLOR_TITLE_INACTIVE_BACKGROUND_GRADIENT));
		
		CTabItem tbtmMain = new CTabItem(tabFolder_1, SWT.NONE);
		tbtmMain.setText("Main");
		
		Composite composite = new Composite(tabFolder_1, SWT.NONE);
		tbtmMain.setControl(composite);
		composite.setLayout(new GridLayout(3, false));
		
		Label lblSelectSourceFile = new Label(composite, SWT.NONE);
		lblSelectSourceFile.setText("Select Source File:");
		
		sourceFilePath = new Text(composite, SWT.BORDER);
		sourceFilePath.addModifyListener(new ModifyListener() {
			public void modifyText(ModifyEvent arg0) {
				String testValue = sourceFilePath.getText();
				
				if (!testValue.isEmpty()) {
					File testFile = new File(testValue);
					
					if ((testFile.exists() && (!testFile.isDirectory()))) {
						sourceIpTopTalkersButton.setEnabled(true);
					} else {
						sourceIpTopTalkersButton.setEnabled(false);
					}
					
				} else {
					sourceIpTopTalkersButton.setEnabled(false);
				}
			}
		});
		sourceFilePath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button sourceFileBrowseButton = new Button(composite, SWT.NONE);
		sourceFileBrowseButton.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 1, 1));
		sourceFileBrowseButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent arg0) {

				FileDialog dialog = new FileDialog(shell, SWT.OK | SWT.CANCEL);
				dialog.setText("Select Source File");
				dialog.setFilterExtensions(new String[] {"*.pcap", "*.*"});
				dialog.setFilterNames(new String[] {"PCAP Files (*.pcap)", "All Files (*.*)"});
				dialog.setFilterPath(System.getProperty("user.home"));

				String path = dialog.open();
				
				if (path != null) {
					sourceFilePath.setText(path);
				}
				//////////////
				//Check that it is a valid data directory?
				//////////////
			}
		});
		sourceFileBrowseButton.setText("Browse...");
		
		Label lblSelectTargetFile = new Label(composite, SWT.NONE);
		lblSelectTargetFile.setText("Select Target File:");
		
		targetFilePath = new Text(composite, SWT.BORDER);
		targetFilePath.addModifyListener(new ModifyListener() {
			public void modifyText(ModifyEvent arg0) {
				String testValue = targetFilePath.getText();
				
				if (!testValue.isEmpty()) {
					File testFile = new File(testValue);
					
					if ((testFile.exists() && (!testFile.isDirectory()))) {
						targetIpTopTalkersButton.setEnabled(true);
					} else {
						targetIpTopTalkersButton.setEnabled(false);
					}
					
				} else {
					targetIpTopTalkersButton.setEnabled(false);
				}
			}
		});
		targetFilePath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button targetFileBrowseButton = new Button(composite, SWT.NONE);
		targetFileBrowseButton.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 1, 1));
		targetFileBrowseButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent arg0) {
				FileDialog dialog = new FileDialog(shell, SWT.OK | SWT.CANCEL);
				dialog.setText("Select Target File");
				dialog.setFilterExtensions(new String[] {"*.pcap", "*.*"});
				dialog.setFilterNames(new String[] {"PCAP Files (*.pcap)", "All Files (*.*)"});
				dialog.setFilterPath(System.getProperty("user.home"));

				String path = dialog.open();
				
				if (path != null) {
					targetFilePath.setText(path);
				}
				
			}
		});
		targetFileBrowseButton.setText("Browse...");
		
		Label lblSelectOutputDirectory = new Label(composite, SWT.NONE);
		lblSelectOutputDirectory.setText("Select Output Directory:");
		
		outputFilePath = new Text(composite, SWT.BORDER);
		outputFilePath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button outputFileBrowseButton = new Button(composite, SWT.NONE);
		outputFileBrowseButton.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 1, 1));
		outputFileBrowseButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent arg0) {
				FileDialog dialog = new FileDialog(shell, SWT.OK | SWT.CANCEL);
				dialog.setText("Select Output File");
				dialog.setFilterExtensions(new String[] {"*.pcap", "*.*"});
				dialog.setFilterNames(new String[] {"PCAP Files (*.pcap)", "All Files (*.*)"});
				dialog.setFilterPath(System.getProperty("user.home"));

				String path = dialog.open();
				
				if (path != null) {
					outputFilePath.setText(path);
				}				
			}
		});
		outputFileBrowseButton.setText("Browse...");
		
		Label lblSourceVictimIp = new Label(composite, SWT.NONE);
		lblSourceVictimIp.setText("Source Victim IP:");
		
		sourceVictimIp = new Text(composite, SWT.BORDER);
		sourceVictimIp.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		sourceIpTopTalkersButton = new Button(composite, SWT.NONE);
		sourceIpTopTalkersButton.setEnabled(false);
		sourceIpTopTalkersButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent arg0) {
				// ok... here's where we start to do something.
				List<IpCountData> topTalkers = projector.getFileTopTalkers(sourceFilePath.getText(), 10);
				
	            logger.info("Top Talkers for source file: ");
	            for (IpCountData entry : topTalkers) {
	            	logger.info(entry.toString());
	            }				
			}
		});
		sourceIpTopTalkersButton.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 1, 1));
		sourceIpTopTalkersButton.setText("Top Talkers");
		
		Label lblTargetVictimIp = new Label(composite, SWT.NONE);
		lblTargetVictimIp.setText("Target Victim IP:");
		
		targetVictimIp = new Text(composite, SWT.BORDER);
		targetVictimIp.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		targetIpTopTalkersButton = new Button(composite, SWT.NONE);
		targetIpTopTalkersButton.setEnabled(false);
		targetIpTopTalkersButton.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent arg0) {
				List<IpCountData> topTalkers = projector.getFileTopTalkers(targetFilePath.getText(), 10);
				
	            logger.info("Top Talkers for source file: ");
	            for (IpCountData entry : topTalkers) {
	            	logger.info(entry.toString());
	            }			
            }
		});
		targetIpTopTalkersButton.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 1, 1));
		targetIpTopTalkersButton.setText("Top Talkers");
		new Label(composite, SWT.NONE);
		
		Button validateButton = new Button(composite, SWT.NONE);
		validateButton.setLayoutData(new GridData(SWT.RIGHT, SWT.CENTER, true, false, 1, 1));
		validateButton.setText("Validate");
		
		Button combineButton = new Button(composite, SWT.NONE);
		combineButton.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false, 1, 1));
		combineButton.setText("Combine");
		
		loggingTextBox = new Text(composite, SWT.BORDER | SWT.WRAP | SWT.H_SCROLL | SWT.V_SCROLL | SWT.CANCEL | SWT.MULTI);
		loggingTextBox.setLayoutData(new GridData(SWT.FILL, SWT.FILL, false, true, 3, 1));
		
		CTabItem tbtmSettings_1 = new CTabItem(tabFolder_1, SWT.NONE);
		tbtmSettings_1.setText("Settings");
		
		Composite composite_1 = new Composite(tabFolder_1, SWT.NONE);
		tbtmSettings_1.setControl(composite_1);
		composite_1.setLayout(new GridLayout(3, false));
		
		Label lblWindowsSettings = new Label(composite_1, SWT.NONE);
		lblWindowsSettings.setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
		lblWindowsSettings.setText("Windows Settings");
		new Label(composite_1, SWT.NONE);
		new Label(composite_1, SWT.NONE);
		
		Label lblNewLabel = new Label(composite_1, SWT.NONE);
		lblNewLabel.setText("EditCap Path");
		
		winEditCapPath = new Text(composite_1, SWT.BORDER);
		winEditCapPath.setText("C:\\\\Program Files\\\\Wireshark\\\\editcap.exe");
		winEditCapPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnBrowse = new Button(composite_1, SWT.NONE);
		btnBrowse.setText("Browse...");
		
		Label lblNewLabel_1 = new Label(composite_1, SWT.NONE);
		lblNewLabel_1.setText("BitTwiste Path");
		
		winBitTwistePath = new Text(composite_1, SWT.BORDER);
		winBitTwistePath.setText("C:\\\\Tools\\\\bittwiste.exe");
		winBitTwistePath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton = new Button(composite_1, SWT.NONE);
		btnNewButton.setText("Browse...");
		
		Label lblNewLabel_2 = new Label(composite_1, SWT.NONE);
		lblNewLabel_2.setText("MergeCap Path");
		
		winMergeCapPath = new Text(composite_1, SWT.BORDER);
		winMergeCapPath.setText("C:\\\\Program Files\\\\Wireshark\\\\mergecap.exe");
		winMergeCapPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_1 = new Button(composite_1, SWT.NONE);
		btnNewButton_1.setText("Browse...");
		
		Label lblNewLabel_3 = new Label(composite_1, SWT.NONE);
		lblNewLabel_3.setText("CapInfos Path");
		
		winCapInfosPath = new Text(composite_1, SWT.BORDER);
		winCapInfosPath.setText("C:\\\\Program Files\\\\Wireshark\\\\capinfos.exe");
		winCapInfosPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_2 = new Button(composite_1, SWT.NONE);
		btnNewButton_2.setText("Browse...");
		
		Label lblNewLabel_4 = new Label(composite_1, SWT.NONE);
		lblNewLabel_4.setText("WinDump Path");
		
		winWinDumpPath = new Text(composite_1, SWT.BORDER);
		winWinDumpPath.setText("C:\\\\Tools\\\\WinDump.exe");
		winWinDumpPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_3 = new Button(composite_1, SWT.NONE);
		btnNewButton_3.setText("Browse...");
		
		Label lblNewLabel_5 = new Label(composite_1, SWT.NONE);
		lblNewLabel_5.setText("TShark Path");
		
		winTsharkPath = new Text(composite_1, SWT.BORDER);
		winTsharkPath.setText("C:\\\\Program Files\\\\Wireshark\\\\tshark.exe");
		winTsharkPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_4 = new Button(composite_1, SWT.NONE);
		btnNewButton_4.setText("Browse...");
		new Label(composite_1, SWT.NONE);
		new Label(composite_1, SWT.NONE);
		new Label(composite_1, SWT.NONE);
		
		Label lblNewLabel_6 = new Label(composite_1, SWT.NONE);
		lblNewLabel_6.setFont(SWTResourceManager.getFont("Segoe UI", 10, SWT.BOLD));
		lblNewLabel_6.setText("Linux Settings");
		new Label(composite_1, SWT.NONE);
		new Label(composite_1, SWT.NONE);
		
		Label lblNewLabel_7 = new Label(composite_1, SWT.NONE);
		lblNewLabel_7.setText("EditCap Path");
		
		linuxEditCapPath = new Text(composite_1, SWT.BORDER);
		linuxEditCapPath.setText("/usr/sbin/editcap");
		linuxEditCapPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_5 = new Button(composite_1, SWT.NONE);
		btnNewButton_5.setText("Browse...");
		
		Label lblNewLabel_8 = new Label(composite_1, SWT.NONE);
		lblNewLabel_8.setText("BitTwiste Path");
		
		linuxBitTwistePath = new Text(composite_1, SWT.BORDER);
		linuxBitTwistePath.setText("/usr/bin/bittwiste");
		linuxBitTwistePath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_6 = new Button(composite_1, SWT.NONE);
		btnNewButton_6.setText("Browse...");
		
		Label lblNewLabel_9 = new Label(composite_1, SWT.NONE);
		lblNewLabel_9.setText("MergeCap Path");
		
		linuxMergeCapPath = new Text(composite_1, SWT.BORDER);
		linuxMergeCapPath.setText("/usr/sbin/mergecap");
		linuxMergeCapPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_7 = new Button(composite_1, SWT.NONE);
		btnNewButton_7.setText("Browse...");
		
		Label lblNewLabel_10 = new Label(composite_1, SWT.NONE);
		lblNewLabel_10.setText("CapInfos Path");
		
		linuxCapInfosPath = new Text(composite_1, SWT.BORDER);
		linuxCapInfosPath.setText("/usr/sbin/capinfos");
		linuxCapInfosPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_8 = new Button(composite_1, SWT.NONE);
		btnNewButton_8.setText("Browse...");
		
		Label lblNewLabel_11 = new Label(composite_1, SWT.NONE);
		lblNewLabel_11.setText("TCPDump Path");
		
		linuxTcpDumpPath = new Text(composite_1, SWT.BORDER);
		linuxTcpDumpPath.setText("/usr/sbin/tcpdump");
		linuxTcpDumpPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_9 = new Button(composite_1, SWT.NONE);
		btnNewButton_9.setText("Browse...");
		
		Label lblNewLabel_12 = new Label(composite_1, SWT.NONE);
		lblNewLabel_12.setText("TShark Path");
		
		linuxTsharkPath = new Text(composite_1, SWT.BORDER);
		linuxTsharkPath.setText("/usr/sbin/tshark");
		linuxTsharkPath.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Button btnNewButton_10 = new Button(composite_1, SWT.NONE);
		btnNewButton_10.setText("Browse...");
		new Label(composite_1, SWT.NONE);
		new Label(composite_1, SWT.NONE);
		new Label(composite_1, SWT.NONE);
		new Label(composite_1, SWT.NONE);
		
		Button saveSettingsButton = new Button(composite_1, SWT.NONE);
		saveSettingsButton.setText("Save Settings");
		new Label(composite_1, SWT.NONE);

		
	}

	
	private static void initLogger() {
		String PATTERN = "%d{ISO8601} %-5p  - %-10.26c{1}  - %m%n";

		ConsoleAppender console = new ConsoleAppender();
		console.setLayout(new EnhancedPatternLayout(PATTERN));
		console.setThreshold(Level.INFO);
		console.activateOptions();
		
		Logger.getRootLogger().addAppender(console);
		
		TextBoxAppender textbox = new TextBoxAppender(); 
		textbox.setLayout(new EnhancedPatternLayout(PATTERN));
		textbox.setThreshold(Level.INFO);
		textbox.activateOptions();
		textbox.setTextBox(loggingTextBox);
		
		Logger.getRootLogger().addAppender(textbox);
	}   
}
