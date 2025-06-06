import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.zip.GZIPInputStream;

public class MonitoringServer {
    private int port;
    private ServerSocket serverSocket;
    private AtomicBoolean running;
    private ExecutorService executorService;
    private List<SystemInfo> systemInfoList;

    public MonitoringServer(int port) {
        this.port = port;
        this.running = new AtomicBoolean(false);
        this.executorService = Executors.newCachedThreadPool();
        this.systemInfoList = new ArrayList<>();

    }

    public MonitoringServer() {
        this(40000);
    }

    public List<SystemInfo> getSystemInfoList() {
        return new ArrayList<>(systemInfoList);
    }

    public void clearSystemInfoList() {
        synchronized (systemInfoList) {
            systemInfoList.clear();
        }
    }

    public void startServer() {
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(port));
            running.set(true);

            System.out.println("服务器已启动，监听端口 " + port);
            System.out.println("等待客户端连接...");

            while (running.get()) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    InetSocketAddress clientAddress = (InetSocketAddress) clientSocket.getRemoteSocketAddress();
                    System.out.println("客户端 " + clientAddress.getAddress().getHostAddress() +
                            ":" + clientAddress.getPort() + " 已连接");

                    // 为每个客户端创建一个线程
                    executorService.submit(new ClientHandler(clientSocket, clientAddress));

                } catch (IOException e) {
                    if (running.get()) {
                        System.err.println("接受连接时出错: " + e.getMessage());
                    }
                    break;
                }
            }
        } catch (Exception e) {
            System.err.println("启动服务器时出错: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    private class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private final InetSocketAddress clientAddress;

        public ClientHandler(Socket clientSocket, InetSocketAddress clientAddress) {
            this.clientSocket = clientSocket;
            this.clientAddress = clientAddress;
        }

        @Override
        public void run() {
            try (DataInputStream inputStream = new DataInputStream(clientSocket.getInputStream())) {
                while (running.get()) {
                    // 接收数据长度（4字节）
                    byte[] lengthData = receiveExact(inputStream, 4);
                    if (lengthData == null) {
                        break;
                    }

                    // 解析数据长度（big-endian）
                    int dataLength = ByteBuffer.wrap(lengthData).getInt();

                    // 接收压缩的JSON数据
                    byte[] compressedData = receiveExact(inputStream, dataLength);
                    if (compressedData == null) {
                        break;
                    }

                    // 解压缩数据
                    byte[] jsonData = decompressGzip(compressedData);
                    if (jsonData == null) {
                        System.err.println("Gzip解压失败");
                        continue;
                    }

                    // 解析并打印JSON数据
                    try {
                        String jsonString = new String(jsonData, "UTF-8");
                        Map<String, Object> data = parseSimpleJson(jsonString);
                        SystemInfo systemInfo = createSystemInfo(data, clientAddress);

                        synchronized (systemInfoList) {
                            systemInfoList.add(systemInfo);
                        }

                        printSystemInfo(data, clientAddress);
                    } catch (Exception e) {
                        System.err.println("JSON解析错误: " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                System.err.println("处理客户端 " + clientAddress.getAddress().getHostAddress() +
                        ":" + clientAddress.getPort() + " 时出错: " + e.getMessage());
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    // 忽略关闭异常
                }
                System.out.println("客户端 " + clientAddress.getAddress().getHostAddress() +
                        ":" + clientAddress.getPort() + " 已断开连接");
            }
        }

        private byte[] receiveExact(DataInputStream inputStream, int length) {
            byte[] data = new byte[length];
            int totalReceived = 0;

            while (totalReceived < length) {
                try {
                    int received = inputStream.read(data, totalReceived, length - totalReceived);
                    if (received == -1) {
                        return null;
                    }
                    totalReceived += received;
                } catch (IOException e) {
                    return null;
                }
            }
            return data;
        }

        // 新增：Gzip解压方法
        private byte[] decompressGzip(byte[] compressedData) {
            try (ByteArrayInputStream bis = new ByteArrayInputStream(compressedData);
                 GZIPInputStream gzipStream = new GZIPInputStream(bis);
                 ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = gzipStream.read(buffer)) != -1) {
                    bos.write(buffer, 0, bytesRead);
                }

                return bos.toByteArray();

            } catch (IOException e) {
                System.err.println("Gzip解压错误: " + e.getMessage());
                return null;
            }
        }
    }

    // 新增：创建SystemInfo对象的方法
    private SystemInfo createSystemInfo(Map<String, Object> data, InetSocketAddress clientAddress) {
        String address = clientAddress.getAddress().getHostAddress() + ":" + clientAddress.getPort();
        String timestamp = getStringValue(data, "timestamp");
        double cpuPercent = getDoubleValue(data, "cpu_percent");

        // 处理内存信息
        SystemInfo.MemoryInfo memory = null;
        @SuppressWarnings("unchecked")
        Map<String, Object> memoryData = (Map<String, Object>) data.get("memory");
        if (memoryData != null) {
            memory = new SystemInfo.MemoryInfo(
                    getLongValue(memoryData, "total"),
                    getLongValue(memoryData, "available"),
                    getLongValue(memoryData, "used"),
                    getDoubleValue(memoryData, "percent")
            );
        }

        // 处理磁盘信息
        SystemInfo.DiskInfo disk = null;
        @SuppressWarnings("unchecked")
        Map<String, Object> diskData = (Map<String, Object>) data.get("disk");
        if (diskData != null) {
            disk = new SystemInfo.DiskInfo(
                    getLongValue(diskData, "total"),
                    getLongValue(diskData, "free"),
                    getLongValue(diskData, "used"),
                    getDoubleValue(diskData, "percent")
            );
        }

        // 处理网络信息
        SystemInfo.NetworkInfo network = null;
        @SuppressWarnings("unchecked")
        Map<String, Object> networkData = (Map<String, Object>) data.get("network");
        if (networkData != null) {
            network = new SystemInfo.NetworkInfo(
                    getLongValue(networkData, "bytes_sent"),
                    getLongValue(networkData, "bytes_recv")
            );
        }

        // 处理进程信息
        int processCount = getIntValue(data, "process_count");
        List<SystemInfo.ProcessInfo> processes = new ArrayList<>();
        @SuppressWarnings("unchecked")
        List<Object> processesData = (List<Object>) data.get("processes");
        if (processesData != null) {
            for (Object procObj : processesData) {
                @SuppressWarnings("unchecked")
                Map<String, Object> proc = (Map<String, Object>) procObj;
                SystemInfo.ProcessInfo processInfo = new SystemInfo.ProcessInfo(
                        getIntValue(proc, "pid"),
                        getIntValue(proc, "ppid"),
                        getStringValue(proc, "name"),
                        getStringValue(proc, "status"),
                        getDoubleValue(proc, "cpu_percent"),
                        getDoubleValue(proc, "memory_percent"),
                        getIntValue(proc, "num_threads"),
                        getIntValue(proc, "num_fds"),
                        getIntValue(proc, "session_id")
                );
                processes.add(processInfo);
            }
        }

        return new SystemInfo(address, timestamp, cpuPercent, memory, disk, network, processCount, processes);
    }

    // 简单的JSON解析方法（用于避免外部依赖）
    private Map<String, Object> parseSimpleJson(String jsonString) {
        Map<String, Object> result = new HashMap<>();

        // 移除外层大括号
        jsonString = jsonString.trim();
        if (jsonString.startsWith("{") && jsonString.endsWith("}")) {
            jsonString = jsonString.substring(1, jsonString.length() - 1);
        }

        // 解析键值对
        String[] pairs = splitJsonPairs(jsonString);

        for (String pair : pairs) {
            int colonIndex = pair.indexOf(':');
            if (colonIndex > 0) {
                String key = pair.substring(0, colonIndex).trim();
                String value = pair.substring(colonIndex + 1).trim();

                // 移除键的引号
                if (key.startsWith("\"") && key.endsWith("\"")) {
                    key = key.substring(1, key.length() - 1);
                }

                // 解析值
                Object parsedValue = parseJsonValue(value);
                result.put(key, parsedValue);
            }
        }

        return result;
    }

    private String[] splitJsonPairs(String jsonContent) {
        List<String> pairs = new ArrayList<>();
        int braceLevel = 0;
        int bracketLevel = 0;
        boolean inString = false;
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < jsonContent.length(); i++) {
            char c = jsonContent.charAt(i);

            if (c == '"' && (i == 0 || jsonContent.charAt(i - 1) != '\\')) {
                inString = !inString;
            }

            if (!inString) {
                if (c == '{') braceLevel++;
                else if (c == '}') braceLevel--;
                else if (c == '[') bracketLevel++;
                else if (c == ']') bracketLevel--;
                else if (c == ',' && braceLevel == 0 && bracketLevel == 0) {
                    pairs.add(current.toString().trim());
                    current = new StringBuilder();
                    continue;
                }
            }

            current.append(c);
        }

        if (current.length() > 0) {
            pairs.add(current.toString().trim());
        }

        return pairs.toArray(new String[0]);
    }

    //解析json报文
    private Object parseJsonValue(String value) {
        value = value.trim();

        // null
        if ("null".equals(value)) {
            return null;
        }

        // boolean
        if ("true".equals(value)) {
            return true;
        }
        if ("false".equals(value)) {
            return false;
        }

        // string
        if (value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }

        // array
        if (value.startsWith("[") && value.endsWith("]")) {
            List<Object> list = new ArrayList<>();
            String arrayContent = value.substring(1, value.length() - 1).trim();
            if (!arrayContent.isEmpty()) {
                String[] elements = splitJsonPairs(arrayContent);
                for (String element : elements) {
                    list.add(parseJsonValue(element));
                }
            }
            return list;
        }

        // object
        if (value.startsWith("{") && value.endsWith("}")) {
            return parseSimpleJson(value);
        }

        // number
        try {
            if (value.contains(".")) {
                return Double.parseDouble(value);
            } else {
                long longValue = Long.parseLong(value);
                if (longValue >= Integer.MIN_VALUE && longValue <= Integer.MAX_VALUE) {
                    return (int) longValue;
                }
                return longValue;
            }
        } catch (NumberFormatException e) {
            // 如果不是数字，返回字符串
            return value;
        }
    }

    private void printSystemInfo(Map<String, Object> data, InetSocketAddress clientAddress) {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("客户端: " + clientAddress.getAddress().getHostAddress() +
                ":" + clientAddress.getPort());
        System.out.println("时间戳: " + data.getOrDefault("timestamp", "N/A"));
        System.out.println("-".repeat(80));

        // CPU信息
        double cpuPercent = getDoubleValue(data, "cpu_percent");
        System.out.printf("CPU利用率: %.2f%%\n", cpuPercent);

        // 内存信息
        @SuppressWarnings("unchecked")
        Map<String, Object> memory = (Map<String, Object>) data.get("memory");
        if (memory != null) {
            System.out.println("内存信息:");
            System.out.println("  总大小: " + formatBytes(getLongValue(memory, "total")));
            System.out.println("  可用大小: " + formatBytes(getLongValue(memory, "available")));
            System.out.println("  已占用大小: " + formatBytes(getLongValue(memory, "used")));
            System.out.printf("  占用率: %.2f%%\n", getDoubleValue(memory, "percent"));
        }

        // 磁盘信息
        @SuppressWarnings("unchecked")
        Map<String, Object> disk = (Map<String, Object>) data.get("disk");
        if (disk != null) {
            System.out.println("磁盘信息:");
            System.out.println("  总大小: " + formatBytes(getLongValue(disk, "total")));
            System.out.println("  可用大小: " + formatBytes(getLongValue(disk, "free")));
            System.out.println("  已占用大小: " + formatBytes(getLongValue(disk, "used")));
            System.out.printf("  占用率: %.2f%%\n", getDoubleValue(disk, "percent"));
        }

        // 网卡信息
        @SuppressWarnings("unchecked")
        Map<String, Object> network = (Map<String, Object>) data.get("network");
        if (network != null) {
            System.out.println("网卡信息:");
            System.out.println("  发送字节数: " + formatBytes(getLongValue(network, "bytes_sent")));
            System.out.println("  接收字节数: " + formatBytes(getLongValue(network, "bytes_recv")));
        }

        // 进程信息
        int processCount = getIntValue(data, "process_count");
        @SuppressWarnings("unchecked")
        List<Object> processes = (List<Object>) data.get("processes");
        System.out.println("进程数: " + processCount);

        if (processes != null && !processes.isEmpty()) {
            System.out.println("进程信息 (前10个进程):");
            System.out.printf("%-8s %-8s %-20s %-12s %-8s %-8s %-8s %-8s %-8s\n",
                    "PID", "父PID", "进程名", "状态", "CPU%", "内存%", "线程数", "文件数", "会话号");
            System.out.println("-".repeat(80));

            int limit = Math.min(processes.size(), 10);
            for (int i = 0; i < limit; i++) {
                @SuppressWarnings("unchecked")
                Map<String, Object> proc = (Map<String, Object>) processes.get(i);
                String name = getStringValue(proc, "name");
                if (name.length() > 19) {
                    name = name.substring(0, 19);
                }

                System.out.printf("%-8d %-8d %-20s %-12s %-8.2f %-8.2f %-8d %-8d %-8d\n",
                        getIntValue(proc, "pid"),
                        getIntValue(proc, "ppid"),
                        name,
                        getStringValue(proc, "status"),
                        getDoubleValue(proc, "cpu_percent"),
                        getDoubleValue(proc, "memory_percent"),
                        getIntValue(proc, "num_threads"),
                        getIntValue(proc, "num_fds"),
                        getIntValue(proc, "session_id"));
            }
        }

        System.out.println("=".repeat(80));
    }

    //辅助方法用于单位格式化
    private String formatBytes(long bytesValue) {
        if (bytesValue == 0) {
            return "0 B";
        }

        String[] units = {"B", "KB", "MB", "GB", "TB"};
        double size = bytesValue;
        int unitIndex = 0;

        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }

        return String.format("%.2f %s", size, units[unitIndex]);
    }

    // 辅助方法用于安全地从Map中获取浮点数
    private double getDoubleValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        return 0.0;
    }

    // 辅助方法用于安全地从Map中获取长整型
    private long getLongValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        return 0L;
    }

    // 辅助方法用于安全地从Map中获取整型
    private int getIntValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return 0;
    }

    // 辅助方法用于安全地从Map中获取字符串
    private String getStringValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value != null ? value.toString() : "N/A";
    }

    public void stopServer() {
        running.set(false);
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                // 忽略关闭异常
            }
        }
        executorService.shutdown();
    }

    private void cleanup() {
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                // 忽略关闭异常
            }
        }
        executorService.shutdown();
        System.out.println("服务器已停止");
    }

    public static void main(String[] args) {
        System.out.println("=== 系统监控服务器 ===");

        MonitoringServer server = new MonitoringServer(40000);

        // 添加关闭钩子来优雅地停止服务器
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n正在停止服务器...");
            server.stopServer();
            System.out.println("程序已退出");
        }));

        try {
            server.startServer();
        } catch (Exception e) {
            System.err.println("服务器运行时出错: " + e.getMessage());
        }
    }
}