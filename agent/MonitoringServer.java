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

                if(running.get()) {
                    byte[] lengthData = receiveExact(inputStream, 4);

                    // 解析数据长度（big-endian）
                    int dataLength = ByteBuffer.wrap(lengthData).getInt();

                    // 接收压缩的JSON数据
                    byte[] compressedData = receiveExact(inputStream, dataLength);

                    // 解压缩数据
                    byte[] jsonData = decompressGzip(compressedData);


                    // 解析并打印JSON数据
                    try {
                        String jsonString = new String(jsonData, "UTF-8");
                        Map<String, Object> data = parseSimpleJson(jsonString);
                        HostInfo hostInfo = createHostInfo(data, clientAddress);

                        printHostInfo(data, clientAddress);
                    } catch (Exception e) {
                        System.err.println("JSON解析错误: " + e.getMessage());
                    }
                }
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

    private HostInfo createHostInfo(Map<String, Object> data, InetSocketAddress clientAddress) {
        HostInfo hostInfo = new HostInfo();

        // 设置基本信息
        hostInfo.setMessageType(getStringValue(data, "messageType"));
        hostInfo.setTimestamp(getStringValue(data, "timestamp"));
        hostInfo.setHostname(getStringValue(data, "hostname"));

        // 处理CPU信息
        HostInfo.CpuInfo cpu = null;
        @SuppressWarnings("unchecked")
        Map<String, Object> cpuData = (Map<String, Object>) data.get("cpu");
        if (cpuData != null) {
            cpu = new HostInfo.CpuInfo();
            cpu.setModel(getStringValue(cpuData, "model"));
            cpu.setPhysicalCores(getIntValue(cpuData, "physicalCores"));
            cpu.setLogicalCores(getIntValue(cpuData, "logicalCores"));
            cpu.setMaxFrequency(getDoubleValue(cpuData, "maxFrequency"));
            cpu.setMinFrequency(getDoubleValue(cpuData, "minFrequency"));
            cpu.setCurrentFrequency(getDoubleValue(cpuData, "currentFrequency"));
        }
        hostInfo.setCpu(cpu);

        // 处理内存信息
        HostInfo.MemoryInfo memory = null;
        @SuppressWarnings("unchecked")
        Map<String, Object> memoryData = (Map<String, Object>) data.get("memory");
        if (memoryData != null) {
            memory = new HostInfo.MemoryInfo();
            memory.setTotalSize(getLongValue(memoryData, "totalSize"));
            memory.setTotalSizeGb(getDoubleValue(memoryData, "totalSizeGb"));
            memory.setFrequency(getStringValue(memoryData, "frequency"));
        }
        hostInfo.setMemory(memory);

        // 处理网络接口信息
        List<HostInfo.NetworkInterface> networkInterfaces = new ArrayList<>();
        @SuppressWarnings("unchecked")
        List<Object> networkInterfacesData = (List<Object>) data.get("networkInterfaces");
        if (networkInterfacesData != null) {
            for (Object networkObj : networkInterfacesData) {
                @SuppressWarnings("unchecked")
                Map<String, Object> networkMap = (Map<String, Object>) networkObj;

                HostInfo.NetworkInterface networkInterface = new HostInfo.NetworkInterface();
                networkInterface.setName(getStringValue(networkMap, "name"));
                networkInterface.setIsUp(getBooleanValue(networkMap, "isUp"));
                networkInterface.setSpeed(getIntValue(networkMap, "speed"));

                // 处理地址信息列表
                List<HostInfo.AddressInfo> addresses = new ArrayList<>();
                @SuppressWarnings("unchecked")
                List<Object> addressesData = (List<Object>) networkMap.get("addresses");
                if (addressesData != null) {
                    for (Object addressObj : addressesData) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> addressMap = (Map<String, Object>) addressObj;

                        HostInfo.AddressInfo addressInfo = new HostInfo.AddressInfo();
                        addressInfo.setFamily(getStringValue(addressMap, "family"));
                        addressInfo.setAddress(getStringValue(addressMap, "address"));
                        addressInfo.setNetmask(getStringValue(addressMap, "netmask"));
                        addressInfo.setBroadcast(getStringValue(addressMap, "broadcast"));

                        addresses.add(addressInfo);
                    }
                }
                networkInterface.setAddresses(addresses);
                networkInterfaces.add(networkInterface);
            }
        }
        hostInfo.setNetworkInterfaces(networkInterfaces);

        // 处理操作系统信息
        HostInfo.OperatingSystem operatingSystem = null;
        @SuppressWarnings("unchecked")
        Map<String, Object> osData = (Map<String, Object>) data.get("operatingSystem");
        if (osData != null) {
            operatingSystem = new HostInfo.OperatingSystem();
            operatingSystem.setSystem(getStringValue(osData, "system"));
            operatingSystem.setRelease(getStringValue(osData, "release"));
            operatingSystem.setVersion(getStringValue(osData, "version"));
            operatingSystem.setMachine(getStringValue(osData, "machine"));
            operatingSystem.setProcessor(getStringValue(osData, "processor"));
            operatingSystem.setPlatform(getStringValue(osData, "platform"));
            operatingSystem.setPythonVersion(getStringValue(osData, "pythonVersion"));
            operatingSystem.setPrettyName(getStringValue(osData, "prettyName"));
        }
        hostInfo.setOperatingSystem(operatingSystem);

        return hostInfo;
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

    private void printHostInfo(Map<String, Object> data, InetSocketAddress clientAddress) {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("客户端: " + clientAddress.getAddress().getHostAddress() +
                ":" + clientAddress.getPort());
        System.out.println("消息类型: " + data.getOrDefault("messageType", "N/A"));
        System.out.println("时间戳: " + data.getOrDefault("timestamp", "N/A"));
        System.out.println("主机名: " + data.getOrDefault("hostname", "N/A"));
        System.out.println("-".repeat(80));

        // CPU信息
        @SuppressWarnings("unchecked")
        Map<String, Object> cpu = (Map<String, Object>) data.get("cpu");
        if (cpu != null) {
            System.out.println("CPU信息:");
            System.out.println("  型号: " + getStringValue(cpu, "model"));
            System.out.println("  物理核心数: " + getIntValue(cpu, "physicalCores"));
            System.out.println("  逻辑核心数: " + getIntValue(cpu, "logicalCores"));
            System.out.printf("  最大频率: %.2f GHz\n", getDoubleValue(cpu, "maxFrequency"));
            System.out.printf("  最小频率: %.2f GHz\n", getDoubleValue(cpu, "minFrequency"));
            System.out.printf("  当前频率: %.2f GHz\n", getDoubleValue(cpu, "currentFrequency"));
        }

        // 内存信息
        @SuppressWarnings("unchecked")
        Map<String, Object> memory = (Map<String, Object>) data.get("memory");
        if (memory != null) {
            System.out.println("内存信息:");
            System.out.println("  总大小: " + formatBytes(getLongValue(memory, "totalSize")));
            System.out.printf("  总大小: %.2f GB\n", getDoubleValue(memory, "totalSizeGb"));
            System.out.println("  频率: " + getStringValue(memory, "frequency"));
        }

        // 网络接口信息
        @SuppressWarnings("unchecked")
        List<Object> networkInterfaces = (List<Object>) data.get("networkInterfaces");
        if (networkInterfaces != null && !networkInterfaces.isEmpty()) {
            System.out.println("网络接口信息:");
            for (Object networkObj : networkInterfaces) {
                @SuppressWarnings("unchecked")
                Map<String, Object> networkInterface = (Map<String, Object>) networkObj;

                System.out.println("  接口名称: " + getStringValue(networkInterface, "name"));
                System.out.println("  状态: " + (getBooleanValue(networkInterface, "isUp") ? "启用" : "禁用"));
                int speed = getIntValue(networkInterface, "speed");
                if (speed > 0) {
                    System.out.println("  速度: " + speed + " Mbps");
                } else {
                    System.out.println("  速度: N/A");
                }

                // 地址信息
                @SuppressWarnings("unchecked")
                List<Object> addresses = (List<Object>) networkInterface.get("addresses");
                if (addresses != null && !addresses.isEmpty()) {
                    System.out.println("  地址信息:");
                    for (Object addressObj : addresses) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> address = (Map<String, Object>) addressObj;

                        System.out.println("    协议族: " + getStringValue(address, "family"));
                        System.out.println("    IP地址: " + getStringValue(address, "address"));
                        System.out.println("    子网掩码: " + getStringValue(address, "netmask"));
                        String broadcast = getStringValue(address, "broadcast");
                        if (broadcast != null && !broadcast.isEmpty()) {
                            System.out.println("    广播地址: " + broadcast);
                        }
                        System.out.println("    " + "-".repeat(40));
                    }
                }
                System.out.println("  " + "-".repeat(50));
            }
        }

        // 操作系统信息
        @SuppressWarnings("unchecked")
        Map<String, Object> operatingSystem = (Map<String, Object>) data.get("operatingSystem");
        if (operatingSystem != null) {
            System.out.println("操作系统信息:");
            System.out.println("  系统类型: " + getStringValue(operatingSystem, "system"));
            System.out.println("  发行版本: " + getStringValue(operatingSystem, "release"));
            System.out.println("  版本信息: " + getStringValue(operatingSystem, "version"));
            System.out.println("  架构: " + getStringValue(operatingSystem, "machine"));
            System.out.println("  处理器: " + getStringValue(operatingSystem, "processor"));
            System.out.println("  平台: " + getStringValue(operatingSystem, "platform"));
            System.out.println("  Python版本: " + getStringValue(operatingSystem, "pythonVersion"));
            System.out.println("  系统描述: " + getStringValue(operatingSystem, "prettyName"));
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

    private long getLongValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            System.out.println("警告: 键 '" + key + "' 不存在或为null");
            return 0L;
        }

        if (value instanceof Number) {
            return ((Number) value).longValue();
        }

        // 尝试解析字符串
        if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                System.out.println("警告: 无法解析字符串为长整型: " + value);
                return 0L;
            }
        }

        System.out.println("警告: 键 '" + key + "' 的值类型不是Number或String: " + value.getClass().getName());
        return 0L;
    }

    private double getDoubleValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            System.out.println("警告: 键 '" + key + "' 不存在或为null");
            return 0.0;
        }

        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }

        if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException e) {
                System.out.println("警告: 无法解析字符串为双精度浮点型: " + value);
                return 0.0;
            }
        }

        System.out.println("警告: 键 '" + key + "' 的值类型不是Number或String: " + value.getClass().getName());
        return 0.0;
    }



    // 辅助方法用于安全地从Map中获取整型
    private int getIntValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return 0;
    }

    private boolean getBooleanValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }
        if (value instanceof Number) {
            return ((Number) value).intValue() != 0;
        }
        return false;
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
