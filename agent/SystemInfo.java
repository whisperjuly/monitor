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

// 新增：系统信息存储类
class SystemInfo {
    private String clientAddress;
    private String timestamp;
    private double cpuPercent;
    private MemoryInfo memory;
    private DiskInfo disk;
    private NetworkInfo network;
    private int processCount;
    private List<ProcessInfo> processes;

    // 内存信息子类
    public static class MemoryInfo {
        private long total;
        private long available;
        private long used;
        private double percent;

        public MemoryInfo(long total, long available, long used, double percent) {
            this.total = total;
            this.available = available;
            this.used = used;
            this.percent = percent;
        }

        // Getters
        public long getTotal() { return total; }
        public long getAvailable() { return available; }
        public long getUsed() { return used; }
        public double getPercent() { return percent; }
    }

    // 磁盘信息子类
    public static class DiskInfo {
        private long total;
        private long free;
        private long used;
        private double percent;

        public DiskInfo(long total, long free, long used, double percent) {
            this.total = total;
            this.free = free;
            this.used = used;
            this.percent = percent;
        }

        // Getters
        public long getTotal() { return total; }
        public long getFree() { return free; }
        public long getUsed() { return used; }
        public double getPercent() { return percent; }
    }

    // 网络信息子类
    public static class NetworkInfo {
        private long bytesSent;
        private long bytesRecv;

        public NetworkInfo(long bytesSent, long bytesRecv) {
            this.bytesSent = bytesSent;
            this.bytesRecv = bytesRecv;
        }

        // Getters
        public long getBytesSent() { return bytesSent; }
        public long getBytesRecv() { return bytesRecv; }
    }

    // 进程信息子类
    public static class ProcessInfo {
        private int pid;
        private int ppid;
        private String name;
        private String status;
        private double cpuPercent;
        private double memoryPercent;
        private int numThreads;
        private int numFds;
        private int sessionId;

        public ProcessInfo(int pid, int ppid, String name, String status,
                           double cpuPercent, double memoryPercent,
                           int numThreads, int numFds, int sessionId) {
            this.pid = pid;
            this.ppid = ppid;
            this.name = name;
            this.status = status;
            this.cpuPercent = cpuPercent;
            this.memoryPercent = memoryPercent;
            this.numThreads = numThreads;
            this.numFds = numFds;
            this.sessionId = sessionId;
        }

        // Getters
        public int getPid() { return pid; }
        public int getPpid() { return ppid; }
        public String getName() { return name; }
        public String getStatus() { return status; }
        public double getCpuPercent() { return cpuPercent; }
        public double getMemoryPercent() { return memoryPercent; }
        public int getNumThreads() { return numThreads; }
        public int getNumFds() { return numFds; }
        public int getSessionId() { return sessionId; }
    }

    // 构造函数
    public SystemInfo(String clientAddress, String timestamp, double cpuPercent,
                      MemoryInfo memory, DiskInfo disk, NetworkInfo network,
                      int processCount, List<ProcessInfo> processes) {
        this.clientAddress = clientAddress;
        this.timestamp = timestamp;
        this.cpuPercent = cpuPercent;
        this.memory = memory;
        this.disk = disk;
        this.network = network;
        this.processCount = processCount;
        this.processes = processes;
    }

    // Getters
    public String getClientAddress() { return clientAddress; }
    public String getTimestamp() { return timestamp; }
    public double getCpuPercent() { return cpuPercent; }
    public MemoryInfo getMemory() { return memory; }
    public DiskInfo getDisk() { return disk; }
    public NetworkInfo getNetwork() { return network; }
    public int getProcessCount() { return processCount; }
    public List<ProcessInfo> getProcesses() { return processes; }

    // 工具方法：格式化字节数
    public static String formatBytes(long bytesValue) {
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

    // 打印方法（可选，用于调试）
    public void printInfo() {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("客户端: " + clientAddress);
        System.out.println("时间戳: " + timestamp);
        System.out.println("-".repeat(80));

        System.out.printf("CPU利用率: %.2f%%\n", cpuPercent);

        if (memory != null) {
            System.out.println("内存信息:");
            System.out.println("  总大小: " + formatBytes(memory.getTotal()));
            System.out.println("  可用大小: " + formatBytes(memory.getAvailable()));
            System.out.println("  已占用大小: " + formatBytes(memory.getUsed()));
            System.out.printf("  占用率: %.2f%%\n", memory.getPercent());
        }

        if (disk != null) {
            System.out.println("磁盘信息:");
            System.out.println("  总大小: " + formatBytes(disk.getTotal()));
            System.out.println("  可用大小: " + formatBytes(disk.getFree()));
            System.out.println("  已占用大小: " + formatBytes(disk.getUsed()));
            System.out.printf("  占用率: %.2f%%\n", disk.getPercent());
        }

        if (network != null) {
            System.out.println("网卡信息:");
            System.out.println("  发送字节数: " + formatBytes(network.getBytesSent()));
            System.out.println("  接收字节数: " + formatBytes(network.getBytesRecv()));
        }

        System.out.println("进程数: " + processCount);

        if (processes != null && !processes.isEmpty()) {
            System.out.println("进程信息 (前10个进程):");
            System.out.printf("%-8s %-8s %-20s %-12s %-8s %-8s %-8s %-8s %-8s\n",
                    "PID", "父PID", "进程名", "状态", "CPU%", "内存%", "线程数", "文件数", "会话号");
            System.out.println("-".repeat(80));

            int limit = Math.min(processes.size(), 10);
            for (int i = 0; i < limit; i++) {
                ProcessInfo proc = processes.get(i);
                String name = proc.getName();
                if (name.length() > 19) {
                    name = name.substring(0, 19);
                }

                System.out.printf("%-8d %-8d %-20s %-12s %-8.2f %-8.2f %-8d %-8d %-8d\n",
                        proc.getPid(), proc.getPpid(), name, proc.getStatus(),
                        proc.getCpuPercent(), proc.getMemoryPercent(),
                        proc.getNumThreads(), proc.getNumFds(), proc.getSessionId());
            }
        }

        System.out.println("=".repeat(80));
    }
}
