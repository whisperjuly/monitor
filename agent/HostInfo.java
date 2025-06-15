import java.util.List;

/**
 * 主机信息类
 * 存储客户端的硬件和系统信息
 */
public class HostInfo {
    private String messageType;

    private String timestamp;

    private String hostname;

    private CpuInfo cpu;

    private MemoryInfo memory;

    private List<NetworkInterface> networkInterfaces;

    private OperatingSystem operatingSystem;

    // 构造方法
    public HostInfo() {}

    // Getter和Setter方法
    public String getMessageType() { return messageType; }
    public void setMessageType(String messageType) { this.messageType = messageType; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }

    public CpuInfo getCpu() { return cpu; }
    public void setCpu(CpuInfo cpu) { this.cpu = cpu; }

    public MemoryInfo getMemory() { return memory; }
    public void setMemory(MemoryInfo memory) { this.memory = memory; }

    public List<NetworkInterface> getNetworkInterfaces() { return networkInterfaces; }
    public void setNetworkInterfaces(List<NetworkInterface> networkInterfaces) {
        this.networkInterfaces = networkInterfaces;
    }

    public OperatingSystem getOperatingSystem() { return operatingSystem; }
    public void setOperatingSystem(OperatingSystem operatingSystem) {
        this.operatingSystem = operatingSystem;
    }

    @Override
    public String toString() {
        return "HostInfo{" +
                "hostname='" + hostname + '\'' +
                ", cpu=" + cpu +
                ", memory=" + memory +
                ", operatingSystem=" + operatingSystem +
                '}';
    }

    // CPU信息内部类
    public static class CpuInfo {
        private String model;

        private Integer physicalCores;

        private Integer logicalCores;

        private Double maxFrequency;

        private Double minFrequency;

        private Double currentFrequency;

        public CpuInfo() {}

        // Getter和Setter方法
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }

        public Integer getPhysicalCores() { return physicalCores; }
        public void setPhysicalCores(Integer physicalCores) { this.physicalCores = physicalCores; }

        public Integer getLogicalCores() { return logicalCores; }
        public void setLogicalCores(Integer logicalCores) { this.logicalCores = logicalCores; }

        public Double getMaxFrequency() { return maxFrequency; }
        public void setMaxFrequency(Double maxFrequency) { this.maxFrequency = maxFrequency; }

        public Double getMinFrequency() { return minFrequency; }
        public void setMinFrequency(Double minFrequency) { this.minFrequency = minFrequency; }

        public Double getCurrentFrequency() { return currentFrequency; }
        public void setCurrentFrequency(Double currentFrequency) { this.currentFrequency = currentFrequency; }

        @Override
        public String toString() {
            return "CpuInfo{" +
                    "model='" + model + '\'' +
                    ", physicalCores=" + physicalCores +
                    ", logicalCores=" + logicalCores +
                    ", maxFrequency=" + maxFrequency +
                    '}';
        }
    }

    // 内存信息内部类
    public static class MemoryInfo {
        private Long totalSize;

        private Double totalSizeGb;

        private String frequency;

        public MemoryInfo() {}

        // Getter和Setter方法
        public Long getTotalSize() { return totalSize; }
        public void setTotalSize(Long totalSize) { this.totalSize = totalSize; }

        public Double getTotalSizeGb() { return totalSizeGb; }
        public void setTotalSizeGb(Double totalSizeGb) { this.totalSizeGb = totalSizeGb; }

        public String getFrequency() { return frequency; }
        public void setFrequency(String frequency) { this.frequency = frequency; }

        @Override
        public String toString() {
            return "MemoryInfo{" +
                    "totalSizeGb=" + totalSizeGb +
                    ", frequency='" + frequency + '\'' +
                    '}';
        }
    }

    // 网络接口内部类
    public static class NetworkInterface {
        private String name;

        private List<AddressInfo> addresses;

        private Boolean isUp;

        private Integer speed;

        public NetworkInterface() {}

        // Getter和Setter方法
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public List<AddressInfo> getAddresses() { return addresses; }
        public void setAddresses(List<AddressInfo> addresses) { this.addresses = addresses; }

        public Boolean getIsUp() { return isUp; }
        public void setIsUp(Boolean isUp) { this.isUp = isUp; }

        public Integer getSpeed() { return speed; }
        public void setSpeed(Integer speed) { this.speed = speed; }

        @Override
        public String toString() {
            return "NetworkInterface{" +
                    "name='" + name + '\'' +
                    ", isUp=" + isUp +
                    ", speed=" + speed +
                    '}';
        }
    }

    // 地址信息内部类
    public static class AddressInfo {
        private String family;

        private String address;

        private String netmask;

        private String broadcast;

        public AddressInfo() {}

        // Getter和Setter方法
        public String getFamily() { return family; }
        public void setFamily(String family) { this.family = family; }

        public String getAddress() { return address; }
        public void setAddress(String address) { this.address = address; }

        public String getNetmask() { return netmask; }
        public void setNetmask(String netmask) { this.netmask = netmask; }

        public String getBroadcast() { return broadcast; }
        public void setBroadcast(String broadcast) { this.broadcast = broadcast; }

        @Override
        public String toString() {
            return "AddressInfo{" +
                    "family='" + family + '\'' +
                    ", address='" + address + '\'' +
                    '}';
        }
    }

    // 操作系统信息内部类
    public static class OperatingSystem {
        private String system;

        private String release;

        private String version;

        private String machine;

        private String processor;

        private String platform;

        private String pythonVersion;

        private String prettyName;

        public OperatingSystem() {}

        // Getter和Setter方法
        public String getSystem() { return system; }
        public void setSystem(String system) { this.system = system; }

        public String getRelease() { return release; }
        public void setRelease(String release) { this.release = release; }

        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }

        public String getMachine() { return machine; }
        public void setMachine(String machine) { this.machine = machine; }

        public String getProcessor() { return processor; }
        public void setProcessor(String processor) { this.processor = processor; }

        public String getPlatform() { return platform; }
        public void setPlatform(String platform) { this.platform = platform; }

        public String getPythonVersion() { return pythonVersion; }
        public void setPythonVersion(String pythonVersion) { this.pythonVersion = pythonVersion; }

        public String getPrettyName() { return prettyName; }
        public void setPrettyName(String prettyName) { this.prettyName = prettyName; }

        @Override
        public String toString() {
            return "OperatingSystem{" +
                    "system='" + system + '\'' +
                    ", release='" + release + '\'' +
                    ", prettyName='" + prettyName + '\'' +
                    '}';
        }
    }
}
