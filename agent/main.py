#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
import time
import psutil
import threading
import gzip
import platform
import subprocess
from datetime import datetime


class SystemMonitor:
    def __init__(self):
        """初始化系统监控器"""
        self.socket = None
        self.running = False
        print("使用压缩方法: gzip")

    def connect_to_server(self, ip, port):
        """建立TCP连接"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((ip, port))
            print(f"成功连接到 {ip}:{port}")
            return True
        except Exception as e:
            print(f"连接失败: {e}")
            return False

    def compress_data(self, data):
        """使用gzip压缩数据"""
        try:
            return gzip.compress(data, compresslevel=6)
        except Exception as e:
            print(f"压缩数据时出错: {e}")
            return data

    def get_cpu_info(self):
        """获取CPU信息"""
        try:
            cpu_info = {}

            # CPU型号
            if platform.system() == "Windows":
                try:
                    result = subprocess.run(['wmic', 'cpu', 'get', 'name'],
                                            capture_output=True, text=True, timeout=5)
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        cpu_info['model'] = lines[1].strip()
                    else:
                        cpu_info['model'] = "Unknown"
                except:
                    cpu_info['model'] = "Unknown"
            else:
                # Linux/Unix系统
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        for line in f:
                            if 'model name' in line:
                                cpu_info['model'] = line.split(':')[1].strip()
                                break
                        else:
                            cpu_info['model'] = "Unknown"
                except:
                    cpu_info['model'] = "Unknown"

            # CPU核心数
            cpu_info['physicalCores'] = psutil.cpu_count(logical=False)
            cpu_info['logicalCores'] = psutil.cpu_count(logical=True)

            # CPU频率
            try:
                cpu_freq = psutil.cpu_freq()
                if cpu_freq:
                    cpu_info['maxFrequency'] = cpu_freq.max
                    cpu_info['minFrequency'] = cpu_freq.min
                    cpu_info['currentFrequency'] = cpu_freq.current
                else:
                    cpu_info['maxFrequency'] = None
                    cpu_info['minFrequency'] = None
                    cpu_info['currentFrequency'] = None
            except:
                cpu_info['maxFrequency'] = None
                cpu_info['minFrequency'] = None
                cpu_info['currentFrequency'] = None

            return cpu_info
        except Exception as e:
            print(f"获取CPU信息时出错: {e}")
            return {"model": "Unknown", "physicalCores": None, "logicalCores": None}

    def get_memory_info(self):
        """获取内存信息"""
        try:
            memory_info = {}

            # 基本内存信息
            memory = psutil.virtual_memory()
            memory_info['totalSize'] = memory.total
            memory_info['totalSizeGb'] = round(memory.total / (1024 ** 3), 2)

            # 尝试获取内存频率（主要在Linux系统上有效）
            memory_frequency = None
            if platform.system() == "Linux":
                try:
                    result = subprocess.run(['dmidecode', '-t', 'memory'],
                                            capture_output=True, text=True, timeout=5)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Speed:' in line and 'MHz' in line:
                            memory_frequency = line.split(':')[1].strip()
                            break
                except:
                    pass
            elif platform.system() == "Windows":
                try:
                    result = subprocess.run(['wmic', 'memorychip', 'get', 'speed'],
                                            capture_output=True, text=True, timeout=5)
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1 and lines[1].strip():
                        memory_frequency = f"{lines[1].strip()} MHz"
                except:
                    pass

            memory_info['frequency'] = memory_frequency if memory_frequency else "Unknown"

            return memory_info
        except Exception as e:
            print(f"获取内存信息时出错: {e}")
            return {"total_size": None, "total_size_gb": None, "frequency": "Unknown"}

    def get_network_interfaces(self):
        """获取网卡信息"""
        try:
            interfaces = []
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()

            for interface_name, addresses in net_if_addrs.items():
                interface_info = {
                    "name": interface_name,
                    "addresses": [],
                    "isUp": False,
                    "speed": None
                }

                # 获取地址信息
                for addr in addresses:
                    addr_info = {
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    }
                    interface_info["addresses"].append(addr_info)

                # 获取接口状态和速度
                if interface_name in net_if_stats:
                    stats = net_if_stats[interface_name]
                    interface_info["isUp"] = stats.isup
                    interface_info["speed"] = stats.speed

                interfaces.append(interface_info)

            return interfaces
        except Exception as e:
            print(f"获取网卡信息时出错: {e}")
            return []

    def get_os_info(self):
        """获取操作系统信息"""
        try:
            os_info = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "platform": platform.platform(),
                "pythonVersion": platform.python_version()
            }

            # 获取更详细的系统信息
            try:
                if platform.system() == "Linux":
                    with open('/etc/os-release', 'r') as f:
                        for line in f:
                            if line.startswith('PRETTY_NAME='):
                                os_info['pretty_name'] = line.split('=')[1].strip().strip('"')
                                break
                elif platform.system() == "Windows":
                    os_info['prettyName'] = f"Windows {platform.release()}"
                else:
                    os_info['prettyName'] = platform.platform()
            except:
                os_info['prettyName'] = platform.platform()

            return os_info
        except Exception as e:
            print(f"获取操作系统信息时出错: {e}")
            return {"system": "Unknown"}

    def get_host_info(self):
        """获取主机基本信息"""
        try:
            host_info = {
                "message_type": "host_info",
                "timestamp": datetime.now().isoformat(),
                "hostname": platform.node(),
                "cpu": self.get_cpu_info(),
                "memory": self.get_memory_info(),
                "networkInterfaces": self.get_network_interfaces(),
                "operatingSystem": self.get_os_info()
            }

            return host_info
        except Exception as e:
            print(f"获取主机信息时出错: {e}")
            return None

    def get_system_info(self):
        """获取系统信息"""
        try:
            # 1. 时间戳
            timestamp = datetime.now().isoformat()

            # 2. CPU利用率
            cpu_percent = psutil.cpu_percent(interval=0.1)

            # 3. 内存信息
            memory = psutil.virtual_memory()
            memory_info = {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percent": memory.percent
            }

            # 4. 磁盘信息
            disk = psutil.disk_usage('/')
            disk_info = {
                "total": disk.total,
                "free": disk.free,
                "used": disk.used,
                "percent": (disk.used / disk.total) * 100
            }

            # 5. 网卡信息
            net_io = psutil.net_io_counters()
            network_info = {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv
            }

            # 6. 进程信息
            processes = []
            process_count = 0

            for proc in psutil.process_iter():
                try:
                    process_count += 1
                    pinfo = proc.as_dict(attrs=[
                        'pid', 'ppid', 'name', 'status', 'create_time',
                        'username', 'cpu_percent', 'memory_percent',
                        'memory_info', 'num_threads'
                    ])

                    try:
                        num_fds = proc.num_fds()
                    except (AttributeError, psutil.AccessDenied):
                        num_fds = 0

                    session_id = None
                    try:
                        if hasattr(proc, 'gids'):
                            session_id = proc.gids().real
                    except (AttributeError, psutil.AccessDenied):
                        session_id = None

                    # 格式化进程信息
                    process_info = {
                        "pid": pinfo['pid'],
                        "ppid": pinfo['ppid'],
                        "name": pinfo['name'],
                        "status": pinfo['status'],
                        "create_time": datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo[
                            'create_time'] else None,
                        "username": pinfo['username'],
                        "cpu_percent": pinfo['cpu_percent'],
                        "memory_percent": pinfo['memory_percent'],
                        "memory_rss": pinfo['memory_info'].rss if pinfo['memory_info'] else 0,
                        "memory_vms": pinfo['memory_info'].vms if pinfo['memory_info'] else 0,
                        "num_threads": pinfo['num_threads'],
                        "num_fds": num_fds,
                        "session_id": session_id
                    }
                    processes.append(process_info)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # 组装完整的系统信息
            system_data = {
                "message_type": "system_info",
                "timestamp": timestamp,
                "cpu_percent": cpu_percent,
                "memory": memory_info,
                "disk": disk_info,
                "network": network_info,
                "process_count": process_count,
                "processes": processes
            }

            return system_data

        except Exception as e:
            print(f"获取系统信息时出错: {e}")
            return None

    def send_data(self, data):
        """发送数据到服务器（带gzip压缩）"""
        try:
            # 转换为JSON字符串
            json_data = json.dumps(data, ensure_ascii=False, indent=2)
            original_data = json_data.encode('utf-8')
            original_size = len(original_data)

            # gzip压缩数据
            compressed_data = self.compress_data(original_data)
            compressed_size = len(compressed_data)

            # 计算压缩比
            compression_ratio = (1 - compressed_size / original_size) * 100 if original_size > 0 else 0

            # 发送：消息长度 + 压缩数据
            self.socket.sendall(compressed_size.to_bytes(4, byteorder='big'))
            self.socket.sendall(compressed_data)

            print(f"数据已发送 - 原始: {original_size} 字节, "
                  f"压缩后: {compressed_size} 字节, "
                  f"压缩比: {compression_ratio:.1f}%")

            return True

        except Exception as e:
            print(f"发送数据时出错: {e}")
            return False

    def send_host_info(self):
        """发送主机基本信息"""
        print("正在获取并发送主机基本信息...")
        host_info = self.get_host_info()
        print(host_info)


        if host_info:
            if self.send_data(host_info):
                print("主机基本信息发送成功")
                return True
            else:
                print("主机基本信息发送失败")
                return False
        else:
            print("获取主机基本信息失败")
            return False

    def monitor_loop(self):
        """监控循环"""
        print("开始监控系统信息...")
        while self.running:
            # 获取系统信息
            time.sleep(5)
            system_info = self.get_system_info()

            if system_info:
                # 发送数据
                if not self.send_data(system_info):
                    print("发送失败，停止监控")
                    break

            # 等待1秒
            time.sleep(1)

    def start_monitoring(self):
        """开始监控"""
        # 首先发送主机基本信息
        if not self.send_host_info():
            print("发送主机基本信息失败，无法启动监控")
            return None


        # 启动监控循环
        self.running = True
        monitor_thread = threading.Thread(target=self.monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        return monitor_thread

    def stop_monitoring(self):
        """停止监控"""
        self.running = False
        if self.socket:
            self.socket.close()
            print("连接已关闭")


def main():
    print("=== 系统监控程序（gzip压缩）===")

    # 获取用户输入
    while True:
        try:
            ip_address = input("请输入IP地址: ").strip()
            if not ip_address:
                print("IP地址不能为空，请重新输入")
                continue
            break
        except KeyboardInterrupt:
            print("\n程序已取消")
            return

    while True:
        try:
            port_str = input("请输入端口号: ").strip()
            port = int(port_str)
            if port < 1 or port > 65535:
                print("端口号必须在1-65535之间，请重新输入")
                continue
            break
        except ValueError:
            print("请输入有效的端口号")
            continue
        except KeyboardInterrupt:
            print("\n程序已取消")
            return

    # 创建监控实例
    monitor = SystemMonitor()

    # 建立连接
    if not monitor.connect_to_server(ip_address, port):
        return

    # 开始监控（会先发送主机信息）
    monitor_thread = monitor.start_monitoring()

    if not monitor_thread:
        print("启动监控失败")
        return

    try:
        print("监控已开始，按 Ctrl+C 停止...")
        while monitor.running:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n正在停止监控...")
        monitor.stop_monitoring()
        monitor_thread.join(timeout=2)
        print("程序已退出")


if __name__ == "__main__":
    main()
