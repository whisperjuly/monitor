#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
import time
import psutil
import threading
import gzip
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

    def monitor_loop(self):
        """监控循环"""
        print("开始监控系统信息...")
        while self.running:
            # 获取系统信息
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

    # 开始监控
    monitor_thread = monitor.start_monitoring()

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
