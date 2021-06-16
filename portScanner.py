import socket
import time
from multiprocessing import Pool


# TCP 全连接端口扫描，这是对单主机单端口进行测试，也就是不可再分的任务
def scan(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        s.connect((host, port))
        print("Port open: " + str(port))
        s.close()
        return port
    except:
        s.close()
        return 0


# 多进程扫描
def multi_process_tcp_scan(host, processNumber):
    # print("Multi Process Scanner:", host)
    t0 = time.perf_counter()
    open_list = []
    with Pool(processes=processNumber) as pool:
        for port in range(0, 65535):
            res = pool.apply_async(scan, (host, port,))
            open_list.append(res)
        pool.close()
        pool.join()
    # print("Elapsed time:", time.perf_counter() - t0, 's')
    result = []
    for res in open_list:
        res = res.get()
        if res != 0:
            result.append(res)
    return result


# 单进程扫描
def test_single_process_tcp_scan():
    host = "127.0.0.1"
    print("Single Process Scan Test")
    t0 = time.perf_counter()
    for port in range(0, 1000):
        scan(host, port)
    print("Elapsed time:", time.perf_counter() - t0, 's')


# 多进程扫描
def test_multi_process_tcp_scan(processNumber):
    host = "127.0.0.1"
    print("Multi Process Scan Test")
    t0 = time.perf_counter()
    with Pool(processes=processNumber) as pool:
        for port in range(0, 65535):
            pool.apply_async(scan, (host, port,))
        pool.close()
        pool.join()
    print("Elapsed time:", time.perf_counter() - t0, 's')


# single_process_tcp_scan()
# print(cpu_count())
# print(multi_process_tcp_scan('192.168.142.11', 512))
