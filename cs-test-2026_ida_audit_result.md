# cs-test-2026 IDA 自动化静态识别结果

## 完整性复核

1. 函数覆盖完整：main、5 个 Mal_func 和 4 个 Vul_func 均存在。
2. 敏感导入函数覆盖 remove、rename、chmod、system、fork、strncpy、malloc、free、aligned_alloc、mprotect 等关键调用。
3. 关键字符串覆盖完整，包含认证日志、system.sh、hustlogo.png、nc 监听命令、setenforce 0、youarethebest、UAF 和整数溢出提示。
4. 计数校验通过：4 个漏洞 + 7 个恶意代码行为。

## 识别结果

### 1. 漏洞1：strncpy 栈缓冲区溢出

1. 类型：vulnerability
2. 函数：Vul_func1
3. 地址：0x00001776
4. 证据：strncpy(desta, dest + 20, dest[50] + dest[70])，目的缓冲区为 24 字节栈数组，长度来自输入偏移 0x32 与 0x46。
5. 触发条件：共同门槛；避开前置恶意分支；dest[0x12] > dest[0x13]；dest[0x32] + dest[0x46] > 24。

### 2. 漏洞2：Double Free 双重释放

1. 类型：vulnerability
2. 函数：Vul_func2
3. 地址：0x000017E5
4. 证据：同一 ptr 在 0x17CA 被释放后，在 dest[10] > 0x32 条件下于 0x17E5 再次释放。
5. 触发条件：共同门槛；dest[0x1C] < dest[0x1D]；dest[10] > 0x32；malloc(0x0A) 成功。

### 3. 漏洞3：Use After Free 使用后释放

1. 类型：vulnerability
2. 函数：Vul_func3
3. 地址：0x00001896
4. 证据：0x1883 free(addr) 后继续将 addr 传入 mprotect，并在成功路径继续 printf(addr)。
5. 触发条件：共同门槛；避开前置分支；dest[0x26] > dest[0x27]。

### 4. 漏洞4：整数溢出导致堆越界写

1. 类型：vulnerability
2. 函数：Vul_func45
3. 地址：0x00001973
4. 证据：count=0x20000001 左移 3 位后在 32 位下截断为 8，malloc(8) 后执行 ptr - 0x10000000 越界写。
5. 触发条件：共同门槛；dest[0x30] == dest[0x31]；dest[0x32] == 0x21。

### 5. 恶意代码1：删除认证日志

1. 类型：malicious
2. 函数：Mal_func1
3. 地址：0x0000152F
4. 证据：remove("/var/log/auth.log") 删除 Linux 认证日志。
5. 触发条件：共同门槛；dest[1] == 0x42；dest[2] == 0x43。

### 6. 恶意代码2：系统文件重命名

1. 类型：malicious
2. 函数：Mal_func2
3. 地址：0x00001564
4. 证据：rename("/home/cs-test/Test/hustlogo.png", "system.sh") 将图片伪装文件改名为脚本。
5. 触发条件：共同门槛；避开 Mal_func1；dest[2] == 0x38。

### 7. 恶意代码3：修改脚本权限

1. 类型：malicious
2. 函数：Mal_func2
3. 地址：0x00001583
4. 证据：chmod("system.sh", 0x1FF)，0x1FF 对应 0777。
5. 触发条件：Mal_func2 中 rename 成功后继续执行 chmod。

### 8. 恶意代码4：执行本地脚本

1. 类型：malicious
2. 函数：Mal_func2
3. 地址：0x000015AB
4. 证据：system("./system.sh") 执行当前目录脚本。
5. 触发条件：Mal_func2 中 rename 与 chmod 均成功后触发。

### 9. 恶意代码5：开启 nc 后门监听

1. 类型：malicious
2. 函数：Mal_func3
3. 地址：0x0000164A
4. 证据：system("nc -l -p 54321 > hustlogo.png") 监听端口并写入文件。
5. 触发条件：共同门槛；避开前置分支；dest[0x0F] == 0x58。

### 10. 恶意代码6：fork 型进程资源消耗

1. 类型：malicious
2. 函数：Mal_func4
3. 地址：0x000016B8
4. 证据：while(fork()) 循环创建子进程，未发现 wait/waitpid 回收逻辑。
5. 触发条件：共同门槛；避开前置分支；dest[0x0D] == 0x59。

### 11. 恶意代码7：关闭 SELinux 强制访问控制

1. 类型：malicious
2. 函数：Mal_func5
3. 地址：0x00001726
4. 证据：system("setenforce 0") 尝试关闭 SELinux enforcing 模式。
5. 触发条件：共同门槛；避开前置分支；gcd(dest[0x19], dest[0x34]) == 0x47。
