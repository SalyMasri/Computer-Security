#  Security Assignments – Hashing, Exploitation, Malware & Attacks

##  Overview
This repository contains solutions for various **security-related assignments**, covering **cryptographic weaknesses, buffer overflow exploits, denial-of-service attacks, malware detection, and side-channel vulnerabilities**. Each assignment was successfully completed while **omitting the bonus tasks**.

## 🛠️ Technologies & Tools Used
- **Programming Languages**: Python, C
- **Libraries**: PyCryptodome (AES), GDB (Debugger)
- **Concepts**: Cryptanalysis, Buffer Overflows, Denial-of-Service (DoS), Malware Detection, Side-Channel Attacks
- **Execution Environment**: Docker (for controlled security testing)

---

## 🔑 **1. Hash Function & Collision Attack**
### **Overview**
Implemented a **custom insecure hash function** using **AES decryption**, analyzed its **weak collision resistance**, and developed a **non-brute-force collision attack**.

### **Methodology**
- The hash function **chains AES decryption** for message blocks.
- Implemented **find_collision(message)** to generate two distinct messages with the same hash.
- Ensured **efficient collision discovery** by leveraging structural weaknesses.

### **Results**
✔️ **Demonstrated the insecurity** of the hashing approach.  
✔️ Successfully **found a collision** without brute force.  
✔️ Highlighted the **importance of cryptographic best practices**.

### **Future Work**
- Implement **SHA-based hashing** for security.
- Introduce **randomized padding** to prevent pattern-dependent attacks.

---

## 💣 **2. Buffer Overflow & Control Flow Hijacking**
### **Overview**
Performed **buffer overflows**, **control flow hijacking**, and **code injection** on a vulnerable C program in a controlled **Docker-based** environment.

### **Methodology**
- **Buffer Over-Read**: Extracted **memory contents** beyond buffer limits.
- **Buffer Overflow**: Overwrote **adjacent memory** to manipulate execution.
- **Control Flow Hijacking**: Redirected execution to an **attacker-controlled function**.
- **Code Injection**: Inserted **custom shellcode** for arbitrary execution.

### **Results**
✔️ Successfully **exploited buffer overflow vulnerabilities**.  
✔️ Demonstrated **execution redirection** via control flow hijacking.  
✔️ Used **GDB to analyze stack memory** and function calls.

### **Future Work**
- Implement **stack canaries** and **non-executable stacks** for protection.
- Explore **ROP chain exploitation** for more advanced attacks.

---

## 🚨 **3. Denial of Service (DoS) via Compression Bomb**
### **Overview**
Identified a **denial-of-service vulnerability** in a **custom compression system**, where **small inputs** could lead to **exponential memory allocation**.

### **Methodology**
- **Crafted input** that triggers unbounded memory expansion.
- **Tested multi-threading limitations**, exploiting resource exhaustion.
- **Implemented filtering rules** to block malicious requests.

### **Results**
✔️ Confirmed that **small inputs cause massive memory allocation**.  
✔️ Successfully **designed and implemented a filter** to mitigate the issue.  
✔️ Validated the **effectiveness of the filter** for real-world applications.

### **Future Work**
- Implement **rate limiting** to control request frequency.
- Introduce **server-side memory quotas** to prevent uncontrolled growth.

---

## 🦠 **4. Malware Injection Detection**
### **Overview**
Developed an **automated malware detection system** to identify **payload injections** into Python scripts.

### **Methodology**
- **Static Analysis**: Identified **malicious payloads** based on variable patterns.
- **Signature Matching**: Detected **payload1.py and payload2.py** modifications.
- **Encryption-Agnostic Detection**: Ensured that encrypted payloads were still detectable.

### **Results**
✔️ Successfully **detected malware injections** and payload versions.  
✔️ Detection method worked **even if the payload was encrypted**.  
✔️ **Automated script scanning** enabled **quick analysis of infected files**.

### **Future Work**
- Implement **behavior-based detection** for obfuscated malware.
- Extend scanning to **bulk file analysis**.

---

## 🕵️‍♂️ **5. Side-Channel Attack on Feistel Cipher**
### **Overview**
Performed a **side-channel attack** on a **Feistel cipher**, using **cache timing analysis** to infer **plaintext values**.

### **Methodology**
- **Implemented Feistel Cipher**: A two-round **symmetric encryption** scheme.
- **Cache Timing Analysis**: Measured **access delays** to detect key-dependent variations.
- **Reverse Engineering**: Identified **plaintext bytes** using **cache state leaks**.

### **Results**
✔️ Successfully **extracted partial plaintext values** using **timing leaks**.  
✔️ **Demonstrated side-channel vulnerabilities** in cryptographic implementations.  
✔️ Validated how **cache behavior can expose cryptographic secrets**.

### **Future Work**
- Implement **constant-time cryptographic operations** to prevent timing attacks.
- Introduce **randomized memory access** to reduce cache predictability.

---

## 📜 **6. GDB Debugging & Memory Inspection**
### **Overview**
Used **GDB (GNU Debugger)** to analyze **stack memory, disassembly, and function calls** in a **C program** to identify potential security vulnerabilities.

### **Methodology**
- **Set breakpoints** to pause execution at critical instructions.
- **Inspected memory regions** using **stack tracing and pointer analysis**.
- **Modified memory contents** dynamically to understand **buffer behavior**.

### **Results**
✔️ Successfully **traced function execution and memory layout**.  
✔️ Demonstrated **how memory manipulation can affect program behavior**.  
✔️ **Disassembled code** to analyze compiler-generated instructions.

### **Future Work**
- Use **GDB scripting** for automated memory analysis.
- Extend debugging to **heap-based vulnerabilities**.

---

## ⚔️ **7. Security Best Practices & Lessons Learned**
Throughout these assignments, the following security principles were reinforced:

🔹 **Memory Safety**: Always validate buffer sizes to prevent overflow exploits.  
🔹 **Cryptographic Integrity**: Avoid custom hash functions and use **secure algorithms**.  
🔹 **DoS Prevention**: Limit memory allocation and **apply rate limiting** for network requests.  
🔹 **Malware Detection**: Combine **static & behavioral analysis** for **robust scanning**.  
🔹 **Side-Channel Defenses**: Use **constant-time operations** to eliminate timing leaks.  

---

## 📌 **Final Thoughts**
These projects provided hands-on experience in **ethical hacking, vulnerability detection, and exploit development**. Future work involves refining **defensive measures**, improving **automation**, and expanding **security research** in modern cryptographic implementations.

For questions or contributions, feel free to create a **pull request** or open an **issue** in this repository. 🚀
