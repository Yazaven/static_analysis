#!/usr/bin/env python3
import argparse
import re
import os
import json
import tempfile
import subprocess
import magic
import hashlib
from datetime import datetime
from collections import defaultdict
from capstone import *
from capstone.x86 import *
import pefile
import elftools.elf.elffile as elffile
import elftools.elf.sections as sections

try:
    import r2pipe
    HAS_R2 = True
except ImportError:
    HAS_R2 = False

class StaticBinaryAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.arch = None
        self.mode = None
        self.md = None
        self.r2 = None
        self.cfg = {}
        self.functions = {}
        self.strings = []
        self.binary_info = {}
        self.analysis_time = datetime.now().isoformat()
        
        self.dangerous_functions = {
            'strcpy': {'risk': 'High', 'params': [1], 'desc': 'No bounds checking'},
            'strcat': {'risk': 'High', 'params': [1], 'desc': 'No bounds checking'},
            'sprintf': {'risk': 'High', 'params': [1], 'desc': 'No bounds checking'},
            'gets': {'risk': 'Critical', 'params': [0], 'desc': 'No bounds checking'},
            'scanf': {'risk': 'High', 'params': [1], 'desc': 'Format string vulnerability'},
            'system': {'risk': 'Medium', 'params': [0], 'desc': 'Command injection'},
            'popen': {'risk': 'Medium', 'params': [0], 'desc': 'Command injection'},
            'malloc': {'risk': 'Low', 'params': [0], 'desc': 'Memory management issues'},
            'free': {'risk': 'Medium', 'params': [0], 'desc': 'Use-after-free'},
            'memcpy': {'risk': 'Medium', 'params': [0, 1, 2], 'desc': 'Buffer overflow risk'},
            'strncpy': {'risk': 'Medium', 'params': [1], 'desc': 'May not null-terminate'},
            'printf': {'risk': 'Medium', 'params': [0], 'desc': 'Format string vulnerability'},
            'vsprintf': {'risk': 'High', 'params': [1], 'desc': 'No bounds checking'},
            'memmove': {'risk': 'Low', 'params': [0, 1, 2], 'desc': 'Buffer overflow risk'},
            'strlen': {'risk': 'Low', 'params': [0], 'desc': 'Buffer size calculations'},
            'alloca': {'risk': 'High', 'params': [0], 'desc': 'Stack allocation risk'},
            'strtok': {'risk': 'Medium', 'params': [0], 'desc': 'Not thread-safe'},
            'atoi': {'risk': 'Low', 'params': [0], 'desc': 'No error checking'},
            'atof': {'risk': 'Low', 'params': [0], 'desc': 'No error checking'},
            'atol': {'risk': 'Low', 'params': [0], 'desc': 'No error checking'},
        }
        
        self.suspicious_patterns = {
            'execve_syscall': [b'\x0f\x05', b'\xcd\x80'],
            'shellcode_prologue': [b'\x31\xc0', b'\x31\xdb', b'\x31\xc9'],
            'geteip_tricks': [b'\xe8\x00\x00\x00\x00', b'\x5e'],
            'nop_sled': [b'\x90' * 8],
            'return_oriented': [b'\xc3'],
            'anti_debug': [b'\x64\xa1', b'\x31\xc0'],
            'code_cave': [b'\x00' * 16],
            'packer_signatures': [b'UPX', b'ASPack', b'PECompact'],
        }
        
        self.secret_patterns = {
            'api_key': [r'[a-zA-Z0-9]{32}', r'[a-zA-Z0-9]{40}'],
            'jwt_token': [r'eyJhbGciOiJ[^\s"]{20,}'],
            'password': [r'password[=:\s]+["\']?[^\s"\']+["\']?', r'pwd[=:\s]+["\']?[^\s"\']+["\']?'],
            'private_key': [r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'],
            'aws_key': [r'AKIA[0-9A-Z]{16}'],
            'email': [r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'],
            'credit_card': [r'\b(?:\d[ -]*?){13,16}\b'],
            'api_endpoint': [r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[a-zA-Z0-9./?&=_-]+'],
            'ip_address': [r'\b(?:\d{1,3}\.){3}\d{1,3}\b'],
            'md5_hash': [r'\b[a-f0-9]{32}\b'],
            'sha1_hash': [r'\b[a-f0-9]{40}\b'],
            'sha256_hash': [r'\b[a-f0-9]{64}\b'],
            'base64_data': [r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'],
        }
        
        self.taint_sources = [
            'read', 'recv', 'fread', 'fgets', 'gets', 'scanf', 
            'recvfrom', 'recvmsg', 'mmap', 'brk', 'accept', 'recv',
            'getenv', 'getcwd', 'getsockopt', 'ioctl', 'pread', 'readv'
        ]
        
        self.vulnerable_sinks = list(self.dangerous_functions.keys())
        
    def collect_binary_info(self):
        info = {
            'filename': os.path.basename(self.binary_path),
            'file_size': os.path.getsize(self.binary_path),
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'analysis_time': self.analysis_time
        }
        
        with open(self.binary_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                info['md5'].update(chunk)
                info['sha1'].update(chunk)
                info['sha256'].update(chunk)
        
        info['md5'] = info['md5'].hexdigest()
        info['sha1'] = info['sha1'].hexdigest()
        info['sha256'] = info['sha256'].hexdigest()
        
        try:
            info['file_type'] = magic.from_file(self.binary_path)
        except:
            info['file_type'] = "Unknown"
        
        self.binary_info = info
        return info
    
    def identify_architecture(self):
        try:
            file_type = magic.from_file(self.binary_path)
            
            if 'ELF' in file_type:
                with open(self.binary_path, 'rb') as f:
                    elf = elffile.ELFFile(f)
                    if elf.header['e_machine'] == 'EM_X86_64':
                        self.arch = CS_ARCH_X86
                        self.mode = CS_MODE_64
                    elif elf.header['e_machine'] == 'EM_386':
                        self.arch = CS_ARCH_X86
                        self.mode = CS_MODE_32
                    elif elf.header['e_machine'] == 'EM_ARM':
                        self.arch = CS_ARCH_ARM
                        self.mode = CS_MODE_ARM
                    elif elf.header['e_machine'] == 'EM_AARCH64':
                        self.arch = CS_ARCH_ARM64
                        self.mode = CS_MODE_ARM
                    elif elf.header['e_machine'] == 'EM_MIPS':
                        self.arch = CS_ARCH_MIPS
                        self.mode = CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN
                    else:
                        return False
                return True
                
            elif 'PE32' in file_type or 'PE64' in file_type:
                pe = pefile.PE(self.binary_path)
                if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                    self.arch = CS_ARCH_X86
                    self.mode = CS_MODE_64
                elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                    self.arch = CS_ARCH_X86
                    self.mode = CS_MODE_32
                elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']:
                    self.arch = CS_ARCH_ARM
                    self.mode = CS_MODE_ARM
                elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']:
                    self.arch = CS_ARCH_ARM64
                    self.mode = CS_MODE_ARM
                else:
                    return False
                return True
                
            else:
                return False
                
        except Exception as e:
            return False
    
    def initialize_disassembler(self):
        try:
            self.md = Cs(self.arch, self.mode)
            self.md.detail = True
            return True
        except CsError as e:
            return False
    
    def initialize_radare2(self):
        if not HAS_R2:
            return False
            
        try:
            self.r2 = r2pipe.open(self.binary_path)
            self.r2.cmd('aaa')
            return True
        except Exception as e:
            return False
    
    def extract_functions_with_r2(self):
        if not self.r2:
            return {}
            
        try:
            functions_info = self.r2.cmdj('aflj')
            if not functions_info:
                return {}
                
            functions = {}
            for func in functions_info:
                func_addr = func.get('offset', 0)
                functions[func_addr] = {
                    'name': func.get('name', 'unknown'),
                    'size': func.get('size', 0),
                    'callrefs': [],
                    'datarefs': []
                }
                
                xrefs = self.r2.cmdj(f'axtj @{func_addr}')
                if xrefs:
                    for xref in xrefs:
                        if xref.get('type') == 'CALL':
                            functions[func_addr]['callrefs'].append(xref.get('from', 0))
                
            return functions
        except Exception as e:
            return {}
    
    def extract_strings(self):
        strings = []
        
        try:
            result = subprocess.run(['strings', '-a', '-t', 'x', '-n', '4', self.binary_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split(None, 1)
                        if len(parts) >= 2:
                            offset = parts[0]
                            string = parts[1]
                            strings.append({'offset': offset, 'string': string})
        except (subprocess.TimeoutExpired, FileNotFoundError):
            try:
                with open(self.binary_path, 'rb') as f:
                    data = f.read()
                    current_str = ""
                    str_start = 0
                    for i, byte in enumerate(data):
                        if 32 <= byte <= 126:
                            if not current_str:
                                str_start = i
                            current_str += chr(byte)
                        else:
                            if len(current_str) >= 4:
                                strings.append({'offset': hex(str_start), 'string': current_str})
                            current_str = ""
            except Exception as e:
                pass
        
        return strings
    
    def build_control_flow_graph(self, code_sections):
        cfg = {}
        
        for section in code_sections:
            code = section['data']
            base_addr = section['address']
            
            for instruction in self.md.disasm(code, base_addr):
                addr = instruction.address
                cfg[addr] = {
                    'instruction': f"{instruction.mnemonic} {instruction.op_str}",
                    'successors': [],
                    'predecessors': [],
                    'size': instruction.size,
                    'type': 'normal'
                }
                
                if instruction.mnemonic in ['jmp', 'je', 'jne', 'ja', 'jb', 'jz', 'jnz']:
                    cfg[addr]['type'] = 'branch'
                    target_str = instruction.op_str
                    if target_str.startswith('0x'):
                        try:
                            target_addr = int(target_str, 16)
                            cfg[addr]['successors'].append(target_addr)
                        except ValueError:
                            pass
                
                if instruction.mnemonic == 'call':
                    cfg[addr]['type'] = 'call'
                    next_addr = addr + instruction.size
                    cfg[addr]['successors'].append(next_addr)
                    
                    target_str = instruction.op_str
                    if target_str.startswith('0x'):
                        try:
                        
                            target_addr = int(target_str, 16)
                            cfg[addr]['successors'].append(target_addr)
                        except ValueError:
                            pass
                
                if instruction.mnemonic == 'ret':
                    cfg[addr]['type'] = 'return'
                
                if cfg[addr]['type'] == 'normal':
                    next_addr = addr + instruction.size
                    cfg[addr]['successors'].append(next_addr)
        
        for addr, node in cfg.items():
            for successor in node['successors']:
                if successor in cfg:
                    cfg[successor]['predecessors'].append(addr)
        
        return cfg
    
    def analyze_data_flow(self):
        if not self.r2:
            return []
            
        findings = []
        
        try:
            taint_sources = []
            for func_name in self.taint_sources:
                func_info = self.r2.cmdj(f'/j {func_name}')
                if func_info:
                    for match in func_info:
                        taint_sources.append(match.get('offset', 0))
            
            vulnerable_sinks = []
            for func_name in self.vulnerable_sinks:
                func_info = self.r2.cmdj(f'/j {func_name}')
                if func_info:
                    for match in func_info:
                        vulnerable_sinks.append(match.get('offset', 0))
            
            for source in taint_sources:
                for sink in vulnerable_sinks:
                    path_info = self.r2.cmdj(f'agj {source} {sink}')
                    if path_info:
                        findings.append({
                            'type': 'Taint Analysis',
                            'source': source,
                            'sink': sink,
                            'details': f"Potential flow from {hex(source)} to {hex(sink)}",
                            'severity': 'High'
                        })
                        
        except Exception as e:
            pass
            
        return findings
    
    def scan_dangerous_functions(self, code_sections):
        findings = []
        
        for section in code_sections:
            code = section['data']
            base_addr = section['address']
            
            for instruction in self.md.disasm(code, base_addr):
                if instruction.mnemonic == 'call':
                    target = instruction.op_str
                    
                    for func, info in self.dangerous_functions.items():
                        if func in target.lower():
                            context = self.get_call_context(instruction.address, 3)
                            
                            user_controlled = self.check_user_input(instruction.address)
                            
                            finding = {
                                'type': 'Dangerous Function',
                                'address': instruction.address,
                                'function': func,
                                'risk': info['risk'],
                                'details': f"Call to {func} at {hex(instruction.address)}: {instruction.mnemonic} {instruction.op_str}",
                                'context': context,
                                'severity': info['risk'],
                                'user_controlled': user_controlled
                            }
                            
                            if user_controlled:
                                finding['severity'] = 'Critical'
                                finding['details'] += " (user-controlled arguments)"
                            
                            findings.append(finding)
        
        return findings
    
    def check_user_input(self, address):
        if not self.r2:
            return False
            
        try:
            trace_cmd = f"aat {address}"
            trace_result = self.r2.cmd(trace_cmd)
            
            for source in self.taint_sources:
                if source in trace_result:
                    return True
                    
            return False
        except:
            return False
    
    def get_call_context(self, address, num_instructions=5):
        context = []
        
        current_addr = address
        for _ in range(num_instructions):
            if current_addr in self.cfg and self.cfg[current_addr]['predecessors']:
                prev_addr = self.cfg[current_addr]['predecessors'][0]
                if prev_addr in self.cfg:
                    context.insert(0, f"{hex(prev_addr)}: {self.cfg[prev_addr]['instruction']}")
                    current_addr = prev_addr
                else:
                    break
            else:
                break
        
        if address in self.cfg:
            context.append(f"{hex(address)}: {self.cfg[address]['instruction']}")
        
        current_addr = address
        for _ in range(num_instructions):
            if current_addr in self.cfg and self.cfg[current_addr]['successors']:
                next_addr = self.cfg[current_addr]['successors'][0]
                if next_addr in self.cfg:
                    context.append(f"{hex(next_addr)}: {self.cfg[next_addr]['instruction']}")
                    current_addr = next_addr
                else:
                    break
            else:
                break
        
        return context
    
    def scan_suspicious_patterns(self, code_sections):
        findings = []
        
        for section in code_sections:
            code = section['data']
            base_addr = section['address']
            
            for pattern_name, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    offset = code.find(pattern)
                    while offset != -1:
                        addr = base_addr + offset
                        findings.append({
                            'type': 'Suspicious Pattern',
                            'address': addr,
                            'pattern': pattern_name,
                            'details': f"Found {pattern_name} pattern at {hex(addr)}",
                            'severity': 'High' if pattern_name in ['execve_syscall', 'shellcode_prologue'] else 'Medium'
                        })
                        offset = code.find(pattern, offset + 1)
            
            for instruction in self.md.disasm(code, base_addr):
                if instruction.mnemonic in ['syscall', 'int'] and ('0x80' in instruction.op_str or 'syscall' in instruction.mnemonic):
                    findings.append({
                        'type': 'System Call',
                        'address': instruction.address,
                        'details': f"Direct system call at {hex(instruction.address)}: {instruction.mnemonic} {instruction.op_str}",
                        'severity': 'Medium'
                    })
                
                if instruction.mnemonic == 'xor':
                    ops = instruction.op_str.split(',')
                    if len(ops) == 2 and ops[0] == ops[1]:
                        findings.append({
                            'type': 'Zeroing Register',
                            'address': instruction.address,
                            'details': f"Register zeroing at {hex(instruction.address)}: {instruction.mnemonic} {instruction.op_str}",
                            'severity': 'Low'
                        })
                
                if instruction.mnemonic == 'nop':
                    nop_count = 1
                    next_addr = instruction.address + instruction.size
                    while next_addr in self.cfg and 'nop' in self.cfg[next_addr]['instruction']:
                        nop_count += 1
                        next_addr += self.cfg[next_addr]['size']
                    
                    if nop_count >= 8:
                        findings.append({
                            'type': 'NOP Sled',
                            'address': instruction.address,
                            'details': f"Found NOP sled of length {nop_count} at {hex(instruction.address)}",
                            'severity': 'Low'
                        })
                
                if instruction.mnemonic == 'call' and '[' in instruction.op_str and ']' in instruction.op_str:
                    findings.append({
                        'type': 'Indirect Call',
                        'address': instruction.address,
                        'details': f"Indirect call at {hex(instruction.address)}: {instruction.mnemonic} {instruction.op_str}",
                        'severity': 'Medium'
                    })
        
        return findings
    
    def scan_hardcoded_secrets(self):
        findings = []
        
        for string_info in self.strings:
            string = string_info['string']
            offset = string_info['offset']
            
            for secret_type, patterns in self.secret_patterns.items():
                for pattern in patterns:
                    try:
                        matches = re.finditer(pattern, string, re.IGNORECASE)
                        for match in matches:
                            refs = self.find_string_references(string)
                            
                            secret_value = match.group()[:50] + "..." if len(match.group()) > 50 else match.group()
                            
                            finding = {
                                'type': 'Hardcoded Secret',
                                'secret_type': secret_type,
                                'value': secret_value,
                                'details': f"Possible {secret_type}: {secret_value}",
                                'severity': 'High',
                                'references': refs,
                                'offset': offset
                            }
                            
                            if refs:
                                finding['details'] += f" (referenced at {', '.join([hex(ref) for ref in refs])})"
                            
                            findings.append(finding)
                    except re.error:
                        continue
        
        return findings
    
    def find_string_references(self, string):
        refs = []
        
        if not self.r2:
            return refs
            
        try:
            search_results = self.r2.cmdj(f'/j {string}')
            if search_results:
                for result in search_results:
                    refs.append(result.get('offset', 0))
        except Exception as e:
            pass
        
        return refs
    
    def check_protections(self):
        protections = {}
        
        if not self.r2:
            return protections
            
        try:
            info = self.r2.cmdj('ij')
            if info and 'bin' in info:
                bin_info = info['bin']
                protections['nx'] = bin_info.get('nx', False)
                protections['pie'] = bin_info.get('pie', False)
                protections['relro'] = bin_info.get('relro', 'none')
                protections['canary'] = bin_info.get('canary', False)
                protections['stripped'] = bin_info.get('stripped', False)
                
            if 'elf' in info:
                protections['aslr'] = info['elf'].get('aslr', False)
            elif 'pe' in info:
                protections['aslr'] = info['pe'].get('aslr', False)
                
            protections['packed'] = self.r2.cmd('i~packed') != ''
            protections['crypto'] = len(self.r2.cmdj('/j openssl')) > 0 or len(self.r2.cmdj('/j libcrypto')) > 0
            
        except Exception as e:
            pass
        
        return protections
    
    def analyze_vulnerabilities(self):
        findings = []
        
        if not self.r2:
            return findings
            
        try:
            fmt_string_funcs = ['printf', 'sprintf', 'fprintf', 'snprintf', 'vsprintf']
            for func in fmt_string_funcs:
                func_refs = self.r2.cmdj(f'/j {func}')
                if func_refs:
                    for ref in func_refs:
                        addr = ref.get('offset', 0)
                        user_controlled = self.check_user_input(addr)
                        
                        severity = 'High' if user_controlled else 'Medium'
                        details = f"Potential format string vulnerability at {hex(addr)} (call to {func})"
                        if user_controlled:
                            details += " with user-controlled format string"
                            
                        findings.append({
                            'type': 'Format String Vulnerability',
                            'address': addr,
                            'details': details,
                            'severity': severity
                        })
            
            buffer_funcs = ['strcpy', 'strcat', 'sprintf', 'gets']
            for func in buffer_funcs:
                func_refs = self.r2.cmdj(f'/j {func}')
                if func_refs:
                    for ref in func_refs:
                        addr = ref.get('offset', 0)
                        stack_based = self.check_stack_buffer(addr)
                        
                        if stack_based:
                            findings.append({
                                'type': 'Stack Buffer Overflow',
                                'address': addr,
                                'details': f"Potential stack-based buffer overflow at {hex(addr)} (call to {func})",
                                'severity': 'High'
                            })
            
            heap_funcs = ['malloc', 'free', 'calloc', 'realloc']
            for func in heap_funcs:
                func_refs = self.r2.cmdj(f'/j {func}')
                if func_refs:
                    for ref in func_refs:
                        addr = ref.get('offset', 0)
                        if func == 'free':
                            findings.append({
                                'type': 'Heap Vulnerability',
                                'address': addr,
                                'details': f"Potential heap issue at {hex(addr)} (call to {func})",
                                'severity': 'Medium'
                            })
            
        except Exception as e:
            pass
        
        return findings
    
    def check_stack_buffer(self, address):
        if not self.r2:
            return False
            
        try:
            func_info = self.r2.cmdj(f"afbj @{address}")
            if func_info:
                for block in func_info:
                    if 'stack' in str(block).lower():
                        return True
            return False
        except:
            return False
    
    def analyze(self, output_format='text'):
        print(f"Analyzing binary: {self.binary_path}")
        print("=" * 60)
        
        self.collect_binary_info()
        
        if not self.identify_architecture():
            return False
        
        if not self.initialize_disassembler():
            return False
        
        r2_initialized = self.initialize_radare2()
        
        code_sections = self.extract_text_section()
        if not code_sections:
            return False
        
        print("[1/8] Extracting strings...")
        self.strings = self.extract_strings()
        
        print("[2/8] Building control flow graph...")
        self.cfg = self.build_control_flow_graph(code_sections)
        
        if r2_initialized:
            print("[3/8] Extracting function information...")
            self.functions = self.extract_functions_with_r2()
        
        all_findings = []
        
        print("[4/8] Scanning for dangerous function calls...")
        dangerous_calls = self.scan_dangerous_functions(code_sections)
        all_findings.extend(dangerous_calls)
        
        print("[5/8] Scanning for suspicious patterns...")
        suspicious_patterns = self.scan_suspicious_patterns(code_sections)
        all_findings.extend(suspicious_patterns)
        
        print("[6/8] Scanning for hardcoded secrets...")
        hardcoded_secrets = self.scan_hardcoded_secrets()
        all_findings.extend(hardcoded_secrets)
        
        print("[7/8] Analyzing data flow...")
        if r2_initialized:
            data_flow = self.analyze_data_flow()
            all_findings.extend(data_flow)
            
        print("[8/8] Analyzing vulnerabilities...")
        if r2_initialized:
            vulnerabilities = self.analyze_vulnerabilities()
            all_findings.extend(vulnerabilities)
        
        protections = self.check_protections()
        
        if output_format == 'json':
            return self.generate_json_report(all_findings, protections)
        elif output_format == 'html':
            return self.generate_html_report(all_findings, protections)
        else:
            return self.generate_text_report(all_findings, protections)
    
    def generate_text_report(self, findings, protections):
        print("\n" + "=" * 60)
        print("BINARY ANALYSIS REPORT")
        print("=" * 60)
        
        print(f"\nBinary Information:")
        print(f"  File: {self.binary_info['filename']}")
        print(f"  Size: {self.binary_info['file_size']} bytes")
        print(f"  MD5: {self.binary_info['md5']}")
        print(f"  SHA1: {self.binary_info['sha1']}")
        print(f"  SHA256: {self.binary_info['sha256']}")
        print(f"  Type: {self.binary_info['file_type']}")
        print(f"  Analysis Time: {self.binary_info['analysis_time']}")
        
        print(f"\nSecurity Protections:")
        for protection, status in protections.items():
            status_str = "Enabled" if status else "Disabled"
            if isinstance(status, str):
                status_str = status.capitalize()
            print(f"  {protection.upper():<10}: {status_str}")
        
        if not findings:
            print("\nNo security issues found!")
            return True
        
        by_type = {}
        for finding in findings:
            if finding['type'] not in by_type:
                by_type[finding['type']] = []
            by_type[finding['type']].append(finding)
        
        print(f"\nFound {len(findings)} potential security issues:")
        for finding_type, items in by_type.items():
            print(f"  {finding_type}: {len(items)}")
        
        print("\nDetailed Findings:")
        print("-" * 60)
        
        for finding_type, items in by_type.items():
            print(f"\n{finding_type} ({len(items)}):")
            for finding in items:
                severity_color = {
                    'Critical': '\033[91m',
                    'High': '\033[91m',
                    'Medium': '\033[93m',
                    'Low': '\033[92m'
                }.get(finding['severity'], '\033[0m')
                
                print(f"  {severity_color}[{finding['severity']}]\033[0m {finding['details']}")
                
                if 'context' in finding and finding['context']:
                    print("    Context:")
                    for line in finding['context']:
                        print(f"      {line}")
                
                if 'references' in finding and finding['references']:
                    print(f"    References: {', '.join([hex(ref) for ref in finding['references']])}")
                
                if 'user_controlled' in finding and finding['user_controlled']:
                    print("    User-controlled input detected!")
        
        return True
    
    def generate_json_report(self, findings, protections):
        report = {
            'binary_info': self.binary_info,
            'protections': protections,
            'findings': findings,
            'analysis_time': self.analysis_time,
            'summary': {
                'total_findings': len(findings),
                'by_type': {},
                'by_severity': {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0
                }
            }
        }
        
        for finding in findings:
            if finding['type'] not in report['summary']['by_type']:
                report['summary']['by_type'][finding['type']] = 0
            report['summary']['by_type'][finding['type']] += 1
            
            if finding['severity'] in report['summary']['by_severity']:
                report['summary']['by_severity'][finding['severity']] += 1
        
        output_file = f"{self.binary_path}_analysis.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nJSON report saved to: {output_file}")
        return True
    
    def generate_html_report(self, findings, protections):
        try:
            from jinja2 import Template
        except ImportError:
            return self.generate_text_report(findings, protections)
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Binary Analysis Report - {{ binary_info.filename }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #333; }
                h2 { color: #555; }
                .section { margin-bottom: 30px; }
                .finding { border-left: 4px solid #ccc; padding: 10px; margin: 10px 0; }
                .critical { border-left-color: #d9534f; }
                .high { border-left-color: #f0ad4e; }
                .medium { border-left-color: #5bc0de; }
                .low { border-left-color: #5cb85c; }
                .severity { font-weight: bold; }
                .context { font-family: monospace; background: #f5f5f5; padding: 10px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { text-align: left; padding: 8px; }
                tr:nth-child(even) { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Binary Analysis Report</h1>
            <p>Generated: {{ analysis_time }}</p>
            
            <div class="section">
                <h2>Binary Information</h2>
                <table>
                    <tr><th>Property</th><th>Value</th></tr>
                    <tr><td>Filename</td><td>{{ binary_info.filename }}</td></tr>
                    <tr><td>Size</td><td>{{ binary_info.file_size }} bytes</td></tr>
                    <tr><td>MD5</td><td>{{ binary_info.md5 }}</td></tr>
                    <tr><td>SHA1</td><td>{{ binary_info.sha1 }}</td></tr>
                    <tr><td>SHA256</td><td>{{ binary_info.sha256 }}</td></tr>
                    <tr><td>Type</td><td>{{ binary_info.file_type }}</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>Security Protections</h2>
                <table>
                    <tr><th>Protection</th><th>Status</th></tr>
                    {% for protection, status in protections.items() %}
                    <tr>
                        <td>{{ protection.upper() }}</td>
                        <td>
                            {% if status is string %}
                                {{ status.capitalize() }}
                            {% elif status %}
                                Enabled
                            {% else %}
                                Disabled
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            <div class="section">
                <h2>Findings ({{ findings|length }} total)</h2>
                {% for finding in findings %}
                <div class="finding {{ finding.severity|lower }}">
                    <div class="severity">{{ finding.severity }}: {{ finding.type }}</div>
                    <div>{{ finding.details }}</div>
                    {% if finding.context %}
                    <div class="context">
                        <strong>Context:</strong><br>
                        {% for line in finding.context %}
                        {{ line }}<br>
                        {% endfor %}
                    </div>
                    {% endif %}
                    {% if finding.references %}
                    <div><strong>References:</strong> {{ finding.references|join(', ') }}</div>
                    {% endif %}
                    {% if finding.user_controlled %}
                    <div><strong>User-controlled input detected!</strong></div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            binary_info=self.binary_info,
            protections=protections,
            findings=findings,
            analysis_time=self.analysis_time
        )
        
        output_file = f"{self.binary_path}_analysis.html"
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"\nHTML report saved to: {output_file}")
        return True
    
    def extract_text_section(self):
        code_sections = []
        
        try:
            file_type = magic.from_file(self.binary_path)
            
            if 'ELF' in file_type:
                with open(self.binary_path, 'rb') as f:
                    elf = elffile.ELFFile(f)
                    for section in elf.iter_sections():
                        if section.header['sh_flags'] & sections.SH_FLAGS.SHF_EXECINSTR:
                            code_sections.append({
                                'name': section.name,
                                'data': section.data(),
                                'address': section.header['sh_addr']
                            })
            
            elif 'PE32' in file_type or 'PE64' in file_type:
                pe = pefile.PE(self.binary_path)
                for section in pe.sections:
                    if section.Characteristics & 0x20000000:
                        code_sections.append({
                            'name': section.Name.decode().rstrip('\x00'),
                            'data': section.get_data(),
                            'address': section.VirtualAddress
                        })
            
            return code_sections
            
        except Exception as e:
            return []

def main():
    parser = argparse.ArgumentParser(description='Static Binary Analyzer')
    parser.add_argument('binary', help='Path to the binary file to analyze')
    parser.add_argument('--format', choices=['text', 'json', 'html'], default='text',
                       help='Output format (default: text)')
    args = parser.parse_args()
    
    if not os.path.isfile(args.binary):
        print(f"Error: File '{args.binary}' not found")
        return
    
    analyzer = StaticBinaryAnalyzer(args.binary)
    analyzer.analyze(output_format=args.format)

if __name__ == '__main__':
    main()