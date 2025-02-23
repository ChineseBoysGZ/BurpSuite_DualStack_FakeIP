# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name:     DualStack fakeIP
   Description:   DualStack IPv4/IPv6 Supported
   Author:        Luoboying
   date:          2025-02-23
-------------------------------------------------
"""

import random
from burp import IBurpExtender, IContextMenuFactory, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator
from javax.swing import JMenu, JMenuItem, JOptionPane
from java.awt.event import ActionListener

class BurpExtender(IBurpExtender, IContextMenuFactory, IIntruderPayloadGeneratorFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("DualStack fakeIP")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
        self.ip_headers = [
            'X-Forwarded-For', 'X-Forwarded', 'Forwarded-For',
            'Forwarded', 'X-Forwarded-Host', 'X-remote-IP',
            'X-remote-addr', 'True-Client-IP', 'X-Client-IP',
            'Client-IP', 'X-Real-IP', 'Ali-CDN-Real-IP',
            'Cdn-Src-Ip', 'Cdn-Real-Ip', 'CF-Connecting-IP',
            'X-Cluster-Client-IP', 'WL-Proxy-Client-IP',
            'Proxy-Client-IP', 'Fastly-Client-Ip', 'True-Client-Ip'
        ]

    # ==================== 菜单处理 ====================
    def createMenuItems(self, invocation):
        self.invocation = invocation
        menu = JMenu("DualStack fakeIP")
        
        menu_items = [
            ("Input IP", self._handle_input_ip),
            ("IPv4 Loopback (127.0.0.1)", lambda: self._modify_all_headers("127.0.0.1", False, "ipv4")),
            ("IPv6 Loopback (::1)", lambda: self._modify_all_headers("::1", False, "ipv6")),
            ("Random IPv4", lambda: self._modify_all_headers(None, True, "ipv4")),
            ("Random IPv6", lambda: self._modify_all_headers(None, True, "ipv6")),
            ("XFF XSS Test", self._handle_xss),
            ("XFF Injection Test", self._handle_injection)
        ]
        
        for title, handler in menu_items:
            item = JMenuItem(title)
            item.addActionListener(self._ActionAdapter(handler))
            menu.add(item)
            
        return [menu]
    
    # ==================== IP生成方法 ====================
    def _generate_ip(self, ip_type):
        if ip_type == "ipv4":
            return ".".join(str(random.randint(0,255)) for _ in range(4))
        elif ip_type == "ipv6":
            return ":".join(format(random.randint(0, 0xFFFF), '04x') for _ in range(8))
        return ""

    # ==================== 事件适配器 ====================
    class _ActionAdapter(ActionListener):
        def __init__(self, handler):
            self.handler = handler
            
        def actionPerformed(self, _):
            self.handler()

    # ==================== 事件处理器 ====================
    def _handle_input_ip(self):
        ip = JOptionPane.showInputDialog("Input (IPv4/IPv6):")
        if ip:
            self._modify_all_headers(ip, False, "custom")

    def _handle_xss(self):
        base_ip = self._generate_ip("ipv4" if random.choice([True, False]) else "ipv6")
        payload = "{}<script>alert('XSS')</script>".format(base_ip)
        self._modify_single_header("X-Forwarded-For", payload)

    def _handle_injection(self):
        base_ip = self._generate_ip("ipv4" if random.choice([True, False]) else "ipv6")
        payload = "{}' OR 1=1-- -".format(base_ip)
        self._modify_single_header("X-Forwarded-For", payload)

    # ==================== 核心请求处理 ====================
    def _modify_all_headers(self, base_value, is_random, ip_type):
        try:
            for message in self.invocation.getSelectedMessages():
                http_service = message.getHttpService()
                request = message.getRequest()
                
                analyzed = self.helpers.analyzeRequest(http_service, request)
                headers = list(analyzed.getHeaders())
                
                headers = [h for h in headers if not any(
                    h.startswith(header + ":") for header in self.ip_headers
                )]
                
                for header in self.ip_headers:
                    if is_random:
                        value = self._generate_ip(ip_type)
                    else:
                        value = base_value
                    headers.append("{}: {}".format(header, value))
                
                body = request[analyzed.getBodyOffset():]
                new_request = self.helpers.buildHttpMessage(headers, body)
                message.setRequest(new_request)
                
        except Exception as e:
            self.callbacks.printError("Process Error: {}".format(str(e)))

    def _modify_single_header(self, header, value):
        try:
            for message in self.invocation.getSelectedMessages():
                http_service = message.getHttpService()
                request = message.getRequest()
                
                analyzed = self.helpers.analyzeRequest(http_service, request)
                headers = list(analyzed.getHeaders())
                
                headers = [h for h in headers if not h.startswith(header + ":")]
                headers.append("{}: {}".format(header, value))
                
                body = request[analyzed.getBodyOffset():]
                new_request = self.helpers.buildHttpMessage(headers, body)
                message.setRequest(new_request)
                
        except Exception as e:
            self.callbacks.printError("Process Error: {}".format(str(e)))

    # ==================== Intruder爆破Payload生成器 ====================
    def getGeneratorName(self):
        return "fakeIpPayloads"

    def createNewInstance(self, attack):
        options = ["IPv4 Only", "IPv6 Only", "Both (Default)"]
        choice = JOptionPane.showInputDialog(
            None,
            "Select IP Type:",
            "Payload Configuration",
            JOptionPane.QUESTION_MESSAGE,
            None,
            options,
            options
        )
        
        if choice not in options:
            choice = options
        
        mode_map = {
            "IPv4 Only": "ipv4",
            "IPv6 Only": "ipv6",
            "Both (Default)": "both"
        }
        return _MultiHeaderPayloadGenerator(mode_map.get(choice, "both"))

class _MultiHeaderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, ip_mode="both"):
        self.payload_count = 0
        self.max_payloads = 100
        self.ip_mode = ip_mode
        
        self.generators = {
            "ipv4": [lambda: ".".join(str(random.randint(0,255)) for _ in range(4))],
            "ipv6": [lambda: ":".join(format(random.randint(0, 0xFFFF), '04x') for _ in range(8))],
            "both": [
                lambda: ".".join(str(random.randint(0,255)) for _ in range(4)),
                lambda: ":".join(format(random.randint(0, 0xFFFF), '04x') for _ in range(8))
            ]
        }
    
    def hasMorePayloads(self):
        return self.payload_count < self.max_payloads
        
    def getNextPayload(self, _):
        if self.ip_mode == "ipv4":
            gen = random.choice(self.generators["ipv4"])
        elif self.ip_mode == "ipv6":
            gen = random.choice(self.generators["ipv6"])
        else:
            gen = random.choice(self.generators["both"])
        
        self.payload_count += 1
        return bytearray(gen())
    
    def reset(self):
        self.payload_count = 0

