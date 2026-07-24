# Module: IoT / SCADA / Embedded

## Topics

- Firmware extraction and filesystem analysis
- Hardcoded secrets and default credentials in firmware
- Insecure update/OTA mechanisms
- Common IoT protocols: MQTT, Modbus, CoAP — enumeration and abuse
- UART/JTAG concepts (exam is simulated, focus stays on firmware-level attacks, not physical hardware access)

## Tools

- binwalk (firmware extraction)
- firmware-mod-kit (filesystem modification/analysis)
- Protocol-specific clients for MQTT/Modbus enumeration

## Practice Resources

- HTB: IoT-tagged machines
- PentesterAcademy: IoT security modules

## Study Sequence

1. Extract and analyze a sample firmware image with binwalk
2. Identify hardcoded credentials/secrets in extracted filesystem
3. Enumerate and interact with an exposed MQTT or Modbus service in a lab
4. Review 2-3 public IoT CVE writeups for attack pattern exposure
