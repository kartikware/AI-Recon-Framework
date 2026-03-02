import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_data):
    open_ports = []

    try:
        root = ET.fromstring(xml_data)

        for host in root.findall("host"):
            for port in host.findall(".//port"):
                state = port.find("state").get("state")

                if state == "open":
                    port_id = port.get("portid")
                    protocol = port.get("protocol")

                    service_elem = port.find("service")

                    service_name = ""
                    product = ""
                    version = ""

                    if service_elem is not None:
                        service_name = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        version = service_elem.get("version", "")

                    # Prefer product name if available (more accurate)
                    if product:
                        service_name = product

                    open_ports.append({
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "version": version
                    })

        return open_ports

    except Exception:
        return []
