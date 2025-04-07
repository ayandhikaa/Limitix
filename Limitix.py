import streamlit as st
import paramiko
import time
import re
import pandas as pd
import plotly.express as px
import ipaddress
from streamlit_extras.app_logo import add_logo
from streamlit_option_menu import option_menu


# Fungsi untuk koneksi SSH ke MikroTik
def connect_ssh(ip, username, password, port=22):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password)
        return ssh, "✅ Connection Successful"
    except Exception as e:
        return None, f"❌ Connection Failed: {str(e)}"

def execute_command(ssh_client, command):
    if ssh_client is None:
        return None, "❌ SSH session not active"
    
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        return output, error
    except Exception as e:
        return None, f"❌ Command Execution Failed: {str(e)}"
    
def parse_rate(rate_str):
    try:
        rate_str = rate_str.lower().replace("bps", "")
        if "k" in rate_str:
            return int(float(rate_str.replace("k", "")) * 1_000)
        elif "m" in rate_str:
            return int(float(rate_str.replace("m", "")) * 1_000_000)
        elif "g" in rate_str:
            return int(float(rate_str.replace("g", "")) * 1_000_000_000)
        else:
            return int(float(rate_str))
    except:
        return 0
    
def get_network_address(subnet):
    return str(ipaddress.ip_network(subnet, strict=False))


# Fungsi Logout
def logout():
    if "logged_in" in st.session_state:
        del st.session_state["logged_in"]
        del st.session_state["ssh_client"]
        del st.session_state["username"]
        st.success("✅ You have logged out successfully!")
        st.stop()
        
def get_ip(interface):
    """Fungsi untuk mendapatkan subnet dari interface yang dipilih."""
    if not interface:
        return None  # Jika interface kosong, kembalikan None
    
    command = f"/ip address print where interface={interface}"
    output, error = execute_command(st.session_state.ssh_client, command)

    if error or not output:
        return None  # Jika output None atau kosong, kembalikan None

    lines = output.strip().split("\n")
    for line in lines:
        parts = line.split()
        for part in parts:
            if '/' in part:
                return part

    
    return None

def validate_ip_range(start_suffix, end_suffix, subnet):
    """Memeriksa apakah rentang IP berada dalam subnet yang benar."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        base_ip = str(network.network_address).rsplit('.', 1)[0]  # Ambil bagian awal IP (contoh: 192.168.1)
        
        start_ip = ipaddress.ip_address(f"{base_ip}.{start_suffix}")
        end_ip = ipaddress.ip_address(f"{base_ip}.{end_suffix}")
        
        return start_ip in network and end_ip in network and start_ip < end_ip
    except ValueError:
        return False

# **LOGIN FORM**
if not st.session_state.get("logged_in"):
    with st.form(key="login_form"):
        st.subheader("🔐 Login to MikroTik")
        ip_address = st.text_input("IP Address", label_visibility="visible")
        username = st.text_input("Username", label_visibility="visible")
        password = st.text_input("Password", type="password", label_visibility="visible")
        port = st.text_input("Port", value=22, label_visibility="visible")
        submit_button = st.form_submit_button("Login")

    if submit_button:
        if ip_address and username and password and port:
            ssh_client, ssh_message = connect_ssh(ip_address, username, password, int(port))
            if ssh_client:
                st.session_state["logged_in"] = True
                st.session_state["ssh_client"] = ssh_client
                st.session_state["username"] = username
                st.success("✅ Login berhasil!")
                st.rerun()
            else:
                st.error(ssh_message)
        else:
            st.warning("⚠️ Harap isi semua kolom.")
else:
    # **SIDE MENU**
    st.title("🚀 LIMITIX - MikroTik Manager")
    with st.sidebar:
        add_logo("https://upload.wikimedia.org/wikipedia/commons/4/42/MikroTik_Logo.png", height=80)
        if st.button("👤" + st.session_state.get("username", "User")):
            st.session_state["menu"] = "User",
        menu = option_menu(
            "Menu" ,
            ["Dashboard", "Manajemen IP Address", "Firewall", "Konfigurasi DNS", "DHCP Client", "DHCP Server", "Bandwidth"],
            icons=["house", "list-task", "shield", "globe", "router", "server", "speedometer"],
            default_index=0
        )
        if st.button("🚪 Logout"):
            logout()


    # **DASHBOARD**
    if menu == "Dashboard":
        st.subheader("🏠 Selamat Datang di LIMITIX")
        st.write("😉 LIMITIX adalah sistem manajemen MikroTik yang memudahkan konfigurasi jaringan Anda.")
        st.markdown("""
        **Fitur yang tersedia:**
        - 🌐 **Manajemen IP Address**
        - 🔥 **Firewall**
        - 🌎 **Konfigurasi DNS**
        - 🖥️ **DHCP Client**
        - 🏠 **DHCP Server**
        - ⏱️ **Limitasi Bandwidth dan Monitoring**
        """)

    # **MANAJEMEN IP ADDRESS**
    elif menu == "Manajemen IP Address":
        st.subheader("🌐 Manajemen IP Address")

        if st.session_state.ssh_client:
            command = "/ip address print without-paging"
            output, error = execute_command(st.session_state.ssh_client, command)

            if error:
                st.error(error)
            else:
                # Memproses output menjadi tabel
                lines = output.split("\n")
                data = []

                for line in lines:
                    # Menggunakan regex untuk memisahkan flag, id, IP Address, dan Interface
                    match = re.match(r"(\d+)\s+([DX]?)\s*(\S+)\s+(\S+)\s+(\S+)", line)
                    if match:
                        id_value, flag, ip_address, network, interface = match.groups()
                        data.append({
                            "ID": id_value,
                            "Flag": flag if flag else "-",  # Jika flag kosong, isi dengan "-"
                            "IP Address": ip_address,
                            "Network": network,
                            "Interface": interface,
                        })

                if data:
                    df = pd.DataFrame(data)
                    st.write("### 📌 Daftar IP Address di MikroTik:")
                    st.table(df)  # Menampilkan tabel yang lebih rapi
                else:
                    st.warning("Tidak ada IP Address yang ditemukan.")

        # Form untuk tambah/hapus IP Address
        ip_address = st.text_input("Masukkan IP Address (Format: x.x.x.x/x)")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        action = st.selectbox("Pilih Aksi", ["Tambah", "Hapus"])
        save_btn = st.button("Save")

        if save_btn and ip_address:
            if action == "Tambah":
                # Cek apakah IP Address sudah ada
                check_cmd = "/ip address print without-paging"
                check_output, check_error = execute_command(st.session_state.ssh_client, check_cmd)

                if check_error:
                    st.error(f"⚠️ Gagal mengecek IP {ip_address}: {check_error}")
                elif check_output and ip_address in check_output:
                    st.warning(f"⚠️ IP Address {ip_address} sudah ada di MikroTik.")
                else:
                    # Tambahkan IP jika belum ada
                    cmd = f"/ip address add address={ip_address} interface={interface}"
                    output, error = execute_command(st.session_state.ssh_client, cmd)

                    if error:
                        st.error(f"⚠️ Gagal menambahkan IP {ip_address}: {error}")
                    else:
                        st.success(f"✅ IP Address {ip_address} berhasil ditambahkan.")
                        st.rerun()

            elif action == "Hapus":
                # Cek apakah IP Address ada di MikroTik
                check_cmd = "/ip address print without-paging"
                check_output, check_error = execute_command(st.session_state.ssh_client, check_cmd)

                if check_error:
                    st.error(f"⚠️ Gagal mengecek IP {ip_address}: {check_error}")
                elif check_output and ip_address in check_output:
                    # Cari ID IP untuk dihapus
                    lines = check_output.split("\n")
                    for line in lines:
                        if ip_address in line and interface in line:
                            match = re.search(r"^\s*(\d+)", line)  # Ambil ID dari awal baris
                            if match:
                                id_to_remove = match.group(1)
                                # Hapus IP berdasarkan ID
                                remove_cmd = f"/ip address remove {id_to_remove}"
                                remove_output, remove_error = execute_command(st.session_state.ssh_client, remove_cmd)

                                if remove_error:
                                    st.error(f"⚠️ Gagal menghapus IP {ip_address}: {remove_error}")
                                else:
                                    st.success(f"✅ IP {ip_address} berhasil dihapus.")
                                    st.rerun()
                                break
                    else:
                        st.warning(f"⚠️ IP Address {ip_address} tidak ditemukan di MikroTik.")
                else:
                    st.warning(f"⚠️ IP Address {ip_address} tidak ditemukan di MikroTik.")
        

    # **FIREWALL**
    elif menu == "Firewall":
        st.subheader("🛡️ Konfigurasi Firewall Rules")
        
            # Fetch and display Layer7 protocol rules directly below the title
        ssh_client = st.session_state.ssh_client
        if not ssh_client:
            st.error("⚠️ Koneksi SSH belum tersedia.")
        else:
            # Get all layer7 protocols
            layer7_command = "/ip firewall layer7-protocol print"
            output, error = execute_command(ssh_client, layer7_command)

            if error:
                st.error(f"⚠️ Gagal mengambil daftar Layer7 Protocols: {error}")
            elif output is None or output.strip() == "":
                st.warning("Tidak ada Website yang diblokir yang ditemukan.")
            else:
                # Process the output into a table
                lines = output.split("\n")
                data = []

                for line in lines:
                    match = re.search(r'^\s*(\d+)\s+(\S+)\s+(.*)', line)
                    if match:
                        id_value, name, regexp = match.groups()
                        data.append({
                            "ID": id_value,
                            "Name": name,
                            "Domain": regexp,
                        })

                if data:
                    df = pd.DataFrame(data)
                    st.write("### Daftar Website yang Diblokir dengan Layer7 Protocol:")
                    st.dataframe(df)
                else:
                    st.warning("Tidak ada Layer7 protocol yang ditemukan.")

        # Input domain website yang akan diblokir
        blocked_website = st.text_input("Masukkan domain website yang ingin diblokir (misal: youtube.com)")
        col1, col2 = st.columns([3, 1])
        with col1:
            save_btn = st.button("Blokir Website")
        with col2:
            reset_btn = st.button("Reset Blokir Website")

        if save_btn:
            ssh_client = st.session_state.ssh_client
            if not ssh_client:
                st.error("⚠️ Koneksi SSH belum tersedia.")
            elif not blocked_website:
                st.error("⚠️ Masukkan domain website yang valid.")
            else:
                layer7_name = f"Block_{blocked_website.replace('.', '_')}"
                layer7_regex = f".*{blocked_website}.*"

                # 1️⃣ Menambahkan Layer7 Protocol
                layer7_command = f'/ip firewall layer7-protocol add name={layer7_name} regexp="{layer7_regex}"'
                output, error = execute_command(ssh_client, layer7_command)

                if error:
                    st.error(f"⚠️ Gagal menambahkan Layer7 Protocol: {error}")
                else:
                    # 2️⃣ Menambahkan Address List
                    address_list_command = f'/ip firewall address-list add list=Blocked_Websites address={blocked_website} comment="Blokir {blocked_website}"'
                    output, error = execute_command(ssh_client, address_list_command)

                    if error:
                        st.error(f"⚠️ Gagal menambahkan Address List: {error}")
                    else:
                        # 3️⃣ Menambahkan Filter Rule untuk Layer7 dan address list
                        filter_layer7_command = f'/ip firewall filter add chain=forward protocol=tcp dst-port=80,443 action=drop dst-address-list=Blocked_Websites layer7-protocol={layer7_name} comment="Blokir {blocked_website}"'
                        output, error = execute_command(ssh_client, filter_layer7_command)

                        if error:
                            st.error(f"⚠️ Gagal menambahkan filter firewall Layer7: {error}")
                        else:
                            if error:
                                st.error(f"⚠️ Gagal menambahkan filter firewall Address List: {error}")
                            else:
                                st.success(f"✅ Website '{blocked_website}' berhasil diblokir dengan Layer7 dan Address List.")
                                st.rerun()


        if reset_btn:
            ssh_client = st.session_state.ssh_client
            if not ssh_client:
                st.error("⚠️ Tidak ada koneksi SSH.")
            else:
                # 1️⃣ Menghapus semua filter rules
                reset_filter_command = "/ip firewall filter remove [find]"
                output, error = execute_command(ssh_client, reset_filter_command)
                if error:
                    st.error(f"⚠️ Gagal mereset filter firewall: {error}")
                else:
                    # 2️⃣ Menghapus semua Layer7 Protocol
                    reset_layer7_command = "/ip firewall layer7-protocol remove [find]"
                    output, error = execute_command(ssh_client, reset_layer7_command)
                    if error:
                        st.error(f"⚠️ Gagal mereset Layer7 Protocol: {error}")
                    else:
                        # 3️⃣ Menghapus semua Address List
                        reset_address_list_command = "/ip firewall address-list remove [find]"
                        output, error = execute_command(ssh_client, reset_address_list_command)
                        if error:
                            st.error(f"⚠️ Gagal mereset Address List: {error}")
                        else:
                            st.success("✅ Semua aturan firewall telah dihapus (Filter, Layer7, dan Address List).")
                            st.rerun()


    # **DNS**                  
    elif menu == "Konfigurasi DNS":
        st.subheader("🌎 Konfigurasi DNS")
        
        dns_option = st.selectbox("Pilih DNS (Domain Name Server)", ["Google", "Cloudflare", "Custom DNS"])
        
        dns_server = ""
        if dns_option == "Custom DNS":
            dns_server = st.text_input("Masukkan DNS Server", placeholder="8.8.8.8")
        elif dns_option == "Google":
            dns_server = "8.8.8.8, 8.8.4.4"
        elif dns_option == "Cloudflare":
            dns_server = "1.1.1.1, 1.0.0.1"
            
        allow_remote = st.checkbox("Allow Remote Requests", value=True)
        save_btn = st.button("Simpan Konfigurasi DNS")
        
        if save_btn and dns_server:
            cmd = f"/ip dns set servers={dns_server} allow-remote-requests={'yes' if allow_remote else 'no'}"
            output, error = execute_command(st.session_state.ssh_client, cmd)
            if error:
                st.error(f"⚠️ Gagal mengeksekusi: {error}")
            else:
                st.success("✅ DNS Server berhasil dikonfigurasi!")
        
        
        # Menampilkan daftar DNS yang telah dikonfigurasi
        def get_dns_servers():
            list_dns_command = "/ip dns print"
            output, error = execute_command(st.session_state.ssh_client, list_dns_command)
            if error:
                st.error(f"⚠️ Gagal mengambil informasi DNS: {error}")
                return []
            return [line.split(':')[1].strip() for line in output.split('\n') if "servers:" in line]
        
        if save_btn:
            st.caption("DNS Server yang Digunakan")
            dns_servers = get_dns_servers()
            st.text("\n".join(dns_servers)) 


    # **DHCP Client*
    elif menu == "DHCP Client":
        st.subheader("📡 Konfigurasi DHCP Client")

        # Form untuk menambah DHCP Client baru
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "wlan1"])
        add_default_route = st.checkbox("Tambahkan Default Route", value=True)
        save_btn = st.button("Simpan DHCP Client")

        if save_btn:
            if "ssh_client" in st.session_state and st.session_state.ssh_client:
                cmd = f"/ip dhcp-client add interface={interface} add-default-route={'yes' if add_default_route else 'no'}"
                output, error = execute_command(st.session_state.ssh_client, cmd)

                if error:
                    st.error(f"⚠️ Gagal mengeksekusi: {error}")
                else:
                    st.success("✅ DHCP Client berhasil ditambahkan!")
            else:
                st.error("⚠️ Tidak ada koneksi SSH.")


    
    # **DHCP Server**
    elif menu == "DHCP Server":
        st.subheader("🏠 Konfigurasi DHCP Server")

        # Pilih interface
        interface = st.selectbox("Pilih Interface untuk DHCP Server", ["ether1", "ether2", "ether3", "ether4", "wlan1", "wlan2"])
        subnet = get_ip(interface)

        if not subnet:
            st.warning("⚠️ Tidak dapat mengambil subnet dari interface yang dipilih. Pastikan interface memiliki IP.")
        else:
            st.info(f"📌 IP Interface Terdeteksi: `{subnet}`")

            # Rentang IP DHCP
            range_option = st.selectbox(
                "Pilih Rentang IP DHCP",
                ["10-50", "51-100", "101-253", "Custom"]
            )

            if range_option != "Custom":
                start_ip_suffix, end_ip_suffix = map(int, range_option.split("-"))
                st.info(f"📌 Rentang IP: {start_ip_suffix} - {end_ip_suffix}")
            else:
                col1, col2 = st.columns(2)
                with col1:
                    start_ip_suffix = st.number_input("IP Awal (Custom)", min_value=2, max_value=253, value=10)
                with col2:
                    end_ip_suffix = st.number_input("IP Akhir (Custom)", min_value=2, max_value=254, value=100)

            # Lease time dengan preset
            lease_option = st.selectbox("Pilih Durasi Lease Time", ["12h", "1d", "3d", "Custom"])
            if lease_option == "Custom":
                lease_time = st.text_input("Durasi Lease (Contoh: 2h, 4d)", value="1h")
            else:
                lease_time = lease_option

            save_btn = st.button("🚀 Aktifkan DHCP Server")

            if save_btn:
                if start_ip_suffix >= end_ip_suffix:
                    st.error("⚠️ IP Awal harus lebih kecil dari IP Akhir.")
                elif not validate_ip_range(start_ip_suffix, end_ip_suffix, subnet):
                    st.error("⚠️ Rentang IP tidak valid dalam subnet.")
                else:
                    # IP dasar dan IP untuk range
                    ip_with_cidr = subnet.split("/")[0]
                    base_ip = ip_with_cidr.rsplit(".", 1)[0]
                    start_ip = f"{base_ip}.{start_ip_suffix}"
                    end_ip = f"{base_ip}.{end_ip_suffix}"

                    # Gateway otomatis dari IP interface (tanpa CIDR)
                    gateway_ip = ip_with_cidr

                    # DNS default Google
                    dns_server = "8.8.8.8"

                    # Pool & DHCP name
                    pool_name = f"dhcp_pool_{interface}"
                    dhcp_name = f"dhcp_{interface}"

                    # Hitung network address
                    network_address = get_network_address(subnet)

                    # Perintah konfigurasi
                    cmd_pool = f"/ip pool add name={pool_name} ranges={start_ip}-{end_ip}"
                    cmd_dhcp_server = (
                        f"/ip dhcp-server add address-pool={pool_name} interface={interface} "
                        f"name={dhcp_name} lease-time={lease_time} disabled=no"
                    )
                    cmd_network = (
                        f"/ip dhcp-server network add address={network_address} "
                        f"gateway={gateway_ip} dns-server={dns_server}"
                    )

                    # Jalankan perintah
                    errors = []
                    for cmd in [cmd_pool, cmd_dhcp_server, cmd_network]:
                        output, error = execute_command(st.session_state.ssh_client, cmd)
                        if error:
                            errors.append(error)

                    # Tampilkan hasil
                    if errors:
                        for err in errors:
                            st.error(f"❌ {err}")
                    else:
                        st.success("✅ DHCP Server berhasil dikonfigurasi!")










                        
    # Limitasi & Monitoring Bandwidth
    elif menu == "Bandwidth":
        st.subheader("📊 Limitasi & Monitoring Bandwidth")

        bd_option = st.selectbox("Tentukan batas", ["100Mbps", "300Mbps", "500Mbps", "Custom Bandwidth"])

        if bd_option == "Custom Bandwidth":
            bandwidth = st.text_input("Masukkan batas bandwidth (kbps)", value=st.session_state.get("bandwidth_limit", "1000"))
        else:
            bandwidth_mapping = {"100Mbps": "100000", "300Mbps": "300000", "500Mbps": "500000"}
            bandwidth = bandwidth_mapping[bd_option]

        try:
            max_limit = int(bandwidth) * 1000  # kbps → bps
        except ValueError:
            st.error("⚠️ Masukkan angka yang valid untuk bandwidth.")
            st.stop()

        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"], index=0)
        limit_btn = st.button("Terapkan Batas Bandwidth")

        if limit_btn and st.session_state.get("ssh_client"):
            try:
                ssh_client = st.session_state.ssh_client
                st.session_state["bandwidth"] = bandwidth

                delete_commands = [
                    f"/queue tree remove [find name=Limit_{interface}_download]",
                    f"/queue tree remove [find name=Limit_{interface}_upload]",
                    f"/ip firewall mangle remove [find comment=Limit_{interface}]",
                ]
                for cmd in delete_commands:
                    execute_command(ssh_client, cmd)

                mangle_commands = [
                    f"/ip firewall mangle add chain=forward action=mark-packet new-packet-mark=Limit_{interface}_upload passthrough=yes out-interface={interface} comment=Limit_{interface}",
                    f"/ip firewall mangle add chain=forward action=mark-packet new-packet-mark=Limit_{interface}_download passthrough=yes in-interface={interface} comment=Limit_{interface}",
                ]
                for cmd in mangle_commands:
                    execute_command(ssh_client, cmd)

                queue_commands = [
                    f"/queue tree add name=Limit_{interface}_download parent={interface} packet-mark=Limit_{interface}_download limit-at={max_limit//2} max-limit={max_limit} burst-limit={int(max_limit*1.1)} burst-threshold={max_limit//2} burst-time=8s queue=default priority=5",
                    f"/queue tree add name=Limit_{interface}_upload parent={interface} packet-mark=Limit_{interface}_upload limit-at={max_limit//2} max-limit={max_limit} burst-limit={int(max_limit*1.1)} burst-threshold={max_limit//2} burst-time=8s queue=default priority=6",
                ]
                for cmd in queue_commands:
                    execute_command(ssh_client, cmd)

                st.success(f"✅ Batas bandwidth {bandwidth} kbps diterapkan pada {interface}.")
            except Exception as e:
                st.error(f"⚠️ Terjadi kesalahan: {str(e)}")

        # --- Monitoring Bandwidth ---
        st.subheader("📡 Monitoring Bandwidth")
        monitor_btn = st.button("Mulai Monitoring")
        if monitor_btn and st.session_state.get("ssh_client"):
            st.session_state["monitoring"] = True

        data = []
        if st.session_state.get("monitoring"):
            monitoring_area = st.empty()
            chart_area = st.empty()

            try:
                while True:
                    ssh_client = st.session_state.ssh_client
                    traffic_command = f"/queue tree print stats where name~'Limit_{interface}'"
                    traffic_output, error = execute_command(ssh_client, traffic_command)

                    if error:
                        monitoring_area.error(f"❌ Gagal mengambil data: {error}")
                        break

                    rx, tx = 0, 0
                    if traffic_output:
                        for line in traffic_output.splitlines():
                            if "name=" in line and "rate=" in line:
                                parts = line.split()
                                for part in parts:
                                    if "rate=" in part:
                                        rate_value = part.split("=")[-1].replace("bps", "").strip()
                                        if rate_value.isdigit():
                                            if "download" in line:
                                                rx = int(rate_value)
                                            elif "upload" in line:
                                                tx = int(rate_value)

                    if rx > max_limit or tx > max_limit:
                        execute_command(ssh_client, f"/queue tree set [find name=Limit_{interface}_download] max-limit={max_limit}")
                        execute_command(ssh_client, f"/queue tree set [find name=Limit_{interface}_upload] max-limit={max_limit}")
                        status = "⚠️ Melebihi Batas! Otomatis Dikendalikan"
                    else:
                        status = "✅ Normal"

                    data.append({"Time": time.strftime("%H:%M:%S"), "Download": rx, "Upload": tx})
                    if len(data) > 20:
                        data.pop(0)

                    df = pd.DataFrame(data)
                    monitoring_area.text(f"📡 Status: {status}")
                    monitoring_area.code(f"⬇️ Download: {rx} bps | ⬆️ Upload: {tx} bps")

                    if not df.empty:
                        fig = px.line(df, x="Time", y=["Download", "Upload"], title="📊 Grafik Penggunaan Bandwidth")
                        chart_area.plotly_chart(fig, use_container_width=True)

                    time.sleep(5)
            except Exception as e:
                monitoring_area.error(f"⚠️ Monitoring dihentikan: {str(e)}")

                
                
        

