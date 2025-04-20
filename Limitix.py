import streamlit as st
import paramiko
import time
import re
import pandas as pd
import plotly.express as px
import ipaddress
import io
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
        st.rerun()
        
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
    
def get_identity(ssh_client):
    output, error = execute_command(ssh_client, "/system identity print")
    if error or not output:
        return "Unknown"
    
    match = re.search(r"name: (\S+)", output)
    if match:
        return match.group(1)
    return "Unknown"


# **LOGIN FORM**
if not st.session_state.get("logged_in"):
    st.header(" ⚡LIMITIX - MikroTik Manager")
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
        identity = get_identity(st.session_state["ssh_client"])
        if st.button(f"👤 {st.session_state.get('username', 'User')} @ {identity}"):
            st.session_state["menu"] = "Setting"
        menu = option_menu(
            "Menu" ,
            ["Dashboard", "Manajemen IP Address", "Firewall", "Konfigurasi DNS", "DHCP Client", "DHCP Server", "Bandwidth", "Setting"],
            icons=["house", "list-task", "shield", "globe", "router", "server", "speedometer", "gear"],
            default_index=0
        )
        if st.button("🚪 Logout"):
            logout()


    # **DASHBOARD**
    if menu == "Dashboard":
        st.subheader("🏠 Selamat Datang di LIMITIX")
        st.write("⚡ LIMITIX adalah sistem manajemen MikroTik berbasis antarmuka yang memudahkan Anda mengelola dan mengkonfigurasi jaringan secara efisien. Dengan tampilan yang mudah digunakan dan fitur otomatis, LIMITIX cocok untuk pemula hingga teknisi profesional tanpa perlu repot menulis perintah manual.")
        st.markdown("""
        **Fitur yang tersedia:**
        - 🌐 **Manajemen IP Address**
        - 🔥 **Firewall**
        - 🌎 **Konfigurasi DNS**
        - 🖥️ **DHCP Client**
        - 🏠 **DHCP Server**
        - ⏱️ **Limitasi Bandwidth dan Monitoring**
        - ⚙️ **Setting nama Router dan password serta backup konfigurasi**
        """)
        
    # **SETTING PROFILE**
    elif menu == "Setting" or st.session_state.get("menu") == "Setting":
        st.subheader("👤 Setting Profile")

        ssh_client = st.session_state["ssh_client"]
        current_username = st.session_state.get("username", "")
        current_identity = get_identity(ssh_client)

        with st.form("profile_form"):
            st.caption("Nama Pengguna")
            st.text(current_username)

            new_identity = st.text_input("🖋️ Nama Router (Identity)", value=current_identity)
            new_password = st.text_input("🔒 Ganti Password Router", type="password", help="Masukkan password baru jika ingin mengganti.")

            save_button = st.form_submit_button("💾 Simpan Perubahan")

            if save_button:
                if new_identity and new_identity != current_identity:
                    set_identity_cmd = f'/system identity set name="{new_identity}"'
                    _, identity_error = execute_command(ssh_client, set_identity_cmd)
                    if identity_error:
                        st.error(f"Gagal mengganti identity: {identity_error}")
                    else:
                        st.success("✅ Nama router berhasil diperbarui!")

                if new_password:
                    set_pass_cmd = f"/user set [find name={current_username}] password={new_password}"
                    _, pass_error = execute_command(ssh_client, set_pass_cmd)
                    if pass_error:
                        st.error(f"Gagal mengganti password: {pass_error}")
                    else:
                        st.success("✅ Password berhasil diperbarui!")

                st.rerun()

        st.markdown("---")
        st.write("### 🛡️ Backup Konfigurasi Router")

        backup_buffer = None
        backup_file_name = None

        with st.form("backup_form"):
            backup_name = st.text_input("Masukkan Nama Backup")
            submitted = st.form_submit_button("📥 Backup Konfigurasi")

            if submitted:
                if not backup_name:
                    st.warning("⚠️ Nama backup tidak boleh kosong.")
                else:
                    try:
                        # 1. Jalankan perintah backup di MikroTik
                        backup_cmd = f"/system backup save name={backup_name}"
                        _, error = execute_command(ssh_client, backup_cmd)

                        if error:
                            st.error(f"Gagal membuat backup: {error}")
                        else:
                            st.success(f"✅ Backup berhasil dibuat: {backup_name}.backup")

                            # 2. Ambil file backup dari router via SFTP
                            sftp = ssh_client.open_sftp()
                            remote_path = f"/{backup_name}.backup"

                            backup_buffer = io.BytesIO()
                            sftp.getfo(remote_path, backup_buffer)
                            sftp.close()

                            backup_buffer.seek(0)
                            backup_file_name = f"{backup_name}.backup"

                            st.session_state["backup_buffer"] = backup_buffer
                            st.session_state["backup_file_name"] = backup_file_name

                    except Exception as e:
                        st.error(f"Gagal mengunduh file backup: {str(e)}")

        # 3. Tampilkan tombol unduh di luar form
        if "backup_buffer" in st.session_state and "backup_file_name" in st.session_state:
            st.download_button(
                label="⬇️ Klik untuk Unduh File Backup",
                data=st.session_state["backup_buffer"],
                file_name=st.session_state["backup_file_name"],
                mime="application/octet-stream"
            )

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
        
        dns_option = st.selectbox("Pilih DNS (Domain Name Server)", ["Google", "Cloudflare", "OpenDNS", "Custom DNS"])
        
        dns_server = ""
        if dns_option == "Custom DNS":
            dns_server = st.text_input("Masukkan DNS Server", placeholder="8.8.8.8")
        elif dns_option == "Google":
            dns_server = "8.8.8.8"
        elif dns_option == "Cloudflare":
            dns_server = "1.1.1.1"
        elif dns_option == "OpenDNS":
            dns_server = "208.67.222.222"
            
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
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "ether4", "wlan1", "wlan2"])
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
            else:
                col1, col2 = st.columns(2)
                with col1:
                    start_ip_suffix = st.number_input("IP Awal (Custom)", min_value=2, max_value=253, value=10)
                with col2:
                    end_ip_suffix = st.number_input("IP Akhir (Custom)", min_value=2, max_value=254, value=100)

            # Lease time dengan preset
            lease_option = st.selectbox("Pilih Durasi DHCP Server", ["12h", "1d", "3d", "Custom"])
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
                                f"/queue type remove [find name=pcq-upload]",            
                                f"/queue type remove [find name=pcq-download]",          
                                f"/ip firewall filter remove [find comment=\"defconf: fasttrack\"]", 
                            ]
                for cmd in delete_commands:
                    execute_command(ssh_client, cmd)

                mangle_commands = [
                    f"/ip firewall mangle add chain=forward action=mark-packet new-packet-mark=Limit_{interface}_upload passthrough=yes out-interface={interface} comment=Limit_{interface}",
                    f"/ip firewall mangle add chain=forward action=mark-packet new-packet-mark=Limit_{interface}_download passthrough=yes in-interface={interface} comment=Limit_{interface}",
                ]
                for cmd in mangle_commands:
                    execute_command(ssh_client, cmd)
                    
                execute_command(ssh_client, f"/queue type add name=pcq-upload kind=pcq pcq-rate={max_limit} pcq-classifier=src-address") 
                execute_command(ssh_client, f"/queue type add name=pcq-download kind=pcq pcq-rate={max_limit} pcq-classifier=dst-address")

                queue_commands = [
                    f"/queue tree add name=Limit_{interface}_download parent=global packet-mark=Limit_{interface}_download limit-at={max_limit//2} max-limit={max_limit} burst-limit={int(max_limit*1.1)} burst-threshold={max_limit//2} burst-time=8s queue=pcq-download priority=5",
                    f"/queue tree add name=Limit_{interface}_upload parent=global packet-mark=Limit_{interface}_upload limit-at={max_limit//2} max-limit={max_limit} burst-limit={int(max_limit*1.1)} burst-threshold={max_limit//2} burst-time=8s queue=pcq-upload priority=6",
                ]
                for cmd in queue_commands:
                    execute_command(ssh_client, cmd)

                st.success(f"✅ Batas bandwidth {bandwidth} kbps diterapkan pada {interface}.")
            except Exception as e:
                st.error(f"⚠️ Terjadi kesalahan: {str(e)}")
                
        st.subheader("📈 Monitoring Bandwidth")

        monitor_interface = st.selectbox(
            "Pilih Interface untuk Monitoring",
            ["ether1", "ether2", "ether3", "wlan1", "wlan2"],
            index=0,
            key="monitor_interface"
        )

        monitor_btn = st.button("Mulai Monitoring Upload & Download")

        def get_queue_rate(ssh_client, queue_name):
            try:
                command = f'/queue tree print stats where name="{queue_name}"'
                stdin, stdout, stderr = ssh_client.exec_command(command)
                output = stdout.read().decode()

                match = re.search(r"rate=(\d+)", output)
                if match:
                    rate_bps = float(match.group(1))
                    return rate_bps / 1000  # to kbps
                return 0
            except Exception as e:
                st.error(f"Gagal membaca queue stats untuk {queue_name}: {str(e)}")
                return 0

        if monitor_btn and st.session_state.get("ssh_client"):
            ssh_client = st.session_state.ssh_client
            data = {"Waktu": [], "Upload (kbps)": [], "Download (kbps)": []}
            placeholder = st.empty()

            try:
                for _ in range(60):  # 5 menit (60x iterasi dengan jeda 5 detik)
                    timestamp = time.strftime("%H:%M:%S")

                    # Pisahkan nama queue
                    upload_queue = f"Limit_{monitor_interface}_upload"
                    download_queue = f"Limit_{monitor_interface}_download"

                    # Ambil data upload & download
                    upload_rate = get_queue_rate(ssh_client, upload_queue)
                    download_rate = get_queue_rate(ssh_client, download_queue)

                    # Simpan data
                    data["Waktu"].append(timestamp)
                    data["Upload (kbps)"].append(upload_rate)
                    data["Download (kbps)"].append(download_rate)

                    # Tampilkan grafik
                    df = pd.DataFrame(data)

                    fig = px.line(
                        df,
                        x="Waktu",
                        y=["Upload (kbps)", "Download (kbps)"],
                        labels={"value": "Bandwidth (kbps)", "Waktu": "Waktu"},
                        title=f"Monitoring Bandwidth di {monitor_interface}",
                        markers=True,
                    )

                    fig.update_traces(line=dict(width=2))
                    fig.for_each_trace(
                        lambda t: t.update(line_color="orange") if t.name == "Upload (kbps)" else t.update(line_color="blue")
                    )

                    placeholder.plotly_chart(fig, use_container_width=True)
                    time.sleep(5)

            except Exception as e:
                st.error(f"⚠️ Gagal mengambil data monitoring: {str(e)}")
