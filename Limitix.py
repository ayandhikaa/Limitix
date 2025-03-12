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

# Fungsi mengeksekusi perintah SSH
def execute_command(ssh_client, command):
    if ssh_client is None:
        return None, "❌ SSH session not active"
    
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        return (output, None) if output else (None, error)
    except Exception as e:
        return None, f"❌ Command Execution Failed: {str(e)}"

# Fungsi Logout
def logout():
    if "logged_in" in st.session_state:
        del st.session_state["logged_in"]
        del st.session_state["ssh_client"]
        del st.session_state["username"]
        st.success("✅ You have logged out successfully!")
        st.stop()
        
def get_subnet(interface):
    """Fungsi untuk mendapatkan subnet dari interface yang dipilih."""
    command = f"/ip address print where interface={interface}"
    output, error = execute_command(st.session_state.ssh_client, command)

    if error or not output or not isinstance(output, str) or not output.strip():
        return None  # Jika output None atau kosong, kembalikan None

    lines = output.strip().split("\n")
    for line in lines:
        parts = line.split()
        for part in parts:
            if '/' in part:
                return part  # Mengembalikan subnet (contoh: 192.168.1.1/24)

    return None

    
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
        ip_address = st.text_input("IP Address")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        port = st.text_input("Port", value=22)
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



    # **USER MANAGEMENT**
    if menu == "User":
        st.subheader("👤 Edit User")
        new_username = st.text_input("Masukkan Username Baru")
        new_password = st.text_input("Masukkan Password Baru", type="password")
        save_user_btn = st.button("Simpan Perubahan")
        
        if save_user_btn:
            if new_username and new_password:
                cmd = f"/user set [find name={st.session_state['username']}] name={new_username} password={new_password}"
                output, error = execute_command(st.session_state["ssh_client"], cmd)
                if error:
                    st.error(f"⚠️ Gagal memperbarui user: {error}")
                else:
                    st.success("✅ Username dan Password berhasil diperbarui!")
            else:
                st.warning("⚠️ Harap isi semua kolom.")


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
                            "Interface": interface
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
                # Pastikan IP belum ada sebelum menambah
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

            elif action == "Hapus":
                # Ambil semua IP Address yang ada
                find_cmd = "/ip address print without-paging"
                response = execute_command(st.session_state.ssh_client, find_cmd)

                # Pastikan response valid
                if response and isinstance(response, tuple) and len(response) == 2:
                    find_output, find_error = response
                else:
                    find_output, find_error = None, "Gagal mendapatkan output dari perintah."

                if find_error:
                    st.error(f"⚠️ Gagal mencari IP {ip_address} untuk dihapus: {find_error}")
                elif not find_output or find_output.strip() == "":
                    st.warning(f"⚠️ Tidak ada IP Address yang ditemukan di MikroTik.")
                else:
                    # Ambil ID dari hasil output
                    lines = find_output.split("\n")
                    id_to_remove = None

                    for line in lines:
                        if ip_address in line and interface in line:
                            match = re.search(r"^\s*(\d+)", line)  # Ambil ID dari awal baris
                            if match:
                                id_to_remove = match.group(1)
                                break

                    if id_to_remove:
                        cmd = f"/ip address remove numbers={id_to_remove}"
                        remove_output, remove_error = execute_command(st.session_state.ssh_client, cmd)

                        if remove_error:
                            st.error(f"⚠️ Gagal menghapus IP {ip_address}: {remove_error}")
                        else:
                            st.success(f"✅ IP Address {ip_address} berhasil dihapus.")
                    else:
                        st.error(f"⚠️ IP {ip_address} tidak ditemukan di interface {interface}.")

        

    # **FIREWALL**
    elif menu == "Firewall":
        st.subheader("🛡️ Konfigurasi Firewall Rules")

        # Pilih Jenis Blokir
        block_type = st.selectbox("Blokir Berdasarkan", ["IP/Domain", "Port", "Layer7 Protocol"])

        # Input Berdasarkan Jenis Blokir
        if block_type == "IP/Domain":
            target_ip = st.text_input("Masukkan IP/Domain yang ingin diblokir (misal: 192.168.1.100 atau youtube.com)")
        elif block_type == "Port":
            target_port = st.text_input("Masukkan Port (misal: 443 untuk HTTPS, 80 untuk HTTP, 5228 untuk WhatsApp)", value="443")
        elif block_type == "Layer7 Protocol":
            l7_regex = st.text_area("Masukkan Regex Layer7 (contoh: .*facebook.com.* untuk blokir Facebook)")

        save_btn = st.button("Save")

        if save_btn:
            if 'ssh_client' not in st.session_state or st.session_state.ssh_client is None:
                st.error("⚠️ Koneksi SSH ke MikroTik belum tersedia. Silakan hubungkan terlebih dahulu.")
            else:
                ssh_client = st.session_state.ssh_client
                cmd = ""

                if block_type == "IP/Domain" and target_ip:
                    cmd = f"/ip firewall filter add chain=forward action=drop dst-address={target_ip} comment='Blokir {target_ip}'"
                elif block_type == "Port" and target_port:
                    cmd = f"/ip firewall filter add chain=forward action=drop protocol=tcp dst-port={target_port} comment='Blokir Port {target_port}'"
                elif block_type == "Layer7 Protocol" and l7_regex:
                    l7_cmd = f"/ip firewall layer7-protocol add name=Block_{l7_regex.replace('.', '_')} regexp='{l7_regex}'"
                    execute_command(ssh_client, l7_cmd)  # Tambahkan Layer7 Protocol
                    cmd = f"/ip firewall filter add chain=forward action=drop layer7-protocol=Block_{l7_regex.replace('.', '_')} comment='Blokir Layer7 {l7_regex}'"
                else:
                    st.error("⚠️ Silakan masukkan nilai yang valid untuk blokir.")
                    cmd = ""

                if cmd:
                    output, error = execute_command(ssh_client, cmd)
                    if error:
                        st.error(f"⚠️ Gagal mengeksekusi: {error}")
                    else:
                        st.success(f"✅ Aturan firewall telah diterapkan.")

        # Menampilkan daftar aturan firewall yang telah diterapkan
        st.subheader("📋 Aturan Firewall yang Diterapkan")
        if 'ssh_client' in st.session_state and st.session_state.ssh_client:
            ssh_client = st.session_state.ssh_client
            list_cmd = "/ip firewall filter print terse"
            output, error = execute_command(ssh_client, list_cmd)

            if output:
                rules = output.strip().split("\n")
                for rule in rules:
                    st.write(rule)
        else:
            st.warning("⚠️ Tidak ada koneksi SSH ke MikroTik.")

        # Tombol untuk menghapus aturan firewall
        delete_btn = st.button("Reset")

        if delete_btn:
            if 'ssh_client' in st.session_state and st.session_state.ssh_client:
                ssh_client = st.session_state.ssh_client
                del_cmd = "/ip firewall filter remove [find]"
                output, error = execute_command(ssh_client, del_cmd)
                if error:
                    st.error(f"⚠️ Gagal menghapus aturan: {error}")
                else:
                    st.success("✅ Semua aturan firewall telah dihapus.")
            else:
                st.error("⚠️ Tidak ada koneksi SSH ke MikroTik.")


    # **DNS**                  
    elif menu == "Konfigurasi DNS":
        st.subheader("🌎 Konfigurasi DNS")
        
        dns_option = st.selectbox("Pilih DNS (Domain Name Server)", ["Google", "Cloudflare", "AdGuard", "CleanBrowsing",  "Custom DNS"])
        
        dns_server = ""
        if dns_option == "Custom DNS":
            dns_server = st.text_input("Masukkan DNS Server", placeholder="8.8.8.8")
        elif dns_option == "Google":
            dns_server = "8.8.8.8, 8.8.4.4"
        elif dns_option == "Cloudflare":
            dns_server = "1.1.1.1, 1.0.0.1"
        elif dns_option == "AdGuard  (Blokir iklan)":
            dns_server = "94.140.14.14, 94.140.15.15"
        elif dns_option == "CleanBrowsing (Family Filter)":
            dns_server = "185.228.168.9, 185.228.169.9"
            
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
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "wlan1"])
        add_default_route = st.checkbox("Tambahkan Default Route", value=True)
        save_btn = st.button("Simpan DHCP Client")
        
        if save_btn:
            cmd = f"/ip dhcp-client add interface={interface} add-default-route={'yes' if add_default_route else 'no'}"
            output, error = execute_command(st.session_state.ssh_client, cmd)
            if error:
                st.error(f"⚠️ Gagal mengeksekusi: {error}")
            else:
                st.success("✅ DHCP Client berhasil ditambahkan!")
    
    # **DHCP Server**
    elif menu == "DHCP Server":
        st.subheader("🖧 Konfigurasi DHCP Server")

        st.caption("📜 Daftar DHCP Server")

        # Perintah untuk setiap kolom
        list_ds_command = "/ip dhcp-server print terse"
        list_pool_command = "/ip pool print terse"
        list_lease_command = "/ip dhcp-server lease print count-only"

        # Eksekusi perintah
        output_ds, error_ds = execute_command(st.session_state.ssh_client, list_ds_command)
        output_pool, error_pool = execute_command(st.session_state.ssh_client, list_pool_command)
        output_lease, error_lease = execute_command(st.session_state.ssh_client, list_lease_command)

        # Periksa error sebelum lanjut
        if error_ds:
            st.error(f"⚠️ Gagal mengambil daftar DHCP Server: {error_ds}")
        elif error_pool:
            st.error(f"⚠️ Gagal mengambil daftar IP Pool: {error_pool}")
        elif error_lease:
            st.error(f"⚠️ Gagal mengambil jumlah IP yang digunakan: {error_lease}")
        else:
            dhcp_data = []
            headers = ["ID", "NAME", "INTERFACE", "RENTANG IP", "IP TERPAKAI", "DURASI"]

            # Parsing output DHCP Server
            dhcp_servers = output_ds.strip().split("\n") if output_ds.strip() else []
            pools = output_pool.strip().split("\n") if output_pool.strip() else []
            lease_count = output_lease.strip() if output_lease.strip() else "0"

            for i, line in enumerate(dhcp_servers):
                parts = line.split()
                if len(parts) >= 5:
                    dhcp_id = parts[0]
                    name = parts[1]
                    interface = parts[2]
                    duration = parts[-1]

                    # Ambil rentang IP dari pool yang sesuai
                    ip_range = pools[i].split()[-1] if len(pools) > i else "Tidak diketahui"

                    dhcp_data.append([dhcp_id, name, interface, ip_range, lease_count, duration])

            if dhcp_data:
                df = pd.DataFrame(dhcp_data, columns=headers)
                st.table(df)
            else:
                st.warning("⚠️ Tidak ada data DHCP Server yang tersedia.")

        interface = st.selectbox("Pilih Interface", ["bridge", "ether1", "ether2", "wlan1"])
        subnet = get_subnet(interface)

        gateway = ""
        if subnet:
            base_ip = str(ipaddress.ip_network(subnet, strict=False).network_address).rsplit('.', 1)[0]
            gateway = f"{base_ip}.1"  # Gateway default
        gateway = st.text_input("Masukkan Gateway", value=gateway)

        # 📌 Input Rentang IP
        st.subheader("Rentang IP Address")
        mode = st.selectbox("Pilih Rentang IP", ["Default (2-255)", "Custom"], index=0)
        if mode == "Default (2-255)":
            pool_start_suffix, pool_end_suffix = 2, 255
        else:
            # Jika mode Custom, biarkan pengguna memilih rentang sendiri
            col1, col2 = st.columns(2)
            with col1:
                pool_start_suffix = st.number_input("Awal (0-255)", min_value=0, max_value=255, value=10, step=1)
            with col2:
                pool_end_suffix = st.number_input("Akhir (0-255)", min_value=0, max_value=255, value=100, step=1)


        # 📌 Pilih Opsi DNS
        st.markdown("### Pilih Opsi DNS")
        dns_option = st.selectbox("", ["Google", "Cloudflare", "AdGuard", "CleanBrowsing",  "Custom DNS"])

        dns_server = ""
        if dns_option == "Custom DNS":
            dns_server = st.text_input("Masukkan DNS Server", placeholder="8.8.8.8")
        elif dns_option == "Google":
            dns_server = "8.8.8.8, 8.8.4.4"
        elif dns_option == "Cloudflare":
            dns_server = "1.1.1.1, 1.0.0.1"
        elif dns_option == "AdGuard":
            dns_server = "94.140.14.14, 94.140.15.15"
        elif dns_option == "CleanBrowsing":
            dns_server = "185.228.168.9, 185.228.169.9"

        # 📌 Pilih Durasi DHCP
        st.subheader("Durasi DHCP Server")
        lease_time_option = st.selectbox("", ["12jam", "1hari", "3hari", "Custom Durasi"])

        lease_time = ""
        if lease_time_option == "Custom Durasi":
            lease_time = st.text_input("Masukkan Durasi", placeholder="12h")
        elif lease_time_option == "12jam":
            lease_time = "12h"
        elif lease_time_option == "1hari":
            lease_time = "1d"
        elif lease_time_option == "3hari":
            lease_time = "3d"

        # 📌 Tombol Simpan DHCP Server
        save_btn = st.button("Simpan DHCP Server")

        if save_btn:
            if not (pool_start_suffix and pool_end_suffix and gateway and dns_server and lease_time and subnet):
                st.error("⚠️ Semua kolom harus diisi sebelum menyimpan konfigurasi DHCP Server!")
            elif pool_start_suffix >= pool_end_suffix:
                st.error("⚠️ Rentang IP tidak valid! Awal harus lebih kecil dari akhir.")
            else:
                base_ip = str(ipaddress.ip_network(subnet, strict=False).network_address).rsplit('.', 1)[0]
                address_pool = f"{base_ip}.{pool_start_suffix}-{base_ip}.{pool_end_suffix}"

                commands = [
                    f"/ip pool remove [find where name='dhcp_pool']",  # Hapus pool lama
                    f"/ip pool add name=dhcp_pool ranges={address_pool}",
                    f"/ip dhcp-server remove [find where interface={interface}]",  # Hapus DHCP lama di interface
                    f"/ip dhcp-server add interface={interface} address-pool=dhcp_pool disabled=no lease-time={lease_time}",
                    f"/ip dhcp-server network remove [find where address={subnet}]",  # Hapus network DHCP lama
                    f"/ip dhcp-server network add address={subnet} gateway={gateway} dns-server={dns_server}"
                ]

                for cmd in commands:
                    output, error = execute_command(st.session_state.ssh_client, cmd)
                    if error:
                        st.error(f"⚠️ Gagal mengeksekusi perintah: {cmd}\nError: {error}")
                        break
                else:
                    st.success("✅ DHCP Server berhasil dikonfigurasi!")


                        
    # Limitasi & Monitoring Bandwidth
    elif menu == "Bandwidth":
# **Konfigurasi Batas Bandwidth**
        st.subheader("📊 Limitasi & Monitoring Bandwidth")

        # Pilihan batas bandwidth
        bd_option = st.selectbox("Tentukan batas", ["100Mbps", "300Mbps", "500Mbps", "Custom Bandwidth"])

        if bd_option == "Custom Bandwidth":
            bandwidth = st.text_input("Masukkan batas bandwidth (kbps)", value=st.session_state.get("bandwidth_limit", "1000"))
        else:
            bandwidth_mapping = {"100Mbps": "100000", "300Mbps": "300000", "500Mbps": "500000"}
            bandwidth = bandwidth_mapping[bd_option]

        # Validasi input
        try:
            max_limit = int(bandwidth) * 1000  # Konversi kbps ke bps
        except ValueError:
            st.error("⚠️ Masukkan angka yang valid untuk bandwidth.")
            st.stop()

        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"], index=0)
        limit_btn = st.button("Terapkan Batas Bandwidth")

        if limit_btn and st.session_state.get("ssh_client"):
            try:
                ssh_client = st.session_state.ssh_client
                st.session_state["bandwidth"] = bandwidth

                # Hapus aturan lama lebih spesifik untuk mencegah konflik
                delete_commands = [
                    f"/queue tree remove [find name=Limit_{interface}_download]",
                    f"/queue tree remove [find name=Limit_{interface}_upload]",
                    f"/ip firewall mangle remove [find comment=Limit_{interface}]",
                ]
                for cmd in delete_commands:
                    execute_command(ssh_client, cmd)

                # Tambah aturan baru untuk marking paket
                mangle_commands = [
                    f"/ip firewall mangle add chain=forward action=mark-packet new-packet-mark=Limit_{interface}_upload passthrough=no out-interface={interface} comment=Limit_{interface}",
                    f"/ip firewall mangle add chain=forward action=mark-packet new-packet-mark=Limit_{interface}_download passthrough=no in-interface={interface} comment=Limit_{interface}",
                ]
                for cmd in mangle_commands:
                    execute_command(ssh_client, cmd)

                # Terapkan limitasi dengan batas yang lebih optimal
                queue_commands = [
                    f"/queue tree add name=Limit_{interface}_download parent=global packet-mark=Limit_{interface}_download limit-at={max_limit//2} max-limit={max_limit} burst-limit={max_limit*1.1} burst-threshold={max_limit//2} burst-time=8s queue=default priority=5",
                    f"/queue tree add name=Limit_{interface}_upload parent=global packet-mark=Limit_{interface}_upload limit-at={max_limit//2} max-limit={max_limit} burst-limit={max_limit*1.1} burst-threshold={max_limit//2} burst-time=8s queue=default priority=6",
                ]
                for cmd in queue_commands:
                    execute_command(ssh_client, cmd)

                st.success(f"✅ Batas bandwidth {bandwidth} kbps diterapkan pada {interface}.")
            except Exception as e:
                st.error(f"⚠️ Terjadi kesalahan: {str(e)}")

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
                    traffic_output, _ = execute_command(ssh_client, traffic_command)
                    
                    rx, tx = 0, 0  # Default jika tidak ditemukan
                    if traffic_output:
                        lines = traffic_output.strip().split("\n")
                        for line in lines:
                            if "bytes=" in line:
                                values = [int(x.replace("rate=", "").replace("bps", "").strip()) for x in line.split() if "rate=" in x]
                                if len(values) >= 2:
                                    rx, tx = values[:2]
                    
                    # Jika bandwidth melebihi batas, atur ulang limitasi
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
                    
                    time.sleep(2)
            except Exception as e:
                monitoring_area.error(f"⚠️ Terjadi kesalahan: {str(e)}")
