import streamlit as st
import paramiko
import time
import re
import pandas as pd
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
            ["Dashboard", "Manajemen IP Address", "Konfigurasi Wireless", "Firewall NAT", "Konfigurasi DNS", "DHCP Client", "DHCP Server", "Bandwidth"],
            icons=["house", "list-task", "wifi", "shield", "globe", "router", "server", "speedometer"],
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
        - 📡 **Konfigurasi Wireless**
        - 🔥 **Firewall NAT**
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


# **KONFIGURASI WIRELESS**
    elif menu == "Konfigurasi Wireless":
        st.subheader("📡 Konfigurasi Wireless")
        
        # Menampilkan daftar SSID yang telah dikonfigurasi
        list_ssid_command = "/interface wireless print"
        output, error = execute_command(st.session_state.ssh_client, list_ssid_command)
        
        if error:
            st.error(f"⚠️ Gagal mengambil daftar SSID: {error}")
        else:
            st.text(output)
        
        interface = st.selectbox("Pilih Interface Wireless", ["wlan1", "wlan2"])
        new_ssid = st.text_input("Masukkan SSID Baru")
        new_password = st.text_input("Masukkan Password Baru", type="password")
        wireless_mode = st.selectbox("Pilih Mode Wireless", ["ap-bridge", "station", "bridge", "wds-slave"])
        save_btn = st.button("Simpan Konfigurasi")
        
        if save_btn:
            if not new_ssid or not new_password:
                st.warning("⚠️ Harap isi SSID dan Password!")
                st.stop()

            commands = [
                f'/interface wireless set {interface} ssid="{new_ssid}"',
                f'/interface wireless security-profiles set default authentication-types=wpa2-psk wpa2-pre-shared-key="{new_password}"',
                f'/interface wireless set {interface} mode={wireless_mode}'
            ]

            for cmd in commands:
                output, error = execute_command(st.session_state.ssh_client, cmd)
                if error:
                    st.error(f"⚠️ Gagal mengeksekusi: {error}")
                    break
            else:
                st.success("✅ Konfigurasi Wireless berhasil diperbarui!")
        

    # **FIREWALL NAT**
    elif menu == "Firewall NAT":
        st.subheader("🛡️ Konfigurasi Firewall NAT")
        
        chain = st.selectbox("Pilih Chain", ["srcnat", "dstnat"])
        firewall_action = st.selectbox("Pilih Action", ["masquerade", "dst-nat", "src-nat", "accept", "drop"])
        out_interface = st.text_input("Masukkan Out Interface (Misal: ether1)")
        dst_ip = st.text_input("Masukkan IP Tujuan (Opsional untuk dstnat)")
        dst_port = st.text_input("Masukkan Port Tujuan (Opsional untuk dstnat)", value="80")
        src_ip = st.text_input("Masukkan IP Sumber (Opsional untuk blokir akses)")
        action = st.selectbox("Pilih Aksi", ["Tambah", "Hapus"])
        save_btn = st.button("Save")
        
        if save_btn:
            if 'ssh_client' not in st.session_state or st.session_state.ssh_client is None:
                st.error("⚠️ Koneksi SSH ke MikroTik belum tersedia. Silakan hubungkan terlebih dahulu.")
            else:
                if action == "Tambah":
                    if chain == "srcnat":
                        if firewall_action == "masquerade" and out_interface:
                            cmd = f"/ip firewall nat add chain=srcnat action=masquerade out-interface={out_interface}"
                        elif firewall_action == "drop" and src_ip:
                            cmd = f"/ip firewall nat add chain=srcnat action=drop src-address={src_ip}"
                        else:
                            cmd = f"/ip firewall nat add chain=srcnat action={firewall_action}"
                    else:  # dstnat
                        if dst_ip:
                            cmd = f"/ip firewall nat add chain=dstnat action=dst-nat to-addresses={dst_ip} to-ports={dst_port} protocol=tcp dst-port={dst_port}"
                        else:
                            st.error("⚠️ IP tujuan harus diisi untuk dst-nat.")
                            cmd = ""
                else:  # Hapus aturan NAT
                    check_cmd = f"/ip firewall nat print where chain={chain}"
                    output, error = execute_command(st.session_state.ssh_client, check_cmd)
                    if not output or "no such item" in output:
                        st.warning("⚠️ Tidak ada aturan yang cocok untuk dihapus.")
                        cmd = ""
                    else:
                        cmd = f"/ip firewall nat remove [find where chain={chain}]"
                
                if cmd:
                    output, error = execute_command(st.session_state.ssh_client, cmd)
                    if error:
                        st.error(f"⚠️ Gagal mengeksekusi: {error}")
                    else:
                        st.success(f"✅ Firewall NAT berhasil dikonfigurasi.")

    # **DNS**                  
    elif menu == "Konfigurasi DNS":
        st.subheader("🌎 Konfigurasi DNS")
        
        dns_server = st.text_input("Masukkan DNS Server (Misal: 8.8.8.8)")
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

        # Menampilkan daftar DHCP Server yang telah dikonfigurasi dalam bentuk tabel
        st.caption("📜 Daftar DHCP Server")
        list_ds_command = "/ip dhcp-server print terse"
        output, error = execute_command(st.session_state.ssh_client, list_ds_command)

        if error:
            st.error(f"⚠️ Gagal mengambil daftar DHCP server: {error}")
        else:
            dhcp_data = []
            if output and isinstance(output, str) and output.strip():  # Cek apakah output tidak kosong
                lines = output.strip().split("\n")
                headers = ["ID", "INTERFACE", "ADDRESS POOL", "LEASE TIME", "STATUS"]

                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:  # Pastikan jumlah kolom cukup
                        dhcp_data.append(parts[:5])

                if dhcp_data:
                    df = pd.DataFrame(dhcp_data, columns=headers)
                    st.table(df)
                else:
                    st.warning("⚠️ Tidak ada data DHCP Server yang tersedia.")
            else:
                st.warning("⚠️ Tidak ada output yang diterima dari perintah SSH.")
    
        interface = st.selectbox("Pilih Interface", ["bridge", "ether1", "ether2", "wlan1"])
        
        col1, col2 = st.columns(2)
        with col1:
            pool_start = st.text_input("Address Pool Awal", placeholder="192.168.1.10")
        with col2:
            pool_end = st.text_input("Address Pool Akhir", placeholder="192.168.1.100")

        gateway = st.text_input("Masukkan Gateway (Misal: 192.168.1.1)")
        dns_server = st.text_input("Masukkan DNS Server (Misal: 8.8.8.8)")
        lease_time = st.text_input("Masukkan Lease Time (Misal: 12h)")

        save_btn = st.button("Simpan DHCP Server")

        if save_btn:
            if not (pool_start and pool_end and gateway and dns_server and lease_time):
                st.error("⚠️ Semua kolom harus diisi sebelum menyimpan konfigurasi DHCP Server!")
            else:
                address_pool = f"{pool_start}-{pool_end}"
                commands = [
                    f"/ip pool add name=dhcp_pool ranges={address_pool}",
                    f"/ip dhcp-server add interface={interface} address-pool=dhcp_pool disabled=no lease-time={lease_time}",
                    f"/ip dhcp-server network add address={gateway}/24 gateway={gateway} dns-server={dns_server}"
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
        st.subheader("📊 Limitasi & Monitoring Bandwidth (Queue Tree)")

        # Input batas bandwidth & interface
        bandwidth_limit = st.text_input("Masukkan batas bandwidth (kbps)", value="1000")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        limit_btn = st.button("Terapkan Batas Bandwidth")

        if limit_btn and st.session_state.ssh_client:
            max_limit = int(bandwidth_limit) * 1000  # Konversi kbps ke bps

            # Hapus aturan lama jika ada
            delete_commands = [
                f"/queue tree remove [find name=Limit_{interface}_upload]",
                f"/queue tree remove [find name=Limit_{interface}_download]",
                f"/ip firewall mangle remove [find comment=Limit_{interface}]"
            ]
            for cmd in delete_commands:
                execute_command(st.session_state.ssh_client, cmd)
            
            # Tambahkan Mangle untuk menandai paket upload & download
            mangle_commands = [
                f"/ip firewall mangle add chain=forward action=mark-packet new-packet-mark=Limit_{interface}_upload passthrough=no out-interface={interface} comment=Limit_{interface}",
                f"/ip firewall mangle add chain=forward action=mark-packet new-packet-mark=Limit_{interface}_download passthrough=no in-interface={interface} comment=Limit_{interface}"
            ]
            for cmd in mangle_commands:
                execute_command(st.session_state.ssh_client, cmd)
            
            # Tambahkan Queue Tree untuk membatasi bandwidth
            queue_commands = [
                f"/queue tree add name=Limit_{interface}_download parent=global packet-mark=Limit_{interface}_download max-limit={max_limit}",
                f"/queue tree add name=Limit_{interface}_upload parent=global packet-mark=Limit_{interface}_upload max-limit={max_limit}"
            ]
            for cmd in queue_commands:
                execute_command(st.session_state.ssh_client, cmd)
            
            st.success(f"✅ Batas bandwidth {bandwidth_limit} kbps diterapkan pada {interface}.")

        # Monitoring Bandwidth
        monitor_btn = st.button("Mulai Monitoring")

        if monitor_btn and st.session_state.ssh_client:
            monitoring_area = st.empty()

            while True:
                try:
                    queue_command = f"/queue tree print where name~\"Limit_{interface}\""
                    queue_output, error = execute_command(st.session_state.ssh_client, queue_command)

                    traffic_command = f"/interface monitor-traffic interface={interface} once"
                    traffic_output, error = execute_command(st.session_state.ssh_client, traffic_command)

                    if error:
                        monitoring_area.error(f"❌ Gagal monitoring: {error}")
                    else:
                        monitoring_area.text("📡 Output Monitoring:")
                        monitoring_area.code(f"📊 Queue Tree Status:\n{queue_output}\n\n📡 Traffic Stats:\n{traffic_output}")

                    time.sleep(2)  # Update tiap 2 detik
                except Exception as e:
                    monitoring_area.error(f"⚠️ Terjadi kesalahan: {str(e)}")
                    break
