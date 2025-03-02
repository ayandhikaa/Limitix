import streamlit as st
import paramiko
import time
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
        st.success("✅ You have logged out successfully!")
        st.stop()

# **LOGIN FORM**
if not st.session_state.get("logged_in"):
    with st.form(key="login_form"):
        st.subheader("🔐 Login to MikroTik")
        ip_address = st.text_input("IP Address")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        port = st.text_input("Port", value="22")
        submit_button = st.form_submit_button("Login")

    if submit_button:
        if ip_address and username and password and port:
            ssh_client, ssh_message = connect_ssh(ip_address, username, password, int(port))
            if ssh_client:
                st.session_state["logged_in"] = True
                st.session_state["ssh_client"] = ssh_client
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
        menu = option_menu(
            "Menu",
            ["Dashboard", "Manajemen IP Address", "Konfigurasi Wireless", "Firewall NAT", "Konfigurasi DNS", "DHCP Client", "DHCP Server", "Bandwidth"],
            icons=["house", "list-task", "wifi", "shield", "globe", "router", "server", "speedometer"],
            default_index=0
        )
        if st.button("Logout"):
            logout()

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
        """)

    # **MANAJEMEN IP ADDRESS**
    elif menu == "Manajemen IP Address":
        st.subheader("🌐 Manajemen IP Address")

        if st.session_state.ssh_client:
            command = "/ip address print"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.code(output)

        ip_address = st.text_input("Masukkan IP Address (Format: x.x.x.x/x)")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        action = st.selectbox("Pilih Aksi", ["Tambah", "Hapus"])
        save_btn = st.button("Save")

        if save_btn and ip_address:
            if action == "Tambah":
                cmd = f"/ip address add address={ip_address} interface={interface}"
            else:
                cmd = f"/ip address remove [find address={ip_address}]"

            output, error = execute_command(st.session_state.ssh_client, cmd)
            if error:
                st.error(f"⚠️ Gagal mengeksekusi: {error}")
            else:
                st.success(f"✅ IP Address {ip_address} berhasil {action.lower()}.")

# **KONFIGURASI WIRELESS**
    elif menu == "Konfigurasi Wireless":
        st.subheader("📡 Konfigurasi Wireless")
        
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
                    if action == "Tambah":
                        if chain == "srcnat":
                            if firewall_action == "masquerade":
                                cmd = f"/ip firewall nat add chain=srcnat action=masquerade out-interface={out_interface}"
                            elif firewall_action == "drop" and src_ip:
                                cmd = f"/ip firewall nat add chain=srcnat action=drop src-address={src_ip}"
                            else:
                                cmd = f"/ip firewall nat add chain=srcnat action={firewall_action}"
                        else:  # dstnat
                            cmd = f"/ip firewall nat add chain=dstnat action=dst-nat to-addresses={dst_ip} to-ports={dst_port} protocol=tcp dst-port={dst_port}"
                    else:  # Hapus
                        cmd = f"/ip firewall nat remove [find chain={chain}]"

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
        interface = st.selectbox("Pilih Interface", ["bridge", "ether2", "wlan1"])
        address_pool = st.text_input("Masukkan Address Pool (Misal: 192.168.1.10-192.168.1.100)")
        gateway = st.text_input("Masukkan Gateway (Misal: 192.168.1.1)")
        dns_server = st.text_input("Masukkan DNS Server (Misal: 8.8.8.8)")
        save_btn = st.button("Simpan DHCP Server")
        
        if save_btn and address_pool and gateway:
            commands = [
                f"/ip pool add name=dhcp_pool ranges={address_pool}",
                f"/ip dhcp-server add interface={interface} address-pool=dhcp_pool disabled=no",
                f"/ip dhcp-server network add address={gateway}/24 gateway={gateway} dns-server={dns_server}"
            ]
            
            for cmd in commands:
                output, error = execute_command(st.session_state.ssh_client, cmd)
                if error:
                    st.error(f"⚠️ Gagal mengeksekusi: {error}")
                    break
            else:
                st.success("✅ DHCP Server berhasil dikonfigurasi!")     
                
    # Limitasi & Monitoring Bandwidth
    elif menu == "Bandwidth":
        st.subheader("📊 Limitasi & Monitoring Bandwidth")

        # Memasukkan batas maksimal bandwidth
        bandwidth_limit = st.text_input("Masukkan batas maksimal bandwidth (kbps)")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        limit_btn = st.button("Terapkan Batas Bandwidth")

        if limit_btn and st.session_state.ssh_client:
            # Konversi kbps ke bps (MikroTik menggunakan bps)
            max_limit = int(bandwidth_limit) * 1000

            # Periksa apakah queue dengan nama ini sudah ada
            check_command = f"/queue simple print where name=Limit_{interface}"
            existing_output, error = execute_command(st.session_state.ssh_client, check_command)

            if error:
                st.error(f"❌ Gagal memeriksa konfigurasi: {error}")
            else:
                if f"Limit_{interface}" in existing_output:
                    # Jika sudah ada, update queue
                    command = f"/queue simple set [find name=Limit_{interface}] max-limit={max_limit}/{max_limit}"
                    success_message = f"✅ Batas bandwidth {bandwidth_limit} kbps telah diperbarui pada {interface}."
                else:
                    # Jika belum ada, buat queue baru
                    command = f"/queue simple add name=Limit_{interface} target={interface} max-limit={max_limit}/{max_limit}"
                    success_message = f"✅ Batas bandwidth {bandwidth_limit} kbps berhasil diterapkan pada {interface}."

                # Eksekusi perintah update atau tambah
                output, error = execute_command(st.session_state.ssh_client, command)
                if error:
                    st.error(f"❌ Gagal mengonfigurasi bandwidth: {error}")
                else:
                    st.success(success_message)

        # Real-time Monitoring Bandwidth
        monitor_btn = st.button("Mulai Monitoring")

        if monitor_btn and st.session_state.ssh_client:
            monitoring_area = st.empty()  # Area tampilan monitoring

            try:
                while True:
                    command = f"/interface monitor-traffic interface={interface} once"
                    output, error = execute_command(st.session_state.ssh_client, command)
                    if error:
                        monitoring_area.error(f"❌ Gagal monitoring: {error}")
                    else:
                        monitoring_area.text("📡 Output Monitoring:")
                        monitoring_area.code(output)
                    time.sleep(2)  # Update tiap 2 detik
            except Exception as e:
                monitoring_area.error(f"⚠️ Terjadi kesalahan: {str(e)}")
