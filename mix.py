import streamlit as st
import paramiko
import pandas as pd

# Membaca Style.css
st.markdown("""
<style>
h1 {
    text-align: center;
}

h2 {
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# Fungsi untuk membuat koneksi SSH
def connect_ssh(ip, username, password, port=22):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password)
        return ssh, "Connection Successful"
    except Exception as e:
        return None, f"Connection Failed: {str(e)}"

# Fungsi untuk mengeksekusi perintah SSH
def execute_command(ssh, command):
    try:
        stdin, stdout, stderr = ssh.exec_command(command)
        return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')
    except Exception as e:
        return None, f"Command Execution Failed: {str(e)}"

# Antarmuka Streamlit
st.title("LIMITIX")

# Login Form
if "logged_in" not in st.session_state:
    with st.form("login_form"):
        st.subheader("Login to MikroTik")
        ip_address = st.text_input("IP Address", placeholder="Enter MikroTik IP Address")
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submit_button = st.form_submit_button("Login")

    if submit_button:
        if ip_address and username and password:
            st.write("Connecting to MikroTik...")
            ssh_client, ssh_message = connect_ssh(ip_address, username, password)
            if ssh_client:
                st.session_state.logged_in = True
                st.session_state.ssh_client = ssh_client
                st.success("Login berhasil! Silakan gunakan fitur di sidebar.")
                st.rerun()  # Refresh halaman setelah login
            else:
                st.error(ssh_message)
        else:
            st.warning("Please fill in all fields (IP Address, Username, and Password).")

else:
    # Sidebar untuk fitur
    st.sidebar.header("Pilih Fitur")
    menu = st.sidebar.selectbox("Fitur", ["Manajemen IP Address", "Konfigurasi Wireless", "Monitoring Bandwidth"])
    
    # Manajemen IP Address
    if menu == "Manajemen IP Address":
        st.subheader("Manajemen IP Address")
        
        # Menampilkan daftar IP Address dan Interface yang ada dalam tabel
        list_command = "/ip address print terse"
        output, _ = execute_command(st.session_state.ssh_client, list_command)
        
        ip_data = []
        for line in output.split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                ip_address_value = parts[1].replace("address=", "")
                interface_value = parts[3].replace("interface=", "")
                ip_data.append({"IP Address": ip_address_value, "Interface": interface_value})
        
        if ip_data:
            df = pd.DataFrame(ip_data)
            st.table(df)
        else:
            st.write("Tidak ada data IP Address yang ditemukan.")
        
        ip_address = st.text_input("Masukkan IP Address (Gunakan format CIDR, misal: 192.168.1.100/24)")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        action = st.selectbox("Pilih Aksi", ["Tambahkan", "Hapus"])
        execute_btn = st.button("Save")

        if execute_btn and st.session_state.ssh_client:
            output, _ = execute_command(st.session_state.ssh_client, list_command)
            import streamlit as st
import paramiko
import pandas as pd

# Membaca Style.css
st.markdown("""
<style>
h1 {
    text-align: center;
}

h2 {
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# Fungsi untuk membuat koneksi SSH
def connect_ssh(ip, username, password, port=22):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password)
        return ssh, "Connection Successful"
    except Exception as e:
        return None, f"Connection Failed: {str(e)}"

# Fungsi untuk mengeksekusi perintah SSH
def execute_command(ssh, command):
    try:
        stdin, stdout, stderr = ssh.exec_command(command)
        return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')
    except Exception as e:
        return None, f"Command Execution Failed: {str(e)}"

# Antarmuka Streamlit
st.title("LIMITIX")

# Login Form
if "logged_in" not in st.session_state:
    with st.form("login_form"):
        st.subheader("Login to MikroTik")
        ip_address = st.text_input("IP Address", placeholder="Enter MikroTik IP Address")
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submit_button = st.form_submit_button("Login")

    if submit_button:
        if ip_address and username and password:
            st.write("Connecting to MikroTik...")
            ssh_client, ssh_message = connect_ssh(ip_address, username, password)
            if ssh_client:
                st.session_state.logged_in = True
                st.session_state.ssh_client = ssh_client
                st.success("Login berhasil! Silakan gunakan fitur di sidebar.")
                st.experimental_rerun()  # Refresh halaman setelah login
            else:
                st.error(ssh_message)
        else:
            st.warning("Please fill in all fields (IP Address, Username, and Password).")

else:
    # Sidebar untuk fitur
    st.sidebar.header("Pilih Fitur")
    menu = st.sidebar.selectbox("Fitur", ["Manajemen IP Address", "Konfigurasi Wireless", "Monitoring Bandwidth"])

    # Manajemen IP Address
    if menu == "Manajemen IP Address":
        st.subheader("Manajemen IP Address")

        # Menampilkan daftar IP Address dan Interface yang ada dalam tabel
        list_command = "/ip address print terse"
        output, _ = execute_command(st.session_state.ssh_client, list_command)

        ip_data = []
        for line in output.split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                ip_address_value = parts[1].replace("address=", "")
                interface_value = parts[3].replace("interface=", "")
                ip_data.append({"IP Address": ip_address_value, "Interface": interface_value})

        if ip_data:
            df = pd.DataFrame(ip_data)
            st.table(df)
        else:
            st.write("Tidak ada data IP Address yang ditemukan.")

        ip_address = st.text_input("Masukkan IP Address (Gunakan format CIDR, misal: 192.168.1.100/24)")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        action = st.selectbox("Pilih Aksi", ["Tambahkan", "Hapus"])
        execute_btn = st.button("Save")

        if execute_btn and st.session_state.ssh_client:
            output, _ = execute_command(st.session_state.ssh_client, list_command)

            if action == "Tambahkan":
                if any(ip_address in line and interface in line for line in output.split("\n")):
                    st.warning(f"IP {ip_address} pada {interface} sudah ada.")
                else:
                    command = f"/ip address add address={ip_address} interface={interface}"
                    output, error = execute_command(st.session_state.ssh_client, command)
                    if error:
                        st.error(error)
                    else:
                        st.success(f"IP {ip_address} berhasil ditambahkan pada {interface}.")
            else:
                lines = output.split("\n")
                ip_id = None
                for line in lines:
                    if ip_address in line and interface in line:
                        ip_id = line.split()[0]
                        break

                if ip_id:
                    command = f"/ip address remove {ip_id}"
                    output, error = execute_command(st.session_state.ssh_client, command)
                    if error:
                        st.error(error)
                    else:
                        st.success(f"IP {ip_address} pada {interface} berhasil dihapus.")
                else:
                    st.warning(f"Tidak ditemukan IP {ip_address} pada {interface}.")

    # Konfigurasi Wireless
    elif menu == "Konfigurasi Wireless":
        st.subheader("Konfigurasi Wireless")
        ssid = st.text_input("SSID")
        wifi_password = st.text_input("Password Wireless", type="password")
        interface = st.selectbox("Pilih Interface", ["wlan1", "wlan2", "wlan3"])
        configure_btn = st.button("Konfigurasi")

        if configure_btn and st.session_state.ssh_client:
            command = f"/interface wireless set {interface} ssid={ssid} password={wifi_password}"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success("Wireless berhasil dikonfigurasi")

    # Monitoring Bandwidth
    elif menu == "Monitoring Bandwidth":
        st.subheader("Monitoring Bandwidth")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        monitor_btn = st.button("Mulai Monitoring")

        if monitor_btn and st.session_state.ssh_client:
            command = f"/interface monitor-traffic interface={interface} once"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.text("Output Monitoring:")
                st.code(output)
            if action == "Tambahkan":
                if any(ip_address in line and interface in line for line in output.split("\n")):
                    st.warning(f"IP {ip_address} pada {interface} sudah ada.")
                else:
                    command = f"/ip address add address={ip_address} interface={interface}"
                    output, error = execute_command(st.session_state.ssh_client, command)
                    if error:
                        st.error(error)
                    else:
                        st.success(f"IP {ip_address} berhasil ditambahkan pada {interface}.")
            else:
                lines = output.split("\n")
                ip_id = None
                for line in lines:
                    if ip_address in line and interface in line:
                        ip_id = line.split()[0]
                        break
                
                if ip_id:
                    command = f"/ip address remove {ip_id}"
                    output, error = execute_command(st.session_state.ssh_client, command)
                    if error:
                        st.error(error)
                    else:
                        st.success(f"IP {ip_address} pada {interface} berhasil dihapus.")
                else:
                    st.warning(f"Tidak ditemukan IP {ip_address} pada {interface}.")
    
    # Konfigurasi Wireless
    elif menu == "Konfigurasi Wireless":
        st.subheader("Konfigurasi Wireless")
        ssid = st.text_input("SSID")
        wifi_password = st.text_input("Password Wireless", type="password")
        interface = st.selectbox("Pilih Interface", ["wlan1", "wlan2", "wlan3"])
        configure_btn = st.button("Konfigurasi")

        if configure_btn and st.session_state.ssh_client:
            command = f"/interface wireless set {interface} ssid={ssid} password={wifi_password}"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success("Wireless berhasil dikonfigurasi")

    # Monitoring Bandwidth
    elif menu == "Monitoring Bandwidth":
        st.subheader("Monitoring Bandwidth")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        monitor_btn = st.button("Mulai Monitoring")

        if monitor_btn and st.session_state.ssh_client:
            command = f"/interface monitor-traffic interface={interface} once"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.text("Output Monitoring:")
                st.code(output)
