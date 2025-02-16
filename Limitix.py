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
st.title("LIMITIX - MikroTik Management")

# Sidebar untuk navigasi
st.sidebar.header("Menu")
menu = st.sidebar.radio("Pilih Halaman", ["Dashboard", "Manajemen IP Address", "Konfigurasi Wireless", "Pembatasan & Monitoring Bandwidth"])

# Dashboard
if menu == "Dashboard":
    st.subheader("Selamat Datang di LIMITIX")
    st.write("LIMITIX adalah sistem manajemen MikroTik yang memudahkan konfigurasi jaringan Anda.")
    st.write("Gunakan menu di sidebar untuk mengakses fitur yang tersedia.")
    st.write("Fitur yang tersedia:")
    st.markdown("""
    - **Manajemen IP Address**: Tambah atau hapus alamat IP pada MikroTik.
    - **Konfigurasi Wireless**: Mengatur SSID dan password jaringan nirkabel.
    - **Pembatasan & Monitoring Bandwidth**: Menetapkan batas bandwidth sebelum melakukan monitoring jaringan.
    """)

# Login Form
elif "logged_in" not in st.session_state:
    with st.form(key="unique_login_form"):
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
                st.rerun()
            else:
                st.error(ssh_message)
        else:
            st.warning("Please fill in all fields (IP Address, Username, and Password).")

else:
    # Manajemen IP Address
    if menu == "Manajemen IP Address":
        st.subheader("Manajemen IP Address")
        
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
        
        ip_address = st.text_input("Masukkan IP Address (format CIDR, misal: 192.168.1.100/24)")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        action = st.selectbox("Pilih Aksi", ["Tambahkan", "Hapus"])
        execute_btn = st.button("Eksekusi")

        if execute_btn:
            if action == "Tambahkan":
                command = f"/ip address add address={ip_address} interface={interface}"
            else:
                command = f"/ip address remove [find address={ip_address} interface={interface}]"
            
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success(f"Aksi {action} berhasil pada {interface}.")

    # Konfigurasi Wireless
    elif menu == "Konfigurasi Wireless":
        st.subheader("Konfigurasi Wireless")
        ssid = st.text_input("SSID")
        wifi_password = st.text_input("Password Wireless", type="password")
        interface = st.selectbox("Pilih Interface", ["wlan1", "wlan2", "wlan3"])
        configure_btn = st.button("Konfigurasi")

        if configure_btn:
            command = f"/interface wireless set {interface} ssid={ssid} password={wifi_password}"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success("Wireless berhasil dikonfigurasi")

    # Pembatasan & Monitoring Bandwidth
    elif menu == "Pembatasan & Monitoring Bandwidth":
        st.subheader("Pembatasan & Monitoring Bandwidth")
        
        bandwidth_limit = st.text_input("Masukkan batas maksimal bandwidth (kbps)")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        limit_btn = st.button("Terapkan Batas Bandwidth")

        if limit_btn:
            command = f"/queue simple add name=Limit_{interface} target={interface} max-limit={bandwidth_limit}k"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success(f"Batas bandwidth {bandwidth_limit} kbps berhasil diterapkan pada {interface}.")

        monitor_btn = st.button("Mulai Monitoring")
        if monitor_btn:
            command = f"/interface monitor-traffic interface={interface} once"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.text("Output Monitoring:")
                st.code(output)