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
    # Pembatasan & Monitoring Bandwidth
    if menu == "Pembatasan & Monitoring Bandwidth":
        st.subheader("Pembatasan & Monitoring Bandwidth")
        
        # Memasukkan batas maksimal bandwidth
        bandwidth_limit = st.text_input("Masukkan batas maksimal bandwidth (kbps)")
        interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "wlan1", "wlan2"])
        limit_btn = st.button("Terapkan Batas Bandwidth")

        if limit_btn and st.session_state.ssh_client:
            command = f"/queue simple add name=Limit_{interface} target={interface} max-limit={bandwidth_limit}k"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success(f"Batas bandwidth {bandwidth_limit} kbps berhasil diterapkan pada {interface}.")
                
        # Monitoring Bandwidth
        monitor_btn = st.button("Mulai Monitoring")

        if monitor_btn and st.session_state.ssh_client:
            command = f"/interface monitor-traffic interface={interface} once"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.text("Output Monitoring:")
                st.code(output)
