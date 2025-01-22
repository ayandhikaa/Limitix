import streamlit as st
import paramiko

# Function to establish SSH connection
def connect_ssh(ip, username, password, port):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password)
        return ssh, "Connection Successful"
    except Exception as e:
        return None, f"Connection Failed: {str(e)}"

# Function to execute SSH command
def execute_command(ssh, command):
    try:
        stdin, stdout, stderr = ssh.exec_command(command)
        return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')
    except Exception as e:
        return None, f"Command Execution Failed: {str(e)}"

# Streamlit UI
st.title("LIMITIX")
st.sidebar.header("Pilih Fitur")

# Sidebar options
menu = st.sidebar.selectbox("Fitur", ["Koneksi SSH", "Manajemen IP Address", "Konfigurasi Wireless", "Monitoring Bandwidth"])

# SSH connection variables
if "ssh_client" not in st.session_state:
    st.session_state.ssh_client = None

# Koneksi SSH
if menu == "Koneksi SSH":
    st.subheader("Koneksi SSH ke Router Mikrotik")
    ip = st.text_input("IP Address")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    port = st.number_input("Port", min_value=1, max_value=65535, value=22)
    connect_btn = st.button("Connect")

    if connect_btn:
        ssh, message = connect_ssh(ip, username, password, port)
        if ssh:
            st.session_state.ssh_client = ssh
            st.success(message)
        else:
            st.error(message)

# Manajemen IP Address
elif menu == "Manajemen IP Address":
    st.subheader("Manajemen IP Address")
    if st.session_state.ssh_client:
        ip_address = st.text_input("Masukkan IP Address")
        action = st.selectbox("Pilih Aksi", ["Tambahkan", "Hapus"])
        execute_btn = st.button("Eksekusi")

        if execute_btn:
            command = ""
            if action == "Tambahkan":
                command = f"/ip address add address={ip_address}"
            elif action == "Hapus":
                command = f"/ip address remove [find address={ip_address}]"

            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success("Aksi berhasil dieksekusi")
    else:
        st.warning("Harap koneksi ke router terlebih dahulu.")

# Konfigurasi Wireless
elif menu == "Konfigurasi Wireless":
    st.subheader("Konfigurasi Wireless")
    if st.session_state.ssh_client:
        ssid = st.text_input("SSID")
        wifi_password = st.text_input("Password Wireless", type="password")
        configure_btn = st.button("Konfigurasi")

        if configure_btn:
            command = f"/interface wireless set ssid={ssid} password={wifi_password}"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success("Wireless berhasil dikonfigurasi")
    else:
        st.warning("Harap koneksi ke router terlebih dahulu.")

# Monitoring Bandwidth
elif menu == "Monitoring Bandwidth":
    st.subheader("Monitoring Bandwidth")
    if st.session_state.ssh_client:
        monitor_btn = st.button("Mulai Monitoring")

        if monitor_btn:
            command = "/interface monitor-traffic interface=all once"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.text("Output Monitoring:")
                st.code(output)
    else:
        st.warning("Harap koneksi ke router terlebih dahulu.")



