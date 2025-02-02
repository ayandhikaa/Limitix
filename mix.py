import streamlit as st
import paramiko

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

# Fungsi untuk melakukan koneksi SSH dan konfigurasi RoMON
def configure_romon(hostname, username, password, romon_enabled=True):
    try:
        # Buat koneksi SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)

        # Pesan berhasil terhubung
        st.success("Berhasil terhubung ke router!")

        # Perintah untuk mengaktifkan/menonaktifkan RoMON
        romon_command = "/interface romon set enabled=yes" if romon_enabled else "/interface romon set enabled=no"
        
        # Eksekusi perintah di MikroTik
        stdin, stdout, stderr = ssh.exec_command(romon_command)
        error = stderr.read().decode()

        # Tutup koneksi SSH
        ssh.close()

        if error:
            return False, f"Error: {error}"
        else:
            return True, None

    except Exception as e:
        return False, f"Connection error: {str(e)}"

# Fungsi untuk membuat koneksi SSH
def connect_ssh(ip, username, password, port):
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

# Input form untuk login
if "logged_in" not in st.session_state:
    with st.form("login_form"):
        st.subheader("Login to MikroTik")
        ip_address = st.text_input("IP Address", placeholder="Enter MikroTik IP Address")
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        romon_enabled = st.checkbox("Enable RoMON", value=True)
        submit_button = st.form_submit_button("Submit")

    if submit_button:
        if ip_address and username and password:
            st.write("Connecting to MikroTik...")
            success, message = configure_romon(ip_address, username, password, romon_enabled)
            if success:
                st.session_state.logged_in = True
                st.session_state.ssh_client, ssh_message = connect_ssh(ip_address, username, password, 22)
                if st.session_state.ssh_client:
                    st.success("Login berhasil, silakan pilih fitur di sidebar.")
                else:
                    st.error(ssh_message)
            else:
                st.error(message)
        else:
            st.warning("Please fill in all fields (IP Address, Username, and Password).")
else:
    st.sidebar.header("Pilih Fitur")
    menu = st.sidebar.selectbox("Fitur", ["Manajemen IP Address", "Konfigurasi Wireless", "Monitoring Bandwidth"])
    
    # Manajemen IP Address
    if menu == "Manajemen IP Address":
        st.subheader("Manajemen IP Address")
        ip_address = st.text_input("Masukkan IP Address")
        action = st.selectbox("Pilih Aksi", ["Tambahkan", "Hapus"])
        execute_btn = st.button("Eksekusi")

        if execute_btn and st.session_state.ssh_client:
            command = f"/ip address add address={ip_address}" if action == "Tambahkan" else f"/ip address remove [find address={ip_address}]"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success("Aksi berhasil dieksekusi")

    # Konfigurasi Wireless
    elif menu == "Konfigurasi Wireless":
        st.subheader("Konfigurasi Wireless")
        ssid = st.text_input("SSID")
        wifi_password = st.text_input("Password Wireless", type="password")
        configure_btn = st.button("Konfigurasi")

        if configure_btn and st.session_state.ssh_client:
            command = f"/interface wireless set ssid={ssid} password={wifi_password}"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.success("Wireless berhasil dikonfigurasi")

    # Monitoring Bandwidth
    elif menu == "Monitoring Bandwidth":
        st.subheader("Monitoring Bandwidth")
        monitor_btn = st.button("Mulai Monitoring")

        if monitor_btn and st.session_state.ssh_client:
            command = "/interface monitor-traffic interface=all once"
            output, error = execute_command(st.session_state.ssh_client, command)
            if error:
                st.error(error)
            else:
                st.text("Output Monitoring:")
                st.code(output)
