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

# Antarmuka Streamlit
st.title("LIMITIX")

# Input form untuk login
with st.form("login_form"):
    st.subheader("Login to MikroTik")
    ip_address = st.text_input("IP Address", placeholder="Enter MikroTik IP Address")
    username = st.text_input("Username", placeholder="Enter your username")
    password = st.text_input("Password", type="password", placeholder="Enter your password")
    romon_enabled = st.checkbox("Enable RoMON", value=True)
    submit_button = st.form_submit_button("Submit")

# Jika tombol submit ditekan
if submit_button:
    if ip_address and username and password:
        st.write("Connecting to MikroTik...")
        
        # Lakukan konfigurasi RoMON
        success, message = configure_romon(ip_address, username, password, romon_enabled)
        
        if success:
            st.success("Konfigurasi RoMON telah diperbarui.")
        else:
            st.error(message)
    else:
        st.warning("Please fill in all fields (IP Address, Username, and Password).")
