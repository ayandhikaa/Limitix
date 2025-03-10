import streamlit as st

st.title(st.session_state.get("username", "User"))