import streamlit as st
import pandas as pd
import os

# Sample user database with roles
USER_CREDENTIALS = {
    "admin": {"password": "admin123", "role": "admin"},
    "agent1": {"password": "password1", "role": "agent"}
}

# Directory to store uploaded files
UPLOAD_DIR = "C:/Dev/boj/boj_demo/uploaded"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Function to validate login
def authenticate(username, password):
    user = USER_CREDENTIALS.get(username)
    if user and user["password"] == password:
        return user["role"]
    return None

# Function to reset password
def reset_password(username, new_password):
    if username in USER_CREDENTIALS:
        USER_CREDENTIALS[username]["password"] = new_password
        return True
    return False

# Function to display screens based on roles
def admin_screen():
    st.subheader("Admin Dashboard")
    st.write("Welcome to the Admin Panel. Review uploaded files here.")

    # List files in upload directory
    files = os.listdir(UPLOAD_DIR)
    if files:
        selected_file = st.selectbox("Select a file to view", files)
        if selected_file:
            file_path = os.path.join(UPLOAD_DIR, selected_file)
            try:
                # Display file as dataframe if it is a CSV or Excel file
                if selected_file.endswith(".csv"):
                    df = pd.read_csv(file_path)
                    st.dataframe(df)
                elif selected_file.endswith(".xlsx"):
                    df = pd.read_excel(file_path)
                    st.dataframe(df)
                else:
                    st.write("Selected file is not a CSV or Excel file. Cannot display.")
            except Exception as e:
                st.error(f"Error reading file: {e}")
    else:
        st.info("No files have been uploaded by agents yet.")

def agent_screen():
    st.subheader("Agent Dashboard")
    st.write("Welcome to the Agent Panel. Handle tasks and client interactions here.")

    # File upload functionality
    uploaded_file = st.file_uploader("Upload a file", type=["csv", "txt", "xlsx", "pdf"])
    if uploaded_file is not None:
        file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.success(f"File '{uploaded_file.name}' uploaded successfully to {UPLOAD_DIR}!")

# Main Streamlit App
def main():
    st.title("Streamlit App with Role-Based Authentication")

    # Initialize session state for authentication
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.session_state.role = ""

    if "show_reset_form" not in st.session_state:
        st.session_state.show_reset_form = False

    # Authentication Logic
    if not st.session_state.authenticated:
        if st.session_state.show_reset_form:
            st.subheader("Reset Password")
            reset_username = st.text_input("Enter your username to reset password")
            new_password = st.text_input("Enter new password", type="password")
            reset_button = st.button("Submit Reset")

            if reset_button:
                if reset_password(reset_username, new_password):
                    st.success("Password reset successfully. You can now log in with your new password.")
                    st.session_state.show_reset_form = False
                    if st.button("Go to Login"):
                        st.experimental_rerun()
                else:
                    st.error("Username not found. Please try again.")
        else:
            st.subheader("Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            login_button = st.button("Login")

            if login_button:
                role = authenticate(username, password)
                if role:
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.role = role
                    st.success(f"Welcome, {username} ({role.capitalize()})!")
                    st.experimental_rerun()
                else:
                    st.error("Invalid username or password.")

            st.markdown("[Reset Password](#)", unsafe_allow_html=True)
            if st.session_state.get("reset_password_clicked"):
                st.session_state.show_reset_form = True

            if "reset_password_clicked" not in st.session_state:
                st.session_state.reset_password_clicked = False

            if st.session_state.reset_password_clicked:
                st.session_state.show_reset_form = True

    else:
        st.subheader(f"Welcome, {st.session_state.username} ({st.session_state.role.capitalize()})!")

        # Display unique screen based on role
        if st.session_state.role == "admin":
            admin_screen()
        elif st.session_state.role == "agent":
            agent_screen()

        logout_button = st.button("Logout")
        if logout_button:
            st.session_state.authenticated = False
            st.session_state.username = ""
            st.session_state.role = ""
            st.success("You have been logged out.")
            st.experimental_rerun()

if __name__ == "__main__":
    main()
