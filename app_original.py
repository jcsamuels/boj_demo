import streamlit as st
import pandas as pd
import os
import boto3
#from deltalake.writer import write_deltalake

# AWS S3 Configuration
S3_BUCKET = "your-s3-bucket-name"
s3_client = boto3.client("s3")

# Sample user database with roles
USER_CREDENTIALS = {
    "admin": {"password": "admin123", "role": "admin"},
    "agent1": {"password": "password1", "role": "agent"}
}

# Function to validate logindeactivate
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

# Function to display admin dashboard
def admin_screen():
    st.subheader("Admin Dashboard")
    st.write("Welcome to the Admin Panel. Review uploaded files from S3.")

    # List files in S3 bucket
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET)
        files = [obj["Key"] for obj in response.get("Contents", [])]
    except Exception as e:
        st.error(f"Error retrieving files from S3: {e}")
        files = []

    if files:
        selected_file = st.selectbox("Select a file to view", files)
        if selected_file:
            try:
                obj = s3_client.get_object(Bucket=S3_BUCKET, Key=selected_file)
                df = pd.read_csv(obj["Body"]) if selected_file.endswith(".csv") else pd.read_excel(obj["Body"])
                st.dataframe(df)
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Approve", key="approve_button", help="Approve file", type="primary"):
                        delta_table_path = f"s3://{S3_BUCKET}/delta/{selected_file.split('.')[0]}"
                        write_deltalake(delta_table_path, df)
                        st.success(f"File '{selected_file}' has been stored as a Delta table in S3.")
                with col2:
                    if st.button("Reject", key="reject_button", help="Reject file", type="secondary"):
                        s3_client.delete_object(Bucket=S3_BUCKET, Key=selected_file)
                        st.warning(f"File '{selected_file}' has been deleted.")
            except Exception as e:
                st.error(f"Error processing file from S3: {e}")
    else:
        st.info("No files available in S3.")

# Function to display agent dashboard
def agent_screen():
    st.subheader("Agent Dashboard")
    st.write("Welcome to the Agent Panel. Upload files to S3.")

    uploaded_file = st.file_uploader("Upload a file", type=["csv", "xlsx"])
    if uploaded_file is not None:
        try:
            s3_client.upload_fileobj(uploaded_file, S3_BUCKET, uploaded_file.name)
            st.success(f"File '{uploaded_file.name}' uploaded successfully to S3!")
        except Exception as e:
            st.error(f"Error uploading file: {e}")

# Main Streamlit App
def main():
    st.title("Streamlit App with Role-Based Authentication")

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.session_state.role = ""

    if "show_reset_form" not in st.session_state:
        st.session_state.show_reset_form = False

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
                else:
                    st.error("Invalid username or password.")

            st.markdown("[Reset Password](#)", unsafe_allow_html=True)
            if st.session_state.get("reset_password_clicked"):
                st.session_state.show_reset_form = True
    else:
        with st.sidebar:
            st.subheader(f"Welcome, {st.session_state.username} ({st.session_state.role.capitalize()})!")
            logout_button = st.button("Logout")
            if logout_button:
                st.session_state.authenticated = False
                st.session_state.username = ""
                st.session_state.role = ""
                st.success("You have been logged out.")

        if st.session_state.role == "admin":
            admin_screen()
        elif st.session_state.role == "agent":
            agent_screen()

if __name__ == "__main__":
    main()
