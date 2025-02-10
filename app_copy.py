import streamlit as st
import pandas as pd
import os
import shutil
import datetime
import hashlib

# Define directories
UPLOAD_DIR = "upload-repo"
APPROVED_DIR = "approved-repo"
REJECTED_DIR = "reject-repo"
USER_DB = "users.csv"
FILE_STATUS_DB = "file_status.csv"

# Ensure directories exist
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(APPROVED_DIR, exist_ok=True)
os.makedirs(REJECTED_DIR, exist_ok=True)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'role' not in st.session_state:
    st.session_state.role = None
if 'username' not in st.session_state:
    st.session_state.username = None

# Hashing function for passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Load users database
def load_users():
    if not os.path.exists(USER_DB):
        df = pd.DataFrame(columns=["username", "password", "role"])
        df.to_csv(USER_DB, index=False)
    return pd.read_csv(USER_DB)

# Load file status database
def load_file_status():
    if not os.path.exists(FILE_STATUS_DB):
        df = pd.DataFrame(columns=["filename", "uploader", "status", "timestamp", "note"])
        df.to_csv(FILE_STATUS_DB, index=False)
    return pd.read_csv(FILE_STATUS_DB)

# Save file status
def save_file_status(df):
    df.to_csv(FILE_STATUS_DB, index=False)

# Save users database
def save_users(df):
    df.to_csv(USER_DB, index=False)

# Authenticate user
def authenticate(username, password):
    users = load_users()
    password_hash = hash_password(password)
    user = users[(users['username'] == username) & (users['password'] == password_hash)]
    if not user.empty:
        return user.iloc[0]['role']
    return None

# Reset password
def reset_password(username, new_password):
    users = load_users()
    if username not in users['username'].values:
        return False
    users.loc[users['username'] == username, 'password'] = hash_password(new_password)
    save_users(users)
    return True

# Logout function
def logout():
    st.session_state.authenticated = False
    st.session_state.role = None
    st.session_state.username = None
    st.experimental_rerun()

# SME Dashboard
def sme_dashboard(username):
    st.title("SME Dashboard")
    st.write(f"Welcome, {username}")
    
    uploaded_file = st.file_uploader("Upload a file", type=["txt", "pdf", "png", "jpg", "csv", "xlsx"])
    if uploaded_file:
        file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        df = load_file_status()
        new_entry = pd.DataFrame([{ "filename": uploaded_file.name, "uploader": username, "status": "Pending", "timestamp": datetime.datetime.now(), "note": ""}])
        df = pd.concat([df, new_entry], ignore_index=True)
        save_file_status(df)
        
        st.success(f"File {uploaded_file.name} uploaded successfully!")
    
    with st.expander("View Uploaded File Content"):
        upload_repo_files = [f for f in os.listdir(UPLOAD_DIR) if os.path.isfile(os.path.join(UPLOAD_DIR, f))]
        if upload_repo_files:
            selected_view_file = st.selectbox("View uploaded file:", upload_repo_files)
            if selected_view_file:
                file_path = os.path.join(UPLOAD_DIR, selected_view_file)
                if os.path.exists(file_path):
                    try:
                        df_file = pd.read_csv(file_path)
                        st.write("File Content:")
                        st.dataframe(df_file)
                    except Exception as e:
                        st.error("Unable to display file content as a table. Showing raw text instead.")
                        with open(file_path, "r", errors='ignore') as file:
                            file_content = file.read()
                            st.text_area("File Content:", file_content, height=200, disabled=True)
                user_files = pd.DataFrame(columns=['filename'])  # Placeholder if no files exist
        
        df = load_file_status()
        user_files = df[df['uploader'] == username].drop_duplicates(subset=['filename']).sort_values(by='timestamp', ascending=False)
    
    with st.expander("Uploaded Files Status"):
        st.write("Below is the status of your uploaded files")
        st.table(user_files)
    
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.role = None
        st.session_state.username = None
        st.experimental_rerun()


# Admin Dashboard
def admin_dashboard():
    st.title("Admin Dashboard")
    st.write("Welcome, Admin")
    
    df = load_file_status()
    upload_repo_files = [f for f in os.listdir(UPLOAD_DIR) if os.path.isfile(os.path.join(UPLOAD_DIR, f))]
    
    if not upload_repo_files:
        st.write("No files pending approval")
    else:
        selected_file = st.selectbox("Select a file to review:", upload_repo_files)
        if selected_file:
            file_path = os.path.join(UPLOAD_DIR, selected_file)
            if os.path.exists(file_path):
                try:
                    df_file = pd.read_csv(file_path)
                    st.write("File Content:")
                    st.dataframe(df_file)
                except Exception as e:
                    st.error("Unable to display file content as a table. Showing raw text instead.")
                    with open(file_path, "r", errors='ignore') as file:
                        file_content = file.read()
                        st.text_area("File Content:", file_content, height=200, disabled=True)
                
            note = st.text_area("Leave a Note:")
            col1, col2 = st.columns(2)
            
            if col1.button("Approve", key="approve", help="Approve the selected file", use_container_width=True):
                shutil.move(os.path.join(UPLOAD_DIR, selected_file), os.path.join(APPROVED_DIR, selected_file))
                df.loc[df['filename'] == selected_file, 'status'] = "Approved"
                df.loc[df['filename'] == selected_file, 'note'] = note
                save_file_status(df)
                st.experimental_rerun()
            
            if col2.button("Reject", key="reject", help="Reject the selected file", use_container_width=True):
                shutil.move(os.path.join(UPLOAD_DIR, selected_file), os.path.join(REJECTED_DIR, selected_file))
                df.loc[df['filename'] == selected_file, 'status'] = "Rejected"
                df.loc[df['filename'] == selected_file, 'note'] = note
                save_file_status(df)
                st.experimental_rerun()  
       
                
    
    with st.expander("All File Status"):
        st.write("Below is the status of all uploaded files")
        df = df.drop_duplicates(subset=['filename']).sort_values(by='timestamp', ascending=False)
        st.table(df)
    
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.role = None
        st.session_state.username = None
        st.experimental_rerun()



# Main application
def main():
    st.title("Secure File Management System")
    
    if not st.session_state.authenticated:
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_button = st.button("Login")
        
        if login_button:
            role = authenticate(username, password)
            if role:
                st.session_state.authenticated = True
                st.session_state.role = role
                st.session_state.username = username
                st.experimental_rerun()
            else:
                st.error("Invalid credentials")
        
        st.markdown("[Forgot Password?](#reset-password)")
        
        if "reset-password" in st.experimental_get_query_params():
            st.subheader("Reset Password")
            reset_username = st.text_input("Enter your username")
            new_password = st.text_input("Enter new password", type="password")
            if st.button("Reset Password"):
                if reset_password(reset_username, new_password):
                    st.success("Password reset successful!")
                else:
                    st.error("Username not found")
    else:
        if st.session_state.role == "SME":
            sme_dashboard(st.session_state.username)
        elif st.session_state.role == "Admin":
            admin_dashboard()

if __name__ == "__main__":
    main()
