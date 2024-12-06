import openai
import streamlit as st
import time
import pandas as pd
import json
import plotly.express as px
import boto3

boto3.client("s3")
s3.upload_file(r'C:/Dev/boj_streamlit_demo/Fake_Profit_and_Loss_Balance_Sheet.csv', 'streamlit_demo', 'fake_balsheet.csv')

st.set_page_config(page_title="BOJ_Demo", page_icon=":speech_balloon:")

df = pd.read_csv("data.csv")
