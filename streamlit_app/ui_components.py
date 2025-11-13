"""
Custom UI Components with Framer Motion-like Animations
"""

import streamlit as st
import time
import random

def animated_header(text, emoji="🔍"):
    """Animated header with fade-in effect"""
    st.markdown(f"""
    <div style="animation: fadeIn 1s ease-in;">
        <h1 style="text-align: center; color: #1f77b4; margin-bottom: 0;">
            {emoji} {text}
        </h1>
    </div>
    """, unsafe_allow_html=True)

def pulse_metric(label, value, delta=None, emoji="📊"):
    """Pulsing metric card with hover effects"""
    delta_html = f"<span style='color: green;'>▲{delta}</span>" if delta else ""
    
    st.markdown(f"""
    <div class="pulse-card" style="
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin: 10px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        transition: transform 0.3s ease;
        animation: pulse 2s infinite;
    ">
        <div style="font-size: 2em; margin-bottom: 10px;">{emoji}</div>
        <div style="font-size: 1.5em; font-weight: bold;">{value}</div>
        <div style="font-size: 0.9em; opacity: 0.9;">{label}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)

def slide_in_alert(alert_type, message, severity="info"):
    """Slide-in alert notification"""
    colors = {
        "high": "#ff4444", 
        "medium": "#ffaa00", 
        "low": "#44ff44",
        "info": "#1f77b4"
    }
    color = colors.get(severity.lower(), "#1f77b4")
    
    st.markdown(f"""
    <div class="slide-in-alert" style="
        background: {color};
        color: white;
        padding: 15px;
        border-radius: 10px;
        margin: 10px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        animation: slideInRight 0.5s ease-out;
    ">
        <div style="display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 1.2em;">🚨</span>
            <div>
                <strong>{alert_type}</strong><br>
                {message}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def floating_action_button(label, icon="🎬", key=None):
    """Floating action button with animation"""
    if st.button(f"{icon} {label}", key=key):
        return True
    return False

def animated_progress_bar(value, max_value=100, color="#1f77b4"):
    """Animated progress bar with smooth filling"""
    percentage = (value / max_value) * 100
    st.markdown(f"""
    <div style="
        background: #f0f2f6;
        border-radius: 10px;
        height: 20px;
        margin: 10px 0;
        overflow: hidden;
    ">
        <div class="progress-fill" style="
            background: {color};
            height: 100%;
            width: {percentage}%;
            border-radius: 10px;
            animation: fillProgress 1.5s ease-in-out;
        "></div>
    </div>
    """, unsafe_allow_html=True)

def bounce_in_card(content, delay=0):
    """Card that bounces in with delay"""
    st.markdown(f"""
    <div class="bounce-in-card" style="animation-delay: {delay}s;">
        {content}
    </div>
    """, unsafe_allow_html=True)

def rotating_icon(icon="🔄", size=24):
    """Rotating icon for loading states"""
    st.markdown(f"""
    <div class="rotating-icon" style="
        font-size: {size}px;
        display: inline-block;
        animation: rotate 2s linear infinite;
    ">
        {icon}
    </div>
    """, unsafe_allow_html=True)

def typewriter_text(text, speed=50):
    """Typewriter effect for text"""
    container = st.empty()
    typed_text = ""
    for char in text:
        typed_text += char
        container.markdown(f"""
        <div style="font-family: monospace; font-size: 1.1em;">
            {typed_text}▊
        </div>
        """, unsafe_allow_html=True)
        time.sleep(speed/1000)
    return typed_text

def glow_on_hover(element, glow_color="#ff6b6b"):
    """Add glow effect on hover to any element"""
    st.markdown(f"""
    <style>
    .glow-element:hover {{
        box-shadow: 0 0 20px {glow_color};
        transform: translateY(-2px);
        transition: all 0.3s ease;
    }}
    </style>
    <div class="glow-element">
        {element}
    </div>
    """, unsafe_allow_html=True)