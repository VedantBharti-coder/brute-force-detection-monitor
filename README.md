# Brute Force Attack Detection & Live Monitoring

A Python-based cybersecurity project for detecting and monitoring failed SSH login attempts in real time.

## Overview

This project monitors the SSH authentication log on a CentOS system and detects failed login attempts. It extracts the attempted username and source IP address, tracks repeated attempts, checks usernames against a known-user list, and retrieves approximate geographic and ISP information for the source IP.

The project was developed using Kali Linux as the testing/attacker environment and CentOS as the monitored target.

## Features

- Real-time SSH authentication log monitoring
- Detection of failed SSH login attempts
- Username and source IP extraction
- Attempt counting
- Known-user matching
- Approximate IP geolocation and ISP lookup
- Live monitoring summary
- Pie-chart visualization of attempts by username
- Designed for continuous monitoring

## Architecture

```text
Kali Linux
    |
    | Controlled SSH brute-force simulation
    v
CentOS SSH Service
    |
    v
/var/log/secure
    |
    v
Python Monitoring Script
    |
    +-- Username/IP Detection
    +-- Attempt Counting
    +-- Known User Matching
    +-- GeoIP Lookup
    +-- Visualization
