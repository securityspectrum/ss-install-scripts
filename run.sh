#!/bin/bash
set -x
python3 -m venv venv
source venv/bin/activate
pip install --upgarde pip
pip install -r requirements.txt
python main.py
